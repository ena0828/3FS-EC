#include <array>
#include <gtest/gtest.h>
#include <limits>

#include "fbs/storage/Service.h"

using namespace hf3fs;
using namespace hf3fs::storage;

namespace {

// A binding with the existing method set needs no EC handler declarations.
// The actual StorageService compilation is also checked by the regression build.
struct LegacyBinding {
  void batchRead() {}
  void write() {}
  void update() {}
  void queryLastChunk() {}
  void truncateChunks() {}
  void removeChunks() {}
  void syncStart() {}
  void syncDone() {}
  void spaceInfo() {}
  void createTarget() {}
  void queryChunk() {}
  void getAllChunkMetadata() {}
  void offlineTarget() {}
  void removeTarget() {}
};
struct CompleteBinding : LegacyBinding {
  void writeECShard() {}
  void readECShard() {}
};
static_assert(refl::Helper::Size<StorageSerde<CompleteBinding>> == 16);
static_assert(refl::Helper::Size<StorageSerde<LegacyBinding>> == 14);
static_assert(refl::Helper::Size<StorageSerde<>> == 16);
static_assert(StorageSerde<>::writeECShardMethodId == 18 && StorageSerde<>::readECShardMethodId == 19);

ECShardRecordDTO record() {
  ECShardRecordDTO r;
  r.key = {0x1020304050607080ULL, 0xfedcba98u, 0, 11};
  r.version = std::numeric_limits<uint64_t>::max();
  r.validBytes = erasure::ECLayout::kChunkSize;
  r.payload.bytes.resize(kECShardPayloadLimit);
  for (size_t i = 0; i < r.payload.bytes.size(); ++i) r.payload.bytes[i] = static_cast<uint8_t>(i * 31);
  r.payloadChecksum = folly::crc32c(r.payload.bytes.data(), r.payload.bytes.size(), 0);
  return r;
}
WriteECShardReq request() {
  WriteECShardReq req;
  req.targetId = flat::TargetId{0xfedcba9876543210ULL};
  req.record = record();
  return req;
}

template <class T>
T roundTrip(const T &input) {
  auto wire = serde::serialize(input);
  T output = input;
  EXPECT_TRUE(serde::deserialize(output, wire));
  EXPECT_EQ(serde::serialize(output), wire);
  return output;
}

// Build length-prefixed tables using the normal reverse writer, without
// validation, to exercise malformed peer messages.
std::string table(std::string_view bytes) { return serde::serialize(bytes); }
std::string encode(auto value) { return serde::serialize(value); }

TEST(ECShardSerde, WriteRequestRoundTripAndFieldOrder) {
  auto req = request();
  auto out = roundTrip(req);
  EXPECT_EQ(out.targetId, req.targetId);
  EXPECT_EQ(out.record.key.inodeId, req.record.key.inodeId);
  EXPECT_EQ(out.record.key.logicalChunkIndex, req.record.key.logicalChunkIndex);
  EXPECT_EQ(out.record.key.shardIndex, 11);
  EXPECT_EQ(out.record.version, req.record.version);
  EXPECT_EQ(out.record.payload.bytes, req.record.payload.bytes);
  EXPECT_EQ(out.record.payloadChecksum, req.record.payloadChecksum);
  // Byte-for-byte order oracle assembled independently of DTO reflection.
  auto &r = req.record;
  auto key = table(encode(r.key.inodeId) + encode(r.key.logicalChunkIndex) + encode(r.key.stripeIndex) +
                   encode(r.key.shardIndex));
  std::string_view payload(reinterpret_cast<const char *>(r.payload.bytes.data()), r.payload.bytes.size());
  auto rec = table(key + encode(r.version) + encode(r.scheme) + encode(r.format) + encode(r.validBytes) +
                   encode(r.payloadChecksum) + table(payload));
  EXPECT_EQ(encode(req), table(encode(req.protocolVersion) + encode(req.targetId) + rec));
}

TEST(ECShardSerde, ReadRequestRoundTrip) {
  ReadECShardReq req;
  req.targetId = flat::TargetId{17};
  req.key = record().key;
  req.version = 19;
  auto out = roundTrip(req);
  EXPECT_EQ(out.version, 19u);
  EXPECT_EQ(out.key.logicalChunkIndex, req.key.logicalChunkIndex);
  EXPECT_EQ(out.scheme, erasure::ECLayout::kEncodingScheme);
  EXPECT_EQ(out.format, erasure::ECLayout::kFormatVersion);
}

TEST(ECShardSerde, WriteSuccessAndAllErrorsAreUnambiguous) {
  for (auto status : {ECShardStatus::Created,
                      ECShardStatus::ExistingVerified,
                      ECShardStatus::ContentConflict,
                      ECShardStatus::TargetUnavailable,
                      ECShardStatus::ECDisabled,
                      ECShardStatus::InvalidRequest,
                      ECShardStatus::QueueFull,
                      ECShardStatus::BackendError,
                      ECShardStatus::CorruptRecord,
                      ECShardStatus::InternalError}) {
    WriteECShardRsp rsp;
    rsp.status = status;
    auto out = roundTrip(rsp);
    EXPECT_EQ(out.status, status);
    EXPECT_EQ(out.succeeded(), status == ECShardStatus::Created || status == ECShardStatus::ExistingVerified);
  }
  EXPECT_FALSE(WriteECShardRsp{}.succeeded());
  EXPECT_FALSE(ReadECShardRsp{}.succeeded());
  // Framework Result<Rsp> is independent of the EC business outcome.
  Result<WriteECShardRsp> transportOK{WriteECShardRsp{}};
  auto decoded = roundTrip(transportOK);
  ASSERT_TRUE(decoded);
  EXPECT_FALSE(decoded->succeeded());
  auto transportError = Result<WriteECShardRsp>(makeError(RPCCode::kTimeout));
  auto error = roundTrip(transportError);
  ASSERT_FALSE(error);
  EXPECT_EQ(error.error().code(), RPCCode::kTimeout);
}

TEST(ECShardSerde, ReadSuccessOwnsAllBytesAndErrorsHaveNoRecord) {
  ReadECShardRsp rsp;
  rsp.status = ECShardStatus::Ok;
  rsp.record = record();
  auto out = roundTrip(rsp);
  ASSERT_TRUE(out.succeeded());
  auto expected = rsp.record->payload.bytes;
  rsp.record.reset();
  EXPECT_EQ(out.record->payload.bytes, expected);
  EXPECT_EQ(out.record->validBytes, erasure::ECLayout::kChunkSize);
  for (auto status : {ECShardStatus::NotFound,
                      ECShardStatus::CorruptRecord,
                      ECShardStatus::TargetUnavailable,
                      ECShardStatus::ECDisabled,
                      ECShardStatus::InvalidRequest,
                      ECShardStatus::QueueFull,
                      ECShardStatus::BackendError,
                      ECShardStatus::InternalError}) {
    ReadECShardRsp failure;
    failure.status = status;
    auto decoded = roundTrip(failure);
    EXPECT_EQ(decoded.status, status);
    EXPECT_FALSE(decoded.succeeded());
    EXPECT_FALSE(decoded.record);
  }
}

TEST(ECShardSerde, EmptyPayloadAndBoundaryLengths) {
  ECShardPayload empty;
  EXPECT_TRUE(roundTrip(empty).bytes.empty());
  auto req = request();
  for (uint32_t length : {0u, erasure::ECLayout::kChunkSize}) {
    req.record.validBytes = length;
    EXPECT_TRUE(roundTrip(req).valid());
  }
  for (size_t length : {size_t{0}, kECShardPayloadLimit - 1}) {
    req.record.payload.bytes.resize(length);
    WriteECShardReq out;
    EXPECT_FALSE(serde::deserialize(out, encode(req)));
  }
  ECShardPayload oversized;
  oversized.bytes.resize(kECShardPayloadLimit + 1);
  EXPECT_THROW(encode(oversized), std::length_error);
  std::string bytes(kECShardPayloadLimit + 1, 'x');
  EXPECT_FALSE(serde::deserialize(empty, table(bytes)));
  EXPECT_TRUE(empty.bytes.empty());
}

TEST(ECShardSerde, InvalidMetadataAndUnknownProtocolAreRejected) {
  const auto good = request();
  for (int choice = 0; choice < 10; ++choice) {
    auto bad = good;
    switch (choice) {
      case 0:
        bad.protocolVersion = 0;
        break;
      case 1:
        bad.protocolVersion = 2;
        break;
      case 2:
        bad.targetId = flat::TargetId{};
        break;
      case 3:
        bad.record.version = 0;
        break;
      case 4:
        bad.record.scheme = 2;
        break;
      case 5:
        bad.record.format = 2;
        break;
      case 6:
        bad.record.validBytes = erasure::ECLayout::kChunkSize + 1;
        break;
      case 7:
        bad.record.key.shardIndex = 12;
        break;
      case 8:
        bad.record.key.stripeIndex = 1;
        break;
      case 9:
        bad.record.payloadChecksum ^= 1;
        break;
    }
    auto out = good;
    EXPECT_FALSE(serde::deserialize(out, encode(bad))) << choice;
    EXPECT_EQ(encode(out), encode(good));  // no partially published output
  }
  ReadECShardReq read;
  read.targetId = flat::TargetId{1};
  read.version = 1;
  read.protocolVersion = 99;
  ReadECShardReq result;
  EXPECT_FALSE(serde::deserialize(result, encode(read)));
  WriteECShardRsp writeRsp;
  writeRsp.protocolVersion = 2;
  WriteECShardRsp w;
  EXPECT_FALSE(serde::deserialize(w, encode(writeRsp)));
  ReadECShardRsp readRsp;
  readRsp.protocolVersion = 2;
  ReadECShardRsp r;
  EXPECT_FALSE(serde::deserialize(r, encode(readRsp)));
}

TEST(ECShardSerde, TruncatedTablesMissingFieldsAndInvalidLengthPrefixes) {
  auto req = request();
  auto wire = encode(req);
  for (size_t n : {size_t{0}, size_t{1}, size_t{5}, wire.size() / 2, wire.size() - 1}) {
    WriteECShardReq out;
    EXPECT_FALSE(serde::deserialize(out, std::string_view(wire).substr(0, n))) << n;
  }
  WriteECShardReq out;
  EXPECT_FALSE(serde::deserialize(out, wire + "x"));
  EXPECT_FALSE(serde::deserialize(out, table(encode(uint16_t{1}))));
  ReadECShardReq read;
  EXPECT_FALSE(serde::deserialize(read, table("")));
  // Complete table plus unknown trailing field is invalid in protocol v1.
  auto rsp = encode(uint16_t{1}) + encode(ECShardStatus::InternalError) + "x";
  WriteECShardRsp write;
  EXPECT_FALSE(serde::deserialize(write, table(rsp)));
  for (auto bytes : {std::string(1, char(0x80)),
                     std::string(5, char(0xff)),
                     std::string("\x80\x80\x80\x80\x10", 5),
                     std::string("\x80\x00", 2),
                     std::string(10, char(0xff))}) {
    ECShardPayload payload;
    EXPECT_FALSE(serde::deserialize(payload, bytes));
    EXPECT_TRUE(payload.bytes.empty());
    EXPECT_FALSE(serde::deserialize(read, bytes));
  }
  // A huge valid uint32 length, with no backing data, must not allocate.
  ECShardPayload payload;
  EXPECT_FALSE(serde::deserialize(payload, std::string("\xff\xff\xff\xff\x0f", 5)));
  EXPECT_TRUE(payload.bytes.empty());
}

TEST(ECShardSerde, ResponseInvariantsUnknownStatusesAndOptionalTags) {
  WriteECShardRsp w, decoded;
  for (auto status : {ECShardStatus::Ok, ECShardStatus::NotFound, static_cast<ECShardStatus>(65535)}) {
    w.status = status;
    EXPECT_FALSE(serde::deserialize(decoded, encode(w)));
    EXPECT_FALSE(decoded.succeeded());
  }
  ReadECShardRsp r, out;
  r.status = ECShardStatus::Ok;  // success without record
  EXPECT_FALSE(serde::deserialize(out, encode(r)));
  r.status = ECShardStatus::NotFound;
  r.record = record();
  EXPECT_FALSE(serde::deserialize(out, encode(r)));
  r.record.reset();
  r.status = ECShardStatus::Created;
  EXPECT_FALSE(serde::deserialize(out, encode(r)));
  auto invalid = table(encode(uint16_t{1}) + encode(ECShardStatus::NotFound) + encode(uint8_t{2}));
  EXPECT_FALSE(serde::deserialize(out, invalid));
  EXPECT_FALSE(out.succeeded());
}

struct ProtocolClientContext {
  template <NameWrapper ServiceName, NameWrapper MethodName, class Req, class Rsp, uint16_t SID, uint16_t MID>
  Result<Rsp> callSync(const Req &, auto...) {
    static_assert(SID == 3 && (MID == 18 || MID == 19));
    if constexpr (MID == 18) {
      static_assert(std::is_same_v<Req, WriteECShardReq> && std::is_same_v<Rsp, WriteECShardRsp>);
      return Rsp{.status = ECShardStatus::Created};
    } else {
      static_assert(std::is_same_v<Req, ReadECShardReq> && std::is_same_v<Rsp, ReadECShardRsp>);
      return Rsp{.status = ECShardStatus::NotFound};
    }
  }
};

struct ExtractorContext {
  template <class M>
  int call() {
    return M::id;
  }
};
TEST(ECShardSerde, MethodIDsAndOriginalRPCWireAreStable) {
  using Table = serde::MethodExtractor<StorageSerde<>, ExtractorContext>;
  ExtractorContext ctx;
  ASSERT_NE(Table::get(18), nullptr);
  ASSERT_NE(Table::get(19), nullptr);
  EXPECT_EQ((ctx.*Table::get(18))(), 18);
  EXPECT_EQ((ctx.*Table::get(19))(), 19);
  EXPECT_EQ(Table::get(20), nullptr);
  std::array<bool, 20> seen{};
  size_t count = 0;
  refl::Helper::iterate<StorageSerde<>>([&](auto method) {
    ASSERT_LT(method.id, seen.size());
    EXPECT_FALSE(seen[method.id]);
    seen[method.id] = true;
    ++count;
    // All default DTOs retain diagnostic JSON serialization.
    EXPECT_FALSE(serde::toJsonString(typename decltype(method)::ReqType{}).empty());
    EXPECT_FALSE(serde::toJsonString(typename decltype(method)::RspType{}).empty());
  });
  EXPECT_EQ(count, 16u);
  for (unsigned id : {1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19}) EXPECT_TRUE(seen[id]);
  EXPECT_EQ(StorageSerde<>::kServiceID, 3);
  ProtocolClientContext client;
  auto sentWrite = StorageSerde<>::writeECShardSync(client, request());
  ASSERT_TRUE(sentWrite);
  EXPECT_TRUE(sentWrite->succeeded());
  auto sentRead = StorageSerde<>::readECShardSync(client, ReadECShardReq{});
  ASSERT_TRUE(sentRead);
  EXPECT_EQ(sentRead->status, ECShardStatus::NotFound);
  WriteRsp old;
  old.result.lengthInfo = uint32_t{73};
  auto wire = encode(old);
  EXPECT_TRUE(serde::deserialize(old, wire));
  EXPECT_EQ(encode(old), wire);
}

}  // namespace
