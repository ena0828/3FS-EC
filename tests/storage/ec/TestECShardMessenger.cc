#include <atomic>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <mutex>

#include "client/storage/StorageMessenger.h"
#include "common/net/Server.h"
#include "common/serde/Service.h"

using namespace hf3fs;
using namespace hf3fs::storage;
using namespace std::chrono_literals;

namespace {
// Test peer only: uses real packet dispatch/TCP but never touches production
// StorageService, a target, a worker, or a database.
SERDE_SERVICE_2(MessengerPeerSerde, StorageSerde, 3) {
  SERDE_SERVICE_METHOD(batchRead, 1, BatchReadReq, BatchReadRsp);
  SERDE_SERVICE_METHOD(write, 2, WriteReq, WriteRsp);
  SERDE_SERVICE_METHOD(update, 3, UpdateReq, UpdateRsp);
  SERDE_SERVICE_METHOD(writeECShard, 18, WriteECShardReq, WriteECShardRsp);
  SERDE_SERVICE_METHOD(readECShard, 19, ReadECShardReq, ReadECShardRsp);
};

ECShardRecordDTO makeRecord() {
  ECShardRecordDTO r;
  r.key = {712, 17, 0, 11};
  r.version = 0x123456789ULL;
  r.validBytes = 4194304;
  r.payload.bytes.resize(kECShardPayloadLimit);
  for (size_t i = 0; i < r.payload.bytes.size(); ++i) r.payload.bytes[i] = static_cast<uint8_t>(i * 13 + 7);
  r.payloadChecksum = folly::crc32c(r.payload.bytes.data(), r.payload.bytes.size(), 0);
  return r;
}
WriteECShardReq makeWrite() { return {.targetId = flat::TargetId{123456}, .record = makeRecord()}; }
ReadECShardReq makeRead() {
  auto r = makeRecord();
  return {.targetId = flat::TargetId{123456}, .key = r.key, .version = r.version};
}

struct PeerState {
  std::mutex mutex;
  std::optional<WriteECShardReq> writeRequest;
  std::optional<ReadECShardReq> readRequest;
  ECShardRecordDTO readRecord = makeRecord();
  uint16_t lastService = 0, lastMethod = 0;
  std::atomic<size_t> writes{0}, reads{0}, legacyWrites{0}, finishedWrites{0}, finishedReads{0};
  std::atomic<ECShardStatus> writeStatus{ECShardStatus::Created}, readStatus{ECShardStatus::NotFound};
  std::atomic<status_code_t> outerError{StatusCode::kOK};
  std::atomic<bool> holdWrite{false}, holdRead{false}, disconnect{false}, released{false};
  folly::coro::Baton gate;
  void release() {
    if (!released.exchange(true)) gate.post();
  }
};

class MessengerPeer : public serde::ServiceWrapper<MessengerPeer, MessengerPeerSerde> {
 public:
  explicit MessengerPeer(std::shared_ptr<PeerState> state)
      : state_(std::move(state)) {}

  CoTryTask<WriteECShardRsp> writeECShard(serde::CallContext &ctx, const WriteECShardReq &req) {
    {
      std::lock_guard lock(state_->mutex);
      state_->writeRequest = req;
      state_->lastService = ctx.packet().serviceId;
      state_->lastMethod = ctx.packet().methodId;
    }
    ++state_->writes;
    if (state_->holdWrite) co_await state_->gate;
    ++state_->finishedWrites;
    if (state_->disconnect) ctx.transport()->invalidate(false);
    if (auto code = state_->outerError.load(); code != StatusCode::kOK)
      co_return makeError(code, "injected rpc failure");
    co_return WriteECShardRsp{.status = state_->writeStatus.load()};
  }

  CoTryTask<ReadECShardRsp> readECShard(serde::CallContext &ctx, const ReadECShardReq &req) {
    {
      std::lock_guard lock(state_->mutex);
      state_->readRequest = req;
      state_->lastService = ctx.packet().serviceId;
      state_->lastMethod = ctx.packet().methodId;
    }
    ++state_->reads;
    if (state_->holdRead) co_await state_->gate;
    ++state_->finishedReads;
    if (state_->disconnect) ctx.transport()->invalidate(false);
    if (auto code = state_->outerError.load(); code != StatusCode::kOK)
      co_return makeError(code, "injected rpc failure");
    ReadECShardRsp rsp{.status = state_->readStatus.load()};
    if (rsp.status == ECShardStatus::Ok) {
      std::lock_guard lock(state_->mutex);
      rsp.record = state_->readRecord;
    }
    co_return rsp;
  }

  CoTryTask<WriteRsp> write(serde::CallContext &ctx, const WriteReq &req) {
    ++state_->legacyWrites;
    if (state_->holdWrite) co_await state_->gate;
    if (state_->disconnect) ctx.transport()->invalidate(false);
    co_return WriteRsp{.tag = req.tag,
                       .result = IOResult{Result<uint32_t>{req.payload.length}, ChunkVer{}, ChunkVer{}}};
  }
  CoTryTask<BatchReadRsp> batchRead(serde::CallContext &, const BatchReadReq &req) {
    co_return BatchReadRsp{.tag = req.tag};
  }
  CoTryTask<UpdateRsp> update(serde::CallContext &, const UpdateReq &req) {
    co_return UpdateRsp{.tag = req.tag,
                        .result = IOResult{Result<uint32_t>{req.payload.length}, ChunkVer{}, ChunkVer{}}};
  }

 private:
  std::shared_ptr<PeerState> state_;
};

class ECShardMessenger : public testing::Test {
 protected:
  std::shared_ptr<PeerState> state = std::make_shared<PeerState>();
  net::Server::Config serverConfig;
  net::Client::Config clientConfig;
  std::unique_ptr<net::Server> server;
  std::unique_ptr<hf3fs::storage::client::StorageMessenger> messenger;
  net::Address address;

  void SetUp() override {
    serverConfig.set_groups_length(1);
    serverConfig.groups(0).set_network_type(net::Address::LOCAL);
    serverConfig.groups(0).set_services({"StorageSerde"});
    serverConfig.groups(0).listener().set_listen_port(0);
    server = std::make_unique<net::Server>(serverConfig);
    ASSERT_TRUE(server->setup());
    ASSERT_TRUE(server->addSerdeService(std::make_unique<MessengerPeer>(state), true));
    ASSERT_TRUE(server->start());
    ASSERT_FALSE(server->groups().front()->addressList().empty());
    address = server->groups().front()->addressList().front();
    ASSERT_EQ(address.type, net::Address::TCP);
    ASSERT_EQ(address.ipStr(), "127.0.0.1");
    ASSERT_NE(address.port, 0);
    clientConfig.set_default_timeout(500_ms);
    messenger = std::make_unique<hf3fs::storage::client::StorageMessenger>(clientConfig);
    ASSERT_TRUE(messenger->start("ECMsgTest"));
  }
  void shutdown() {
    state->release();  // Never strand a peer coroutine on a failing assertion.
    if (messenger) {
      messenger->stopAndJoin();
      messenger.reset();
    }
    if (server) {
      server->stopAndJoin();
      server.reset();
    }
  }
  void TearDown() override { shutdown(); }
};

TEST_F(ECShardMessenger, WriteParametersMethodAndLazyOwnership) {
  auto req = makeWrite();
  const auto expected = serde::serialize(req);
  serde::Timestamp timestamp;
  // Stack options/address disappear before the lazy Task starts.
  auto task = [&] {
    net::Address localAddress = address;
    net::UserRequestOptions options;
    options.timeout = 2_s;
    return messenger->writeECShard(localAddress, req, &options, &timestamp);
  }();
  req.record.payload.bytes.clear();
  req.targetId = flat::TargetId{9};
  auto result = folly::coro::blockingWait(std::move(task));
  ASSERT_TRUE(result);
  EXPECT_TRUE(result->succeeded());
  EXPECT_GT(timestamp.clientWaked, 0);
  std::lock_guard lock(state->mutex);
  ASSERT_TRUE(state->writeRequest);
  EXPECT_TRUE(serde::serialize(*state->writeRequest) == expected);
  EXPECT_EQ(state->lastService, 3);
  EXPECT_EQ(state->lastMethod, 18);
  EXPECT_EQ(state->writes.load(), 1u);
}

TEST_F(ECShardMessenger, ReadParametersMethodAndTemporaryOwnership) {
  const auto expected = serde::serialize(makeRead());
  auto task = [&] {
    auto req = makeRead();
    auto localAddress = address;
    return messenger->readECShard(localAddress, std::move(req));
  }();
  auto result = folly::coro::blockingWait(std::move(task));
  ASSERT_TRUE(result);
  EXPECT_FALSE(result->succeeded());
  EXPECT_EQ(result->status, ECShardStatus::NotFound);
  std::lock_guard lock(state->mutex);
  ASSERT_TRUE(state->readRequest);
  EXPECT_TRUE(serde::serialize(*state->readRequest) == expected);
  EXPECT_EQ(state->lastService, 3);
  EXPECT_EQ(state->lastMethod, 19);
}

TEST_F(ECShardMessenger, OuterErrorsPreserveCodeAndMessage) {
  state->outerError = RPCCode::kRequestRefused;
  auto w = folly::coro::blockingWait(messenger->writeECShard(address, makeWrite()));
  auto r = folly::coro::blockingWait(messenger->readECShard(address, makeRead()));
  ASSERT_FALSE(w);
  ASSERT_FALSE(r);
  EXPECT_EQ(w.error().code(), RPCCode::kRequestRefused);
  EXPECT_EQ(r.error().code(), RPCCode::kRequestRefused);
  EXPECT_EQ(w.error().message(), "injected rpc failure");
  EXPECT_EQ(r.error().message(), "injected rpc failure");
  EXPECT_EQ(state->writes.load(), 1u);
  EXPECT_EQ(state->reads.load(), 1u);
}

TEST_F(ECShardMessenger, BusinessOutcomesAreNotFlattenedIntoTransportSuccess) {
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
    state->writeStatus = status;
    auto w = folly::coro::blockingWait(messenger->writeECShard(address, makeWrite()));
    ASSERT_TRUE(w);
    EXPECT_EQ(w->status, status);
    EXPECT_EQ(w->succeeded(), status == ECShardStatus::Created || status == ECShardStatus::ExistingVerified);
  }
  for (auto status : {ECShardStatus::NotFound,
                      ECShardStatus::CorruptRecord,
                      ECShardStatus::TargetUnavailable,
                      ECShardStatus::ECDisabled,
                      ECShardStatus::InvalidRequest,
                      ECShardStatus::QueueFull,
                      ECShardStatus::BackendError,
                      ECShardStatus::InternalError}) {
    state->readStatus = status;
    auto r = folly::coro::blockingWait(messenger->readECShard(address, makeRead()));
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, status);
    EXPECT_FALSE(r->succeeded());
  }
}

TEST_F(ECShardMessenger, ReadPayloadOwnsBytesAfterPeerAndMessengerAreDestroyed) {
  state->readStatus = ECShardStatus::Ok;
  auto expected = makeRecord();
  auto result = folly::coro::blockingWait(messenger->readECShard(address, makeRead()));
  ASSERT_TRUE(result);
  ASSERT_TRUE(result->succeeded());
  shutdown();
  state->readRecord = {};
  ASSERT_TRUE(result->record);
  EXPECT_EQ(result->record->payload.bytes, expected.payload.bytes);
  EXPECT_TRUE(serde::serialize(*result->record) == serde::serialize(expected));
}

TEST_F(ECShardMessenger, WriteCustomTimeoutDoesNotRetryOrCancelAcceptedPeerCall) {
  state->holdWrite = true;
  net::UserRequestOptions options;
  options.timeout = 200_ms;
  auto result = folly::coro::blockingWait(messenger->writeECShard(address, makeWrite(), &options));
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), RPCCode::kTimeout);
  EXPECT_EQ(state->writes.load(), 1u);
  EXPECT_EQ(state->finishedWrites.load(), 0u);
  state->release();  // Accepted peer coroutine survives the client timeout.
  auto read = folly::coro::blockingWait(messenger->readECShard(address, makeRead()));
  ASSERT_TRUE(read);
  EXPECT_EQ(state->writes.load(), 1u);
  shutdown();
  EXPECT_EQ(state->finishedWrites.load(), 1u);
}

TEST_F(ECShardMessenger, ReadUsesDefaultTimeout) {
  state->holdRead = true;
  auto result = folly::coro::blockingWait(messenger->readECShard(address, makeRead()));
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), RPCCode::kTimeout);
  EXPECT_EQ(state->reads.load(), 1u);
  EXPECT_EQ(state->finishedReads.load(), 0u);
  state->release();
  shutdown();
  EXPECT_EQ(state->finishedReads.load(), 1u);
}

TEST_F(ECShardMessenger, DisconnectMatchesExistingMessengerFailureSemantics) {
  state->disconnect = true;
  net::UserRequestOptions options;
  options.timeout = 1_s;
  auto w = folly::coro::blockingWait(messenger->writeECShard(address, makeWrite(), &options));
  auto r = folly::coro::blockingWait(messenger->readECShard(address, makeRead(), &options));
  WriteReq legacy;
  auto old = folly::coro::blockingWait(messenger->write(address, legacy, &options));
  ASSERT_FALSE(w);
  ASSERT_FALSE(r);
  ASSERT_FALSE(old);
  // Waiter::clearPendingRequestsOnTransportFailure reports Timeout in this
  // repository, even for an established socket closed by the peer.
  EXPECT_EQ(w.error().code(), RPCCode::kTimeout);
  EXPECT_EQ(r.error().code(), old.error().code());
  EXPECT_EQ(w.error().code(), old.error().code());
  EXPECT_EQ(state->writes.load(), 1u);
  EXPECT_EQ(state->reads.load(), 1u);
  EXPECT_EQ(state->legacyWrites.load(), 1u);
}

TEST_F(ECShardMessenger, ExistingWriteReadAndUpdateInterfacesStillWork) {
  WriteReq w;
  w.payload.length = 73;
  auto written = folly::coro::blockingWait(messenger->write(address, w));
  ASSERT_TRUE(written);
  ASSERT_TRUE(written->result.lengthInfo);
  EXPECT_EQ(*written->result.lengthInfo, 73u);
  BatchReadReq r;
  auto read = folly::coro::blockingWait(messenger->batchRead(address, r));
  ASSERT_TRUE(read);
  EXPECT_TRUE(read->results.empty());
  UpdateReq u;
  u.payload.length = 19;
  auto updated = folly::coro::blockingWait(messenger->update(address, u));
  ASSERT_TRUE(updated);
  ASSERT_TRUE(updated->result.lengthInfo);
  EXPECT_EQ(*updated->result.lengthInfo, 19u);
}

}  // namespace
