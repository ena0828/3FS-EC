#include "fbs/meta/EcRequestDigest.h"

#include <algorithm>
#include <memory>
#include <openssl/evp.h>
#include <span>

namespace hf3fs::meta {
namespace {
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

Result<storage::EcSha256> digest(std::span<const std::string_view> parts) {
  Context ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
    return makeError(StatusCode::kIOError, "cannot initialize EC request digest");
  }
  for (auto part : parts) {
    if (EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
      return makeError(StatusCode::kIOError, "cannot update EC request digest");
    }
  }
  storage::EcSha256 result{};
  unsigned length = 0;
  if (EVP_DigestFinal_ex(ctx.get(), result.data(), &length) != 1 || length != result.size()) {
    return makeError(StatusCode::kIOError, "cannot finalize EC request digest");
  }
  return result;
}
void number(std::string &out, uint64_t value, size_t width) {
  for (size_t i = width; i != 0; --i) out.push_back(static_cast<char>(value >> ((i - 1) * 8)));
}
}  // namespace

Result<storage::EcSha256> computeEcRequestDigest(const EcMutationIntent &intent,
                                                 uint32_t shardBytes,
                                                 const storage::EcSha256 &content) {
  if (!shardBytes || shardBytes > storage::kEcFragmentRpcMaxBytes || !intent.logicalLength ||
      intent.logicalLength > uint64_t(shardBytes) * 10 || intent.object.incarnation.is_nil()) {
    return makeError(StatusCode::kInvalidArg, "invalid EC request digest shape");
  }
  std::string header("3FS-EC-REQUEST\0\1", 16);
  number(header, intent.object.inode.u64(), 8);
  header.append(intent.object.incarnation.asStringView());
  number(header, intent.stripe, 8);
  number(header, intent.expectedEpoch, 8);
  number(header, intent.expectedRevision, 8);
  number(header, intent.logicalLength, 8);
  number(header, shardBytes, 4);
  number(header, static_cast<uint8_t>(intent.kind), 1);
  number(header, intent.replacementMask, 2);
  for (uint16_t value : {1, 1, 10, 2, 0x11d}) number(header, value, 2);
  for (uint32_t crc : intent.fragmentCrc32c) number(header, crc, 4);
  const std::array<std::string_view, 2> parts{
      header,
      std::string_view(reinterpret_cast<const char *>(content.data()), content.size())};
  return digest(parts);
}

Result<storage::EcSha256> computeEcLogicalSha256(const std::array<std::string_view, 10> &data, uint64_t logicalLength) {
  std::array<std::string_view, 10> parts{};
  uint64_t remaining = logicalLength;
  for (size_t i = 0; i != data.size(); ++i) {
    const auto length = static_cast<size_t>(std::min<uint64_t>(remaining, data[i].size()));
    parts[i] = data[i].substr(0, length);
    remaining -= length;
  }
  if (remaining) return makeError(StatusCode::kInvalidArg, "EC logical length exceeds data shards");
  return digest(parts);
}
}  // namespace hf3fs::meta
