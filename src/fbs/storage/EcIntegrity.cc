#include "fbs/storage/EcIntegrity.h"

#include <algorithm>
#include <folly/hash/Checksum.h>
#include <memory>
#include <openssl/evp.h>

namespace hf3fs::storage {
namespace {

void appendInteger(std::string &out, uint64_t value, size_t bytes) {
  for (size_t index = bytes; index != 0; --index) out.push_back(static_cast<char>(value >> ((index - 1) * 8)));
}

// Common prefix after the eight-byte domain tag:
// identity.version:u16, object:16, stripe:u64, generation:u64, shard:u16,
// version:u16, codec:u16, matrix:u16, k:u16, m:u16, polynomial:u16,
// blockBytes:u32, wholeLength:u32. Integers are big endian.
std::string header(std::string_view domain,
                   const EcFragmentIdentity &identity,
                   const EcIntegrityDescriptor &descriptor) {
  std::string out(domain);
  appendInteger(out, identity.version, 2);
  out.append(identity.object.asStringView());
  appendInteger(out, identity.stripe, 8);
  appendInteger(out, identity.generation, 8);
  appendInteger(out, identity.shard, 2);
  appendInteger(out, descriptor.version, 2);
  appendInteger(out, descriptor.codecId, 2);
  appendInteger(out, descriptor.matrixVersion, 2);
  appendInteger(out, descriptor.dataShards, 2);
  appendInteger(out, descriptor.parityShards, 2);
  appendInteger(out, descriptor.fieldPolynomial, 2);
  appendInteger(out, descriptor.blockBytes, 4);
  appendInteger(out, descriptor.wholeLength, 4);
  return out;
}

Result<EcSha256> digest(std::string_view prefix, std::string_view payload = {}) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context) return makeError(StatusCode::kNotEnoughMemory, "cannot allocate EC digest context");
  EcSha256 result{};
  unsigned int length = 0;
  if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), prefix.data(), prefix.size()) != 1 ||
      (!payload.empty() && EVP_DigestUpdate(context.get(), payload.data(), payload.size()) != 1) ||
      EVP_DigestFinal_ex(context.get(), result.data(), &length) != 1 || length != result.size()) {
    return makeError(StatusCode::kIOError, "EC SHA-256 calculation failed");
  }
  return result;
}

uint32_t crc32c(std::string_view bytes) {
  if (bytes.empty()) return 0;
  return ~folly::crc32c(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size(), ~uint32_t{});
}

Result<EcSha256> blockHash(const EcFragmentIdentity &identity,
                           const EcIntegrityDescriptor &descriptor,
                           uint32_t blockIndex,
                           std::string_view bytes) {
  auto prefix = header(std::string_view("3FSECB\0\1", 8), identity, descriptor);
  appendInteger(prefix, blockIndex, 4);
  appendInteger(prefix, bytes.size(), 4);
  return digest(prefix, bytes);
}

Result<EcSha256> rootHash(const EcFragmentIdentity &identity, const EcIntegrityDescriptor &descriptor) {
  auto prefix = header(std::string_view("3FSECR\0\1", 8), identity, descriptor);
  appendInteger(prefix, descriptor.wholeCrc32c, 4);
  appendInteger(prefix, descriptor.blockCount, 2);
  for (uint32_t index = 0; index != descriptor.blockCount; ++index) {
    const auto &block = descriptor.blocks[index];
    appendInteger(prefix, index, 4);
    appendInteger(prefix, block.validLength, 4);
    appendInteger(prefix, block.crc32c, 4);
    prefix.append(reinterpret_cast<const char *>(block.sha256.data()), block.sha256.size());
  }
  return digest(prefix);
}

Result<Void> validateIdentity(const EcFragmentIdentity &identity) {
  RETURN_ON_ERROR(identity.validate());
  if (identity.shard >= 12) return makeError(StatusCode::kInvalidArg, "EC integrity format 1 requires shard < 12");
  return Void{};
}

}  // namespace

Result<EcIntegrityDescriptor> computeEcIntegrity(const EcFragmentIdentity &identity, std::string_view bytes) {
  RETURN_ON_ERROR(validateIdentity(identity));
  if (bytes.size() > kEcFragmentRpcMaxBytes) {
    return makeError(StatusCode::kInvalidArg, "EC integrity fragment exceeds 1 MiB");
  }
  EcIntegrityDescriptor descriptor;
  descriptor.wholeLength = bytes.size();
  descriptor.wholeCrc32c = crc32c(bytes);
  descriptor.blockCount = (bytes.size() + kEcIntegrityBlockBytes - 1) / kEcIntegrityBlockBytes;
  for (uint32_t index = 0; index != descriptor.blockCount; ++index) {
    auto input = bytes.substr(index * kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
    auto &block = descriptor.blocks[index];
    block.validLength = input.size();
    block.crc32c = crc32c(input);
    CHECK_RESULT(hash, blockHash(identity, descriptor, index, input));
    block.sha256 = hash;
  }
  CHECK_RESULT(root, rootHash(identity, descriptor));
  descriptor.root = root;
  return descriptor;
}

Result<Void> validateEcIntegrity(const EcFragmentIdentity &identity, const EcIntegrityDescriptor &descriptor) {
  RETURN_ON_ERROR(validateIdentity(identity));
  if (descriptor.version != 1 || descriptor.codecId != 1 || descriptor.matrixVersion != 1 ||
      descriptor.dataShards != 10 || descriptor.parityShards != 2 || descriptor.fieldPolynomial != 0x11d ||
      descriptor.blockBytes != kEcIntegrityBlockBytes || descriptor.wholeLength > kEcFragmentRpcMaxBytes) {
    return makeError(StatusCode::kInvalidArg, "unsupported EC integrity parameters");
  }
  const auto count = (descriptor.wholeLength + kEcIntegrityBlockBytes - 1) / kEcIntegrityBlockBytes;
  if (descriptor.blockCount != count || (descriptor.wholeLength == 0 && descriptor.wholeCrc32c != 0)) {
    return makeError(StatusCode::kInvalidArg, "EC integrity block count or empty CRC is invalid");
  }
  for (uint32_t index = 0; index != kEcIntegrityMaxBlocks; ++index) {
    const auto &block = descriptor.blocks[index];
    if (index < count) {
      const auto expected = std::min(kEcIntegrityBlockBytes, descriptor.wholeLength - index * kEcIntegrityBlockBytes);
      if (block.validLength != expected) {
        return makeError(StatusCode::kInvalidArg, "EC integrity block length is invalid");
      }
    } else if (block.validLength != 0 || block.crc32c != 0 || block.sha256 != EcSha256{}) {
      return makeError(StatusCode::kInvalidArg, "unused EC integrity slot is not zero");
    }
  }
  CHECK_RESULT(expected, rootHash(identity, descriptor));
  if (descriptor.root != expected) return makeError(StatusCode::kDataCorruption, "EC integrity root mismatch");
  return Void{};
}

Result<Void> verifyEcIntegrityBlock(const EcFragmentIdentity &identity,
                                    const EcIntegrityDescriptor &descriptor,
                                    uint32_t blockIndex,
                                    std::string_view bytes) {
  RETURN_ON_ERROR(validateEcIntegrity(identity, descriptor));
  if (blockIndex >= descriptor.blockCount || bytes.size() != descriptor.blocks[blockIndex].validLength) {
    return makeError(StatusCode::kInvalidArg, "EC integrity read must return one complete aligned block");
  }
  const auto &expected = descriptor.blocks[blockIndex];
  if (crc32c(bytes) != expected.crc32c) return makeError(StatusCode::kDataCorruption, "EC block CRC32C mismatch");
  CHECK_RESULT(hash, blockHash(identity, descriptor, blockIndex, bytes));
  if (hash != expected.sha256) return makeError(StatusCode::kDataCorruption, "EC block SHA-256 mismatch");
  return Void{};
}

}  // namespace hf3fs::storage
