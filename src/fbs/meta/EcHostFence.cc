#include "fbs/meta/EcHostFence.h"

#include <algorithm>
#include <fstream>
#include <memory>
#include <openssl/evp.h>
#include <sys/stat.h>

#include "fbs/meta/EcTargetRetirement.h"

namespace hf3fs::meta {
namespace {
template <class T> bool nonzero(const T &v) { return std::any_of(v.begin(), v.end(), [](auto x) { return x != 0; }); }
}
bool EcHostFenceBinding::valid() const {
  return !providerId.is_nil() && !enrollmentId.is_nil() && !resourceGeneration.is_nil() && nonzero(bindingDigest);
}
bool EcHostFenceSummary::valid() const {
  return !providerId.is_nil() && !enrollmentId.is_nil() && !resourceGeneration.is_nil() &&
         nonzero(bindingDigest) && nonzero(denyDigest) && nonzero(proofDigest) && sequence == 1;
}
Result<EcHostFencePublicKey> EcHostFence::loadPublicKey(std::string_view path) {
  if (path.empty() || path.front() != '/' || path.find('\0') != std::string_view::npos)
    return makeError(StatusCode::kInvalidConfig, "host fence requires an absolute public key path");
  const std::string name(path);
  struct stat st{};
  if (::lstat(name.c_str(), &st) || !S_ISREG(st.st_mode) || st.st_size != 32)
    return makeError(StatusCode::kInvalidConfig, "host fence public key must be a regular 32-byte file");
  std::ifstream input(name, std::ios::binary);
  EcHostFencePublicKey key{};
  input.read(reinterpret_cast<char *>(key.data()), key.size());
  if (!input || input.peek() != std::char_traits<char>::eof() || !nonzero(key))
    return makeError(StatusCode::kInvalidConfig, "invalid host fence public key");
  return key;
}
Result<std::array<uint8_t, kEcHostFenceClaimsBytes>> EcHostFence::claims(
    const EcTargetRetirementIntent &i, const EcHostFenceBinding &b,
    const storage::EcSha256 &deny, uint64_t sequence) {
  if (i.version != 2 || i.authority.is_nil() || i.retirementId.is_nil() || i.requestId.is_nil() ||
      i.owner.uid != flat::Uid(0) || i.owner.client.is_nil() || !b.valid() || !nonzero(deny) || sequence != 1 ||
      i.endpoint.placement.node == flat::NodeId{} || i.endpoint.placement.chain == storage::ChainId{} ||
      i.endpoint.placement.target == storage::TargetId{} || i.endpoint.engineUuid.is_nil() ||
      i.endpoint.targetIncarnation.is_nil()) return makeError(StatusCode::kInvalidArg);
  std::array<uint8_t, kEcHostFenceClaimsBytes> out{};
  size_t n = 0;
  auto bytes = [&](const auto &v) { for (auto c : v) out[n++] = static_cast<uint8_t>(c); };
  auto number = [&](uint64_t v, size_t width) { for (size_t k = width; k; --k) out[n++] = uint8_t(v >> ((k - 1) * 8)); };
  auto uuid = [&](const Uuid &u) { for (auto c : u.data) out[n++] = c; };
  bytes(std::string_view("3FSEHF01")); number(1, 2); number(1, 2); uuid(i.authority);
  number(i.endpoint.placement.node.toUnderType(), 4); number(i.endpoint.placement.chain.toUnderType(), 4);
  number(i.endpoint.placement.target.toUnderType(), 8); uuid(i.endpoint.engineUuid); uuid(i.endpoint.targetIncarnation);
  uuid(b.providerId); uuid(b.enrollmentId); uuid(b.resourceGeneration); uuid(i.retirementId);
  uuid(i.owner.client); number(i.owner.uid.toUnderType(), 4); uuid(i.requestId);
  bytes(b.bindingDigest); bytes(deny); number(sequence, 8);
  if (n != out.size()) return makeError(StatusCode::kInvalidFormat);
  return out;
}
Result<EcHostFenceSummary> EcHostFence::verify(std::string_view certificate,
    const EcTargetRetirementIntent &i, const EcHostFenceBinding &b, const EcHostFencePublicKey &key) {
  if (certificate.size() != kEcHostFenceCertificateBytes || !nonzero(key)) return makeError(StatusCode::kInvalidFormat);
  storage::EcSha256 deny{};
  std::copy_n(reinterpret_cast<const uint8_t *>(certificate.data()) + 208, deny.size(), deny.begin());
  uint64_t sequence = 0;
  for (size_t n = 240; n != 248; ++n) sequence = (sequence << 8) | static_cast<uint8_t>(certificate[n]);
  CHECK_RESULT(expected, claims(i, b, deny, sequence));
  if (!std::equal(expected.begin(), expected.end(), reinterpret_cast<const uint8_t *>(certificate.data())))
    return makeError(StatusCode::kTokenMismatch, "external fence differs from original target and binding");
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key.data(), key.size()), EVP_PKEY_free);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!pk || !ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pk.get()) != 1 ||
      EVP_DigestVerify(ctx.get(), reinterpret_cast<const uint8_t *>(certificate.data()) + 248, 64,
                       reinterpret_cast<const uint8_t *>(certificate.data()), 248) != 1)
    return makeError(StatusCode::kAuthenticationFail, "external fence provider signature rejected");
  EcHostFenceSummary out;
  out.providerId = b.providerId; out.enrollmentId = b.enrollmentId; out.resourceGeneration = b.resourceGeneration;
  out.bindingDigest = b.bindingDigest; out.denyDigest = deny; out.sequence = sequence;
  unsigned int size = 0;
  if (EVP_Digest(certificate.data(), certificate.size(), out.proofDigest.data(), &size, EVP_sha256(), nullptr) != 1 ||
      size != out.proofDigest.size() || !out.valid()) return makeError(StatusCode::kIOError);
  return out;
}
}  // namespace hf3fs::meta
