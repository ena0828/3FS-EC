#include "client/ec/EcAllocationExport.h"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <folly/json.h>
#include <memory>
#include <span>
#include <sys/stat.h>
#include <unistd.h>

#include "client/meta/MetaClient.h"
#include "fbs/meta/EcRequestDigest.h"

namespace hf3fs::client::ec {
namespace {
Result<Void> active(const EcStripeControl &control) {
  if (control.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
Result<Void> corrupt() {
  return makeError(StatusCode::kDataCorruption, "operation metadata differs from the published run");
}
bool owner(const meta::EcOwner &a, const meta::EcOwner &b) { return a.uid == b.uid && a.client == b.client; }
std::string hex(const storage::EcSha256 &value) {
  return serde::SerdeMethod<storage::EcSha256>::serdeToReadable(value);
}
folly::dynamic objectJson(const meta::EcObjectRef &object) {
  return folly::dynamic::object("inode_decimal", std::to_string(object.inode.u64()))("incarnation",
                                                                                     object.incarnation.toHexString());
}

// No replacement or temporary rename can overwrite an earlier observation.
// The output parent must already exist. An unsuccessful attempt can leave an
// empty/partial archive; it is not a confirmed export and is never reused.
class Archive {
 public:
  static Result<std::unique_ptr<Archive>> open(const std::filesystem::path &path) {
    if (path.empty() || path.filename().empty() || path.filename() == "." || path.filename() == "..")
      return makeError(StatusCode::kInvalidArg, "allocation_output requires an explicit new file");
    auto value = std::make_unique<Archive>();
    const auto parent = path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
    value->directory_ = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (value->directory_ < 0) return makeError(StatusCode::kIOError, "cannot open allocation output directory");
    value->file_ = ::openat(value->directory_,
                            path.filename().c_str(),
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                            0600);
    if (value->file_ < 0) return makeError(StatusCode::kIOError, "allocation output must be a new exclusive file");
    if (::fchmod(value->file_, 0600) != 0 || ::fsync(value->file_) != 0 || ::fsync(value->directory_) != 0)
      return makeError(StatusCode::kIOError, "cannot persist allocation output creation");
    return std::move(value);
  }
  ~Archive() {
    if (file_ >= 0) ::close(file_);
    if (directory_ >= 0) ::close(directory_);
  }
  Result<Void> write(std::string_view bytes) {
    size_t offset = 0;
    while (offset != bytes.size()) {
      auto count = ::write(file_, bytes.data() + offset, bytes.size() - offset);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) return makeError(StatusCode::kIOError, "cannot write allocation export");
      offset += static_cast<size_t>(count);
    }
    if (::fsync(file_) != 0 || ::fsync(directory_) != 0)
      return makeError(StatusCode::kIOError, "cannot persist allocation export");
    return Void{};
  }

 private:
  int file_ = -1, directory_ = -1;
};

Result<Void> validate(const EcStripeRunRecord &run,
                      const EcStripeRunObservation &observed,
                      const meta::EcV2MutationRsp &rsp) {
  const auto &op = rsp.record;
  const auto &intent = op.intent;
  const auto &manifest = op.candidate;
  const auto &saved = *observed.object;
  const meta::EcOwner expected{flat::Uid(observed.ownerUid), run.clientNamespace};
  if (op.version != meta::kEcCatalogVersion || intent.version != meta::kEcCatalogVersion ||
      manifest.version != meta::kEcCatalogVersion || rsp.object.version != meta::kEcCatalogVersion ||
      op.state != meta::EcOperationState::Published || !owner(op.owner, expected) || intent.object != saved.object ||
      intent.operation != run.operation || intent.stripe != 0 || intent.expectedRevision != run.expectedRevision ||
      !intent.expectedEpoch || intent.logicalLength != run.inputBytes ||
      intent.kind != (run.action == "repair" ? meta::EcMutationKind::Repair : meta::EcMutationKind::Write) ||
      intent.replacementMask != (run.action == "repair" ? run.replacementMask : meta::kEcAllShards) ||
      manifest.object != saved.object || manifest.stripe != 0 || !manifest.generation ||
      manifest.revision != observed.revision || manifest.logicalLength != run.inputBytes ||
      rsp.object.object != saved.object || rsp.object.shardBytes != run.shardBytes ||
      rsp.object.createRequest != saved.createRequest || !owner(rsp.object.creator, saved.creator) ||
      rsp.object.allowColocated != saved.allowColocated || !rsp.reservation || !rsp.allocations)
    return corrupt();
  const auto &reservation = *rsp.reservation;
  if (reservation.version != meta::kEcV2LifecycleVersion || reservation.original.version != meta::kEcCatalogVersion ||
      reservation.original.candidate.version != meta::kEcCatalogVersion ||
      reservation.original.state != meta::EcOperationState::Preparing ||
      !serde::equals(reservation.original.intent, intent) || !owner(reservation.original.owner, expected) ||
      reservation.original.candidate.object != manifest.object ||
      reservation.original.candidate.stripe != manifest.stripe ||
      reservation.original.candidate.generation != manifest.generation ||
      reservation.original.candidate.revision != manifest.revision ||
      reservation.original.candidate.logicalLength != manifest.logicalLength ||
      reservation.contentSha256 != run.inputSha256)
    return corrupt();
  CHECK_RESULT(digest, meta::computeEcRequestDigest(intent, run.shardBytes, reservation.contentSha256));
  if (digest != intent.requestDigest) return corrupt();
  const auto &set = reservation.operationEndpoints;
  if (set.count < 12 || set.count > 24) return corrupt();
  std::array<storage::EcScopeEndpoint, 24> endpoints{};
  for (size_t i = 0; i != set.endpoints.size(); ++i) {
    if (i >= set.count) {
      if (set.endpoints[i] != meta::EcV2PhysicalEndpoint{}) return corrupt();
      continue;
    }
    for (size_t j = 0; j != i; ++j)
      if (set.endpoints[i] == set.endpoints[j]) return corrupt();
    endpoints[i] = set.endpoints[i].controlEndpoint();
  }
  CHECK_RESULT(endpointDigest, storage::computeEcScopeEndpointDigest(std::span(endpoints.data(), set.count)));
  if (endpointDigest != set.digest) return corrupt();
  for (size_t i = 0; i != 12; ++i) {
    const auto &binding = (*rsp.allocations)[i];
    const auto &fragment = binding.fragment;
    const auto &identity = fragment.identity;
    const auto &reserved = reservation.candidates[i];
    const auto &original = reservation.original.candidate.fragments[i];
    RETURN_ON_ERROR(identity.validate());
    RETURN_ON_ERROR(storage::validateEcIntegrity(identity, fragment.integrity));
    if (binding.version != meta::kEcBindingCatalogVersion || binding.object != saved.object ||
        !(fragment == manifest.fragments[i]) || identity.object != saved.object.incarnation ||
        identity.stripe != manifest.stripe || identity.generation != manifest.generation || identity.shard != i ||
        fragment.operation.is_nil() || binding.writer.client.is_nil() || !fragment.placement.node.toUnderType() ||
        !fragment.placement.chain.toUnderType() || !fragment.placement.target.toUnderType() ||
        binding.engineUuid.is_nil() || binding.targetIncarnation.is_nil() ||
        fragment.placement != intent.placements[i] || fragment.integrity.wholeLength != run.shardBytes ||
        fragment.integrity.wholeCrc32c != intent.fragmentCrc32c[i] || !serde::equals(identity, original.identity) ||
        fragment.operation != original.operation || fragment.placement != original.placement ||
        (run.action == "repair" && fragment.integrity != original.integrity) ||
        (run.action == "write" && original.integrity != storage::EcIntegrityDescriptor{}) ||
        !serde::equals(identity, reserved.identity) || fragment.operation != reserved.operation ||
        binding.endpoint() != reserved.endpoint || !owner(binding.writer, reserved.writer) ||
        std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, binding.endpoint()) ==
            set.endpoints.begin() + set.count)
      return corrupt();
    // Unchanged repair shards retain their original fragment operation/writer.
    if ((intent.replacementMask & (1u << i)) &&
        (fragment.operation != run.operation || !owner(binding.writer, expected)))
      return corrupt();
    for (size_t previous = 0; previous != i; ++previous) {
      const auto &other = (*rsp.allocations)[previous];
      if (identity.allocation == other.fragment.identity.allocation ||
          fragment.placement.target == other.fragment.placement.target ||
          fragment.placement.chain == other.fragment.placement.chain)
        return corrupt();
    }
  }
  // GetOperation must not accidentally mint capabilities; even if a server
  // regresses, do not turn an export into a credential archive.
  if (std::any_of(rsp.grants.begin(), rsp.grants.end(), [](const auto &grant) { return grant.has_value(); }))
    return corrupt();
  return Void{};
}

folly::dynamic allocationJson(const meta::EcV2AllocationBinding &binding) {
  const auto &f = binding.fragment;
  const auto &id = f.identity;
  const auto &d = f.integrity;
  folly::dynamic blocks = folly::dynamic::array;
  // Preserve all sixteen fixed slots, including canonical unused zero entries.
  for (const auto &block : d.blocks)
    blocks.push_back(
        folly::dynamic::object("valid_length", block.validLength)("crc32c", block.crc32c)("sha256", hex(block.sha256)));
  folly::dynamic integrity = folly::dynamic::object("version", d.version)("codec_id", d.codecId)(
      "matrix_version",
      d.matrixVersion)("data_shards", d.dataShards)("parity_shards", d.parityShards)(
      "field_polynomial",
      d.fieldPolynomial)("block_bytes", d.blockBytes)("whole_length", d.wholeLength)("whole_crc32c", d.wholeCrc32c)(
      "block_count",
      d.blockCount)("blocks", std::move(blocks))("root", hex(d.root));
  folly::dynamic identity =
      folly::dynamic::object("version", id.version)("object", id.object.toHexString())("stripe_decimal",
                                                                                       std::to_string(id.stripe))(
          "generation_decimal",
          std::to_string(id.generation))("shard", id.shard)("allocation", id.allocation.toHexString());
  folly::dynamic placement = folly::dynamic::object("node", f.placement.node.toUnderType())(
      "chain",
      f.placement.chain.toUnderType())("target_decimal", std::to_string(f.placement.target.toUnderType()));
  return folly::dynamic::object("version", binding.version)("identity", std::move(identity))(
      "fragment_operation",
      f.operation.toHexString())("placement", std::move(placement))("engine_uuid", binding.engineUuid.toHexString())(
      "target_incarnation",
      binding.targetIncarnation.toHexString())("writer",
                                               folly::dynamic::object("uid", binding.writer.uid.toUnderType())(
                                                   "client_namespace",
                                                   binding.writer.client.toHexString()))("integrity",
                                                                                         std::move(integrity));
}
}  // namespace

CoTryTask<void> exportEcAllocations(std::shared_ptr<meta::client::MetaClient> metadata,
                                    const EcStripeRunJournal &journal,
                                    flat::UserInfo credentials,
                                    std::filesystem::path output,
                                    EcStripeControl control) {
  try {
    const auto &run = journal.record();
    CO_RETURN_ON_ERROR(run.validate());
    if (!metadata || metadata->clientId().uuid != run.clientNamespace || !journal.latest())
      co_return makeError(StatusCode::kTokenMismatch, "export requires the original client namespace and journal");
    const auto &observed = *journal.latest();
    if ((run.action != "write" && run.action != "repair") || !observed.mutationPublished || !observed.object ||
        !observed.revision || observed.errorCode ||
        (observed.state != "Published" && !(run.action == "repair" && observed.state == "ReadReleased")) ||
        observed.object->shardBytes != run.shardBytes || (run.object && run.object->object != observed.object->object))
      co_return makeError(StatusCode::kInvalidArg, "export requires an observed Published write/repair run");
    CO_RETURN_ON_ERROR(active(control));
    auto opened = Archive::open(output);
    CO_RETURN_ON_ERROR(opened);
    auto archive = std::move(*opened);
    // Authenticate first, then compare the verified effective UID with the
    // durable run owner. Root is not an alternate owner for this read API.
    auto authenticated = co_await metadata->authenticate(credentials);
    if (!authenticated) co_return makeError(std::move(authenticated.error()));
    CO_RETURN_ON_ERROR(active(control));
    if (authenticated->uid.toUnderType() != observed.ownerUid ||
        (run.expectedOwnerUid && authenticated->uid.toUnderType() != *run.expectedOwnerUid))
      co_return makeError(StatusCode::kAuthenticationFail, "authenticated UID differs from original run owner");
    auto token = std::move(credentials.token);
    credentials = std::move(*authenticated);
    credentials.token = std::move(token);
    meta::GetEcOperationV2Req req;
    req.user = std::move(credentials);
    req.uuid = run.getRequest;
    req.object = observed.object->object;
    req.operation = run.operation;
    auto result = co_await metadata->getEcOperationV2(std::move(req));
    if (!result) co_return makeError(std::move(result.error()));
    // Await the real request to completion; this deadline never destroys an
    // in-flight borrowed RPC or implies a remote mutation was canceled.
    CO_RETURN_ON_ERROR(active(control));
    CO_RETURN_ON_ERROR(validate(run, observed, *result));
    folly::dynamic allocations = folly::dynamic::array;
    for (const auto &binding : *result->allocations) allocations.push_back(allocationJson(binding));
    const auto &manifest = result->record.candidate;
    folly::dynamic value = folly::dynamic::object("schema", 1)("cluster", run.cluster)(
        "client_namespace",
        run.clientNamespace.toHexString())("owner_uid", observed.ownerUid)("operation", run.operation.toHexString())(
        "request_id",
        run.getRequest.toHexString())("query_rpc", 33)("mutation_state", "Published")(
        "object",
        objectJson(manifest.object))("stripe_decimal", std::to_string(manifest.stripe))(
        "revision_decimal",
        std::to_string(manifest.revision))("generation_decimal", std::to_string(manifest.generation))(
        "logical_bytes_decimal",
        std::to_string(manifest.logicalLength))("shard_bytes", run.shardBytes)(
        "content_sha256",
        hex(result->reservation->contentSha256))("allocations", std::move(allocations))("metadata_observation_only",
                                                                                        true)("gc_authorized", false);
    CO_RETURN_ON_ERROR(archive->write(folly::toJson(value) + "\n"));
    co_return Void{};
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(StatusCode::kIOError);
  }
}
}  // namespace hf3fs::client::ec
