#pragma once

#include "meta/store/EcV2DrainCatalog.h"

namespace hf3fs::meta::server {
// Historical provenance, separate from V1 manifests and pin schemas. It is
// written in the same transaction as V2 T2 publication and never inferred from
// whichever mixed old/new fragment happens to be present after a repair.
struct EcV2PublishedContent {
  SERDE_STRUCT_FIELD(version, kEcV2LifecycleVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
};
class EcV2PublishedCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  static CoTryTask<EcV2PublishedContent> get(Transaction &, const EcObjectRef &, uint64_t stripe, uint64_t revision);
  // No caller-supplied digest. Requires an already completed, authenticated T2
  // record and extracts its immutable proof and permanent Begin commitment.
  static CoTryTask<EcV2PublishedContent> record(Transaction &,
                                                const EcObjectRef &,
                                                const Uuid &operation,
                                                const EcOwner &);
};
}  // namespace hf3fs::meta::server
