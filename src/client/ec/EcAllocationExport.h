#pragma once

#include "client/ec/EcStripeRunRecord.h"

namespace hf3fs::client::ec {
// Local-only export of one completed tree-read snapshot (at most eight stripes).
// Requires an existing exclusive journal lock; creates only a new output archive.
// Includes Released snapshots but conveys no retirement/GC or full-history authority.
Result<Void> exportEcTreeReadAllocations(const std::filesystem::path &readRun,
                                         const std::filesystem::path &output);

// Pure validation shared by metadata export and the explicit recovery writer.
// The caller supplies a real authenticated RPC33 response, never a grant.
Result<Void> validatePublishedEcStripeRun(const EcStripeRunRecord &,
                                          const EcStripeRunObservation &,
                                          const meta::EcV2MutationRsp &);
// The caller retains the journal's exclusive lock until this task completes.
// Queries the original operation through authenticated MetaClient RPC 33;
// never acquires a pin, issues a grant or mutates remote metadata. The archive
// is a metadata observation, not permission to retire or collect an allocation.
CoTryTask<void> exportEcAllocations(std::shared_ptr<meta::client::MetaClient> metadata,
                                    const EcStripeRunJournal &journal,
                                    flat::UserInfo credentials,
                                    std::filesystem::path output,
                                    EcStripeControl control);
}  // namespace hf3fs::client::ec
