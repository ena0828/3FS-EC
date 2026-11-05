#pragma once

#include "client/ec/EcStripeRunRecord.h"

namespace hf3fs::client::ec {
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
