#pragma once

#include "fbs/storage/EcStageResultV2.h"

namespace hf3fs::storage {

// Client-side response consistency checks. The caller supplies the capability
// obtained from its trusted Meta path; these checks do not verify its MAC.
Result<Void> validateEcReceiptV2(const EcFragmentReceiptV2 &, const EcFragmentAccessV2 &, const EcGrantClaimsV2 &);
Result<Void> validateEcStageStateV2(const EcStageStateV2 &, const EcFragmentAccessV2 &, const EcGrantClaimsV2 &);
Result<Void> validateEcReadBlockV2(const EcReadBlockResultV2 &, const EcReadBlockV2Req &);
}  // namespace hf3fs::storage
