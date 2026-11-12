#pragma once

#include "EcReadSpoolIO.h"

namespace hf3fs::client::ec::detail {
struct EcReadArchive {
  EcReadReceipt receipt;
  EcFileRunRecord record;
  EcFileRunProgress progress;
};
struct EcReadRetirementMarker {
  EcReadReceipt receipt;
  std::filesystem::path archive;
  storage::EcSha256 digest{};
};
Result<std::string> encodeReadArchive(const EcReadArchive &);
Result<EcReadArchive> decodeReadArchive(std::string_view);
Result<std::string> encodeReadRetirementMarker(const EcReadRetirementMarker &);
Result<EcReadRetirementMarker> decodeReadRetirementMarker(std::string_view);
Result<storage::EcSha256> readArchiveDigest(std::string_view);
Result<EcReadArchive> loadReadArchive(const EcReadRetirementMarker &);
bool sameReadReceipt(const EcReadReceipt &, const EcReadReceipt &);
inline std::string readRetirementMarkerName(uint64_t sequence) { return fmt::format("retire-{:020}.json", sequence); }
}  // namespace hf3fs::client::ec::detail
