#pragma once
#include "EcFileClient.h"
namespace hf3fs::client::ec {
// Only for a new run, after authenticated Describe. These factories allocate
// identities but perform no RPC; caller must create/fsync the journal first.
Result<EcFileRunRecord> prepareEcFileRead(const meta::EcFileState &,
                                          const meta::EcOwner &,
                                          std::string cluster,
                                          uint64_t offset,
                                          uint64_t length,
                                          Uuid describeRequest);
Result<EcFileRunRecord> prepareEcFileAppend(const meta::EcFileState &,
                                            const meta::EcOwner &,
                                            std::string cluster,
                                            uint64_t expectedEOF,
                                            std::string inputPath,
                                            std::span<const uint8_t> input,
                                            Uuid describeRequest);
Result<EcFilePayload> readEcFileInput(EcFileClient &, const std::filesystem::path &);
Result<Void> saveEcFileReadOutput(const std::filesystem::path &, std::span<const uint8_t>);
}  // namespace hf3fs::client::ec
