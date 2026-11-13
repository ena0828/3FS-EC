#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace hf3fs::test::ec_pending {
// Test-executable-only linker interception. No Engine handle or fd is retained.
struct Observation {
  uint64_t device = 0;
  uint64_t inode = 0;
  uint64_t offset = 0;
  uint64_t captures = 0;
  uint64_t failures = 0;
  uint64_t interceptionErrors = 0;
};
void captureNext(const std::filesystem::path &dataClassDirectory, std::string bytes);
void failNext(const Observation &firstBlock, uint64_t blockBytes, std::string bytes);
Observation observation();
void reset();
}  // namespace hf3fs::test::ec_pending
