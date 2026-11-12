#pragma once

#include "EcRmwComputation.h"

namespace hf3fs::storage {
inline constexpr size_t kEcRmwPlanWireBytes = 11469;
inline constexpr size_t kEcRmwGrantWireBytes = 164;
inline constexpr size_t kEcRmwComputedWireBytes = 8520;
struct EcRmwPlanWire {
  EcRmwPlanInput input;
};
class EcRmwWireCodec final {
 public:
  static std::string encode(const EcRmwPlanWire &);
  static std::string encode(const EcRmwGrant &);
  static std::string encode(const EcRmwComputedCommitment &);
  static Result<EcRmwPlanWire> plan(std::string_view);
  static Result<EcRmwGrant> grant(std::string_view);
  static Result<EcRmwComputedCommitment> computed(std::string_view);
};
}  // namespace hf3fs::storage
// Parse the borrowed fixed-sized field before constructing/copying an owning
// plan/credential. Every bearer/internal source record is binary-only.
#define EC_RMW_WIRE(Type, Parser)                                                      \
  template <>                                                                          \
  struct hf3fs::serde::SerdeMethod<hf3fs::storage::Type> {                             \
    static void serialize(const storage::Type &v, auto &out) {                         \
      if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) \
        serde::serialize(storage::EcRmwWireCodec::encode(v), out);                     \
      else                                                                             \
        serde::serialize(std::string_view("EC RMW internal (redacted)"), out);         \
    }                                                                                  \
    static Result<Void> deserialize(storage::Type &v, auto &in) {                      \
      if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; })  \
        return makeError(StatusCode::kInvalidFormat, "RMW requires binary Serde");     \
      else {                                                                           \
        std::string_view bytes;                                                        \
        RETURN_ON_ERROR(serde::deserialize(bytes, in));                                \
        CHECK_RESULT(decoded, storage::EcRmwWireCodec::Parser(bytes));                 \
        v = std::move(decoded);                                                        \
        return Void{};                                                                 \
      }                                                                                \
    }                                                                                  \
  };
EC_RMW_WIRE(EcRmwPlanWire, plan)
EC_RMW_WIRE(EcRmwGrant, grant)
EC_RMW_WIRE(EcRmwComputedCommitment, computed)
#undef EC_RMW_WIRE
