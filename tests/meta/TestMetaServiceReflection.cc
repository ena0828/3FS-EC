#include <array>
#include <string_view>
#include <tuple>
#include <type_traits>

#include "common/serde/Service.h"
#include "fbs/meta/Service.h"
#include "meta/service/MetaSerdeService.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta {
namespace {
using VoidMethods = refl::Helper::FieldInfoList<MetaSerde<>>;
using BoundMethods = refl::Helper::FieldInfoList<MetaSerde<server::MetaSerdeService>>;
using WrappedMethods = refl::Helper::FieldInfoList<server::MetaSerdeService>;
static_assert(std::tuple_size_v<VoidMethods> == 76);
static_assert(std::tuple_size_v<BoundMethods> == 76);
static_assert(std::is_same_v<BoundMethods, WrappedMethods>);
static_assert(serde::MaxMethodId<VoidMethods> == 76);
static_assert(MetaSerde<>::testRpcMethodId == 50);
static_assert(MetaSerde<>::bindEcRmwOutputMethodId == 52);
static_assert(MetaSerde<>::closeEcFileRepairDebtMethodId == 67);
static_assert(MetaSerde<>::prepareEcTargetRetirementMethodId == 68);
static_assert(MetaSerde<>::queryEcTargetRetirementMethodId == 69);
static_assert(MetaSerde<>::prepareEcFileRepairDirectMethodId == 70);
static_assert(MetaSerde<>::prepareEcRepairDirectV2MethodId == 71);

static_assert(MetaSerde<>::queryEcFileOutputMethodId == 72);
static_assert(MetaSerde<>::confirmEcFileOutputResolutionMethodId == 73);
static_assert(MetaSerde<>::queryEcFileOutputResolutionMethodId == 74);
static_assert(MetaSerde<>::confirmEcFragmentAbsentMethodId == 75);
static_assert(MetaSerde<>::queryEcFragmentAbsentMethodId == 76);

// Expected wire mapping, preserving IDs 1..74 independently of declaration order.
constexpr std::array<std::string_view, 76> kNamesByWireId{
    "statFs",                       // 1
    "stat",                         // 2
    "create",                       // 3
    "mkdirs",                       // 4
    "symlink",                      // 5
    "hardLink",                     // 6
    "remove",                       // 7
    "open",                         // 8
    "sync",                         // 9
    "close",                        // 10
    "rename",                       // 11
    "list",                         // 12
    "truncate",                     // 13
    "getRealPath",                  // 14
    "setAttr",                      // 15
    "pruneSession",                 // 16
    "dropUserCache",                // 17
    "authenticate",                 // 18
    "lockDirectory",                // 19
    "batchStat",                    // 20
    "batchStatByPath",              // 21
    "createEcFile",                 // 22
    "beginEcMutation",              // 23
    "publishEcMutation",            // 24
    "getEcOperation",               // 25
    "cancelEcMutation",             // 26
    "acquireEcRead",                // 27
    "releaseEcRead",                // 28
    "createEcFileV2",               // 29
    "beginEcMutationV2",            // 30
    "bindEcMutationV2",             // 31
    "publishEcMutationV2",          // 32
    "getEcOperationV2",             // 33
    "cancelEcMutationV2",           // 34
    "acquireEcReadV2",              // 35
    "releaseEcReadV2",              // 36
    "prepareEcRepairV2",            // 37
    "collectEcFragmentV2",          // 38
    "queryEcFragmentGcV2",          // 39
    "retireEcRevisionV2",           // 40
    "queryEcRevisionRetirementV2",  // 41
    "describeEcFileV2",             // 42
    "acquireEcRangeV2",             // 43
    "queryEcRangeV2",               // 44
    "queryEcOwnedMutationV2",       // 45
    "openEcFileSession",            // 46
    "beginEcFilePwrite",            // 47
    "queryEcFilePwrite",            // 48
    "advanceEcFilePwrite",          // 49
    "testRpc",                      // 50
    "closeEcFileSession",           // 51
    "bindEcRmwOutput",              // 52
    "acquireEcTreeRead",            // 53
    "queryEcTreeRead",              // 54
    "releaseEcTreeRead",            // 55
    "beginEcFileTruncate",          // 56
    "queryEcFileTruncate",          // 57
    "advanceEcFileTruncate",        // 58
    "closeEcFileTruncateDebt",      // 59
    "advanceEcTreeReclaim",         // 60
    "beginEcFileAppend",            // 61
    "queryEcFileAppend",            // 62
    "syncEcFileSession",            // 63
    "beginEcFileRepair",            // 64
    "queryEcFileRepair",            // 65
    "advanceEcFileRepair",          // 66
    "closeEcFileRepairDebt",        // 67
    "prepareEcTargetRetirement",    // 68
    "queryEcTargetRetirement",      // 69
    "prepareEcFileRepairDirect",     // 70
    "prepareEcRepairDirectV2",        // 71
    "queryEcFileOutput",             // 72
    "confirmEcFileOutputResolution", // 73
    "queryEcFileOutputResolution",   // 74
    "confirmEcFragmentAbsent",       // 75
    "queryEcFragmentAbsent",         // 76
};
template <class... M>
consteval bool exactWireMap(std::tuple<M...> *) {
  std::array<bool, 77> seen{};
  bool valid = true;
  const auto add = [&](uint16_t id, std::string_view name) {
    if (id == 0 || id >= seen.size() || seen[id]) {
      valid = false;
      return;
    }
    seen[id] = true;
    valid = valid && kNamesByWireId[id - 1] == name;
  };
  (add(M::id, M::name), ...);
  for (size_t id = 1; id < seen.size(); ++id) valid = valid && seen[id];
  return valid;
}
template <class... M>
consteval bool unbound(std::tuple<M...> *) {
  return ((M::method == nullptr) && ...);
}
template <class... M>
consteval bool bound(std::tuple<M...> *) {
  return ((std::is_same_v<typename M::Object, server::MetaSerdeService> && M::method != nullptr) && ...);
}
static_assert(exactWireMap(static_cast<VoidMethods *>(nullptr)));
static_assert(exactWireMap(static_cast<BoundMethods *>(nullptr)));
static_assert(unbound(static_cast<VoidMethods *>(nullptr)));
static_assert(bound(static_cast<BoundMethods *>(nullptr)));

struct DispatchProbe {
  template <class Info>
  static uint16_t call() {
    return Info::id;
  }
};
TEST(TestMetaServiceReflection, RegistersAll76IncludingBeyondDefaultFieldRank) {
  // Instantiate the same ID extraction used by real service dispatch, rather
  // than only counting sender constants or source declaration lines.
  using Extractor = serde::MethodExtractor<server::MetaSerdeService, DispatchProbe>;
  for (uint16_t id = 1; id <= 76; ++id) {
    const auto method = Extractor::get(id);
    ASSERT_NE(method, nullptr) << id;
    EXPECT_EQ(method(), id);
  }
  EXPECT_EQ(Extractor::get(0), nullptr);
  EXPECT_EQ(Extractor::get(77), nullptr);
  EXPECT_EQ(Extractor::get(65535), nullptr);
  EXPECT_EQ(MetaSerde<>::getRpcName(TestRpcReq{}), "testRpc");
  EXPECT_EQ(MetaSerde<>::getRpcName(BindEcRmwOutputReq{}), "bindEcRmwOutput");
  EXPECT_EQ(MetaSerde<>::getRpcName(CloseEcFileRepairDebtReq{}), "closeEcFileRepairDebt");
  EXPECT_EQ(MetaSerde<>::getRpcName(PrepareEcTargetRetirementReq{}), "prepareEcTargetRetirement");
  EXPECT_EQ(MetaSerde<>::getRpcName(QueryEcTargetRetirementReq{}), "queryEcTargetRetirement");
  EXPECT_EQ(MetaSerde<>::getRpcName(PrepareEcFileRepairDirectReq{}), "prepareEcFileRepairDirect");
  EXPECT_EQ(MetaSerde<>::getRpcName(PrepareEcRepairDirectV2Req{}), "prepareEcRepairDirectV2");
  EXPECT_EQ(MetaSerde<>::getRpcName(QueryEcFileOutputReq{}), "queryEcFileOutput");
  EXPECT_EQ(MetaSerde<>::getRpcName(ConfirmEcFileOutputResolutionReq{}), "confirmEcFileOutputResolution");
  EXPECT_EQ(MetaSerde<>::getRpcName(QueryEcFileOutputResolutionReq{}), "queryEcFileOutputResolution");
  EXPECT_EQ(MetaSerde<>::getRpcName(ConfirmEcFragmentAbsentReq{}), "confirmEcFragmentAbsent");
  EXPECT_EQ(MetaSerde<>::getRpcName(QueryEcFragmentAbsentReq{}), "queryEcFragmentAbsent");
}
}  // namespace
}  // namespace hf3fs::meta
