#include <array>

#include "common/app/AppInfo.h"
#include "common/app/ConfigManager.h"
#include "common/utils/ConfigBase.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::test {
namespace {
struct PinnedEntry : ConfigBase<PinnedEntry> {
  CONFIG_ITEM(value, 7);
};
struct PinnedConfig : ConfigBase<PinnedConfig> {
  CONFIG_ITEM(fixed, 7);
  CONFIG_HOT_UPDATED_ITEM(hot, 11, ConfigCheckers::checkPositive);
  CONFIG_ITEM(label, "same");
  CONFIG_OBJ_ARRAY(groups, PinnedEntry, 4);
};

TEST(ConfigManagerPinned, CanonicalEquivalentAcknowledgesWithoutMutatingOrCallingCallbacks) {
  PinnedConfig cfg;
  app::ConfigManager manager;
  manager.lastConfigContent = "local source remains authoritative";
  size_t callbacks = 0;
  auto outer = cfg.addCallbackGuard([&] { ++callbacks; });
  auto nested = cfg.groups(0).addCallbackGuard([&] { ++callbacks; });
  const auto before = cfg.toString();
  flat::AppInfo info;
  info.nodeId = flat::NodeId(7);
  const String supplied = R"(
    # Formatting, ordering and equivalent quoting are not runtime changes.
    label = 'same'
    hot = 11
    fixed = 7
    [[groups]]
    value = 7
  )";
  ASSERT_OK(manager.checkEquivalentConfig(supplied, cfg, &info));
  ASSERT_OK(manager.checkEquivalentConfig(cfg.toString(), cfg, &info));
  ASSERT_OK(manager.checkEquivalentConfig("", cfg, nullptr));
  ASSERT_EQ(cfg.toString(), before);
  ASSERT_EQ(callbacks, 0);
  ASSERT_EQ(manager.lastConfigContent, "local source remains authoritative");
  ASSERT_FALSE(manager.lastConfigUpdateRecord);
  ASSERT_EQ(manager.configStatus, ConfigStatus::NORMAL);
}

TEST(ConfigManagerPinned, DifferentFixedAndHotValuesAreRejectedWithoutApplyingThem) {
  PinnedConfig cfg;
  app::ConfigManager manager;
  size_t callbacks = 0;
  auto guard = cfg.addCallbackGuard([&] { ++callbacks; });
  const auto before = cfg.toString();
  ASSERT_ERROR(manager.checkEquivalentConfig("fixed = 8", cfg, nullptr), StatusCode::kCannotPushConfig);
  ASSERT_ERROR(manager.checkEquivalentConfig("hot = 12", cfg, nullptr), StatusCode::kCannotPushConfig);
  ASSERT_ERROR(manager.checkEquivalentConfig("label = 'different'", cfg, nullptr), StatusCode::kCannotPushConfig);
  ASSERT_EQ(cfg.toString(), before);
  ASSERT_EQ(callbacks, 0);
  ASSERT_FALSE(manager.lastConfigUpdateRecord);
  // A remote omission means its default, not the local command-line override.
  ASSERT_TRUE(cfg.set_fixed(99));
  const auto overridden = cfg.toString();
  ASSERT_ERROR(manager.checkEquivalentConfig("", cfg, nullptr), StatusCode::kCannotPushConfig);
  ASSERT_EQ(cfg.toString(), overridden);
  ASSERT_EQ(callbacks, 0);
}

TEST(ConfigManagerPinned, ArrayLengthAloneCannotBeAcknowledgedThroughLegacyDiffEquality) {
  PinnedConfig cfg;
  PinnedConfig changed;
  changed.set_groups_length(2);
  config::IConfig::ItemDiff diffs[1];
  ASSERT_EQ(cfg.diffWith(changed, std::span(diffs)), 0);
  ASSERT_NE(cfg.toToml(), changed.toToml());
  size_t callbacks = 0;
  auto guard = cfg.addCallbackGuard([&] { ++callbacks; });
  const auto before = cfg.toString();
  app::ConfigManager manager;
  ASSERT_ERROR(manager.checkEquivalentConfig(changed.toString(), cfg, nullptr), StatusCode::kCannotPushConfig);
  ASSERT_ERROR(manager.checkEquivalentConfig("groups = []", cfg, nullptr), StatusCode::kCannotPushConfig);
  ASSERT_EQ(cfg.toString(), before);
  ASSERT_EQ(cfg.groups_length(), 1);
  ASSERT_EQ(callbacks, 0);
}

TEST(ConfigManagerPinned, MalformedUnknownAndInternalAliasFieldsCannotBecomeAnAcknowledgement) {
  PinnedConfig cfg;
  app::ConfigManager manager;
  size_t callbacks = 0;
  auto outer = cfg.addCallbackGuard([&] { ++callbacks; });
  auto nested = cfg.groups(0).addCallbackGuard([&] { ++callbacks; });
  const auto before = cfg.toString();
  const std::array<String, 12> invalid = {"fixed = [",
                                          "unknown = 7",
                                          "fixed = 'seven'",
                                          "hot = 0",
                                          "fixed = {{ broken",
                                          "fixed = {{ app.nodeId }}",
                                          "[[groups]]\nstray = 7",
                                          "['groups#0']\nvalue = 7",
                                          "['groups#1']\nvalue = 99",
                                          "fixed = true",
                                          "fixed = 7.9",
                                          "fixed = 4294967303"};
  for (const auto &input : invalid) {
    SCOPED_TRACE(input);
    ASSERT_FALSE(manager.checkEquivalentConfig(input, cfg, nullptr));
    ASSERT_EQ(cfg.toString(), before);
    ASSERT_EQ(callbacks, 0);
    ASSERT_FALSE(manager.lastConfigUpdateRecord);
  }
}
}  // namespace
}  // namespace hf3fs::test
