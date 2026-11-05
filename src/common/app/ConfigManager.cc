#include "ConfigManager.h"

#include <new>

#include "common/utils/ConfigBase.h"
#include "common/utils/RenderConfig.h"
#include "common/utils/StringUtils.h"

namespace hf3fs::app {
namespace {
// ConfigBase accepts internal section aliases such as "groups#1". Such a
// section can be inactive and disappear from toToml(), so matching the final
// values alone is not enough. Require every supplied structured path to exist
// in the canonical effective representation after strict typed parsing.
Result<Void> canonicalConfigShape(const toml::node &supplied, const toml::node &canonical) {
  // Typed parsing can construct an integer from bool/float or narrow a large
  // integer. Such lossy aliases must not be acknowledged as unchanged values.
  if (supplied.type() != canonical.type()) return makeError(StatusCode::kConfigInvalidType);
  if (const auto *table = supplied.as_table()) {
    const auto *expected = canonical.as_table();
    if (!expected) return makeError(StatusCode::kConfigInvalidType);
    for (const auto &[key, value] : *table) {
      const auto *field = expected->get(key.str());
      if (!field) return makeError(StatusCode::kConfigRedundantKey, "noncanonical configuration section");
      RETURN_ON_ERROR(canonicalConfigShape(value, *field));
    }
  } else if (const auto *array = supplied.as_array()) {
    const auto *expected = canonical.as_array();
    if (!expected || array->size() != expected->size()) return makeError(StatusCode::kConfigInvalidType);
    for (size_t i = 0; i != array->size(); ++i) RETURN_ON_ERROR(canonicalConfigShape((*array)[i], (*expected)[i]));
  } else if (supplied.is_integer() && supplied.as_integer()->get() != canonical.as_integer()->get()) {
    return makeError(StatusCode::kConfigInvalidValue);
  } else if (supplied.is_floating_point() &&
             supplied.as_floating_point()->get() != canonical.as_floating_point()->get()) {
    return makeError(StatusCode::kConfigInvalidValue);
  } else if (supplied.is_boolean() && supplied.as_boolean()->get() != canonical.as_boolean()->get()) {
    return makeError(StatusCode::kConfigInvalidValue);
  }
  return Void{};
}
}  // namespace

Result<Void> ConfigManager::checkEquivalentConfig(const String &configContent,
                                                  const config::IConfig &cfg,
                                                  const flat::AppInfo *appInfo) const {
  try {
    auto rendered = hf3fs::renderConfig(configContent, appInfo);
    RETURN_ON_ERROR(rendered);
    const auto supplied = toml::parse(std::string_view(*rendered));
    auto expected = cfg.defaultPtr();
    // Partial updates on failure affect only this disposable object. Never
    // apply to cfg and roll back: callbacks could already have changed runtime.
    RETURN_ON_ERROR(expected->update(supplied, /*isHotUpdate=*/false));
    // Use the normal startup parser's validation. validate() additionally walks
    // inactive array capacity, whose default slots need not be runnable configs.
    const auto canonical = expected->toToml();
    RETURN_ON_ERROR(canonicalConfigShape(supplied, canonical));
    // Full typed TOML retains active CONFIG_OBJ_ARRAY lengths. diffWith() and
    // IConfig::operator== currently omit those separate length fields.
    if (cfg.toToml() != canonical)
      return makeError(StatusCode::kCannotPushConfig, "remote configuration differs from pinned local values");
    return Void{};
  } catch (const toml::parse_error &) {
    return makeError(StatusCode::kConfigParseError);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kConfigUpdateFailed);
  }
}

#define RETURN_AND_RECORD_CONFIG_UPDATE(ret, desc)                                        \
  Result<Void> _r = (ret);                                                                \
  updateConfigRecord(_r.hasError() ? _r.error() : Status(StatusCode::kOK), String(desc)); \
  return _r;

void ConfigManager::updateConfigRecord(Status status, String desc) {
  ConfigUpdateRecord rec;
  rec.updateTime = UtcClock::now();
  rec.result = std::move(status);
  rec.description = std::move(desc);
  lastConfigUpdateRecord = std::move(rec);
}

void ConfigManager::updateConfigContent(config::IConfig &cfg,
                                        const flat::AppInfo *appInfo,
                                        std::string_view configContent,
                                        bool checkDiff) {
  if (!configContent.empty()) {
    lastConfigContent = configContent;
  }
  auto oldConfigStatus = configStatus;
  SCOPE_EXIT {
    XLOGF_IF(INFO,
             configStatus != oldConfigStatus,
             "Update configStatus {} -> {}",
             toStringView(oldConfigStatus),
             toStringView(configStatus));
  };
  auto renderRes = hf3fs::renderConfig(lastConfigContent, appInfo);
  if (renderRes.hasError()) {
    configStatus = ConfigStatus::FAILED;
    return;
  }
  auto expected = cfg.defaultPtr();
  auto updateRes = expected->atomicallyUpdate(std::string_view(*renderRes), /*isHotUpdate=*/false);
  if (updateRes.hasError()) {
    configStatus = ConfigStatus::FAILED;
    return;
  }

  if (checkDiff) {
    config::IConfig::ItemDiff diffs[10];
    auto diffCnt = cfg.diffWith(*expected, std::span(diffs));
    if (diffCnt != 0) {
      String msg = "Config has diffs, display at most 10:";
      for (size_t i = 0; i < diffCnt; ++i) {
        msg += fmt::format("\n{}: actual {}. expected {}", diffs[i].key, diffs[i].left, diffs[i].right);
      }
      XLOG(WARN, msg);
      configStatus = ConfigStatus::DIRTY;
    } else {
      configStatus = ConfigStatus::NORMAL;
    }
  } else {
    configStatus = ConfigStatus::NORMAL;
  }
}

void ConfigManager::updateConfigStatus(config::IConfig &cfg, const flat::AppInfo *appInfo) {
  updateConfigContent(cfg, appInfo, {});
}

Result<Void> ConfigManager::updateConfig(const String &configContent,
                                         std::string_view configDesc,
                                         config::IConfig &cfg,
                                         const flat::AppInfo *appInfo,
                                         bool hotUpdate,
                                         bool checkDiff) {
  auto renderRes = hf3fs::renderConfig(configContent, appInfo);
  if (renderRes.hasError()) {
    XLOGF(ERR, "Update config failed at rendering: {}. desc: {}", renderRes.error(), configDesc);
    RETURN_AND_RECORD_CONFIG_UPDATE(makeError(renderRes.error()), configDesc);
  }
  auto updateRes = cfg.atomicallyUpdate(std::string_view(*renderRes), hotUpdate);
  if (updateRes.hasError()) {
    XLOGF(WARN, "Update config failed at updating: {}. desc: {}", updateRes.error(), configDesc);
    RETURN_AND_RECORD_CONFIG_UPDATE(makeError(updateRes.error()), configDesc);
  }
  XLOGF(INFO, "Update config succeeded. desc: {}\nFull Config:\n{}", configDesc, cfg.toString());
  updateConfigContent(cfg, appInfo, configContent, checkDiff);
  RETURN_AND_RECORD_CONFIG_UPDATE(Void{}, configDesc);
}

Result<Void> ConfigManager::hotUpdateConfig(const String &update,
                                            bool render,
                                            config::IConfig &cfg,
                                            const flat::AppInfo *appInfo) {
  String updateStr;
  if (render) {
    auto renderRes = hf3fs::renderConfig(update, appInfo);
    RETURN_ON_ERROR(renderRes);
    updateStr = *renderRes;
  } else {
    updateStr = update;
  }
  auto res = cfg.atomicallyUpdate(std::string_view{updateStr});
  if (res.hasError()) {
    XLOGF(WARN, "Hot update config failed: {}. Config content:\n{}", res.error(), update);
    RETURN_ERROR(res);
  }
  XLOGF(INFO, "Hot update config succeeded. Config content:\n{}", update);
  updateConfigStatus(cfg, appInfo);
  return Void{};
}
}  // namespace hf3fs::app
