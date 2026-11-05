#include <array>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

#include "fbs/storage/EcAuthorization.h"
#include "fbs/storage/EcGcControl.h"
#include "fbs/storage/EcScopeControl.h"
#include "storage/ec_repair/EcHelperAuthorization.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {

bool writeKey(const std::filesystem::path &path, char value) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << std::string(32, value);
  out.close();
  return bool(out) && ::chmod(path.c_str(), 0600) == 0;
}

EcKeyFileIdentity identityAt(const std::filesystem::path &path) {
  struct stat value {};
  if (::stat(path.c_str(), &value) != 0) throw std::runtime_error("test key stat failed");
  return {static_cast<uint64_t>(value.st_dev), static_cast<uint64_t>(value.st_ino)};
}

EcGcRoleFileIdentity gcRole(const EcKeyFileIdentity &identity) { return {identity.device, identity.inode}; }

TEST(TestEcKeyFileIdentity, RawMemoryKeyDoesNotInventFileIdentity) {
  std::array<uint8_t, 32> bytes{};
  bytes.fill(0x5a);
  const EcCapabilityKey key(bytes);
  EXPECT_FALSE(key.fileIdentity());
  static_assert(noexcept(key.fileIdentity()));
}

TEST(TestEcKeyFileIdentity, LoadedRolesExposeTheirActualFileIdentity) {
  folly::test::TemporaryDirectory directory;
  const auto root = std::filesystem::path(directory.path().string());
  const auto dataPath = root / "data.key";
  const auto controlPath = root / "control.key";
  const auto helperPath = root / "helper.key";
  ASSERT_TRUE(writeKey(dataPath, 'a'));
  ASSERT_TRUE(writeKey(controlPath, 'b'));
  ASSERT_TRUE(writeKey(helperPath, 'c'));
  auto data = EcCapabilityKey::loadFile(dataPath);
  auto control = EcScopeControlKey::loadFile(controlPath);
  auto helper = EcHelperKey::loadFile(helperPath);
  ASSERT_OK(data);
  ASSERT_OK(control);
  ASSERT_OK(helper);
  ASSERT_TRUE((*data)->fileIdentity());
  ASSERT_TRUE((*control)->fileIdentity());
  ASSERT_TRUE((*helper)->fileIdentity());
  EXPECT_EQ(*(*data)->fileIdentity(), identityAt(dataPath));
  EXPECT_EQ(*(*control)->fileIdentity(), identityAt(controlPath));
  EXPECT_EQ(*(*helper)->fileIdentity(), identityAt(helperPath));
  EXPECT_NE(*(*data)->fileIdentity(), *(*control)->fileIdentity());
  EXPECT_NE(*(*data)->fileIdentity(), *(*helper)->fileIdentity());
  EXPECT_NE(*(*control)->fileIdentity(), *(*helper)->fileIdentity());
}

TEST(TestEcKeyFileIdentity, SymlinksRejectAndHardlinksRetainTheSameIdentity) {
  folly::test::TemporaryDirectory directory;
  const auto root = std::filesystem::path(directory.path().string());
  const auto path = root / "data.key";
  const auto link = root / "hardlink.key";
  const auto symbolic = root / "symlink.key";
  ASSERT_TRUE(writeKey(path, 'd'));
  std::filesystem::create_hard_link(path, link);
  std::filesystem::create_symlink(path, symbolic);
  ASSERT_ERROR(EcCapabilityKey::loadFile(symbolic), StatusCode::kIOError);
  ASSERT_ERROR(EcScopeControlKey::loadFile(symbolic), StatusCode::kIOError);
  ASSERT_ERROR(EcHelperKey::loadFile(symbolic), StatusCode::kIOError);
  auto original = EcCapabilityKey::loadFile(path);
  auto alias = EcCapabilityKey::loadFile(link);
  ASSERT_OK(original);
  ASSERT_OK(alias);
  ASSERT_TRUE((*original)->fileIdentity());
  ASSERT_TRUE((*alias)->fileIdentity());
  EXPECT_EQ(*(*original)->fileIdentity(), *(*alias)->fileIdentity());
}

TEST(TestEcKeyFileIdentity, LoadedIdentityDoesNotFollowLaterPathReplacement) {
  folly::test::TemporaryDirectory directory;
  const auto root = std::filesystem::path(directory.path().string());
  const auto path = root / "role.key";
  ASSERT_TRUE(writeKey(path, 'a'));
  auto data = EcCapabilityKey::loadFile(path);
  auto control = EcScopeControlKey::loadFile(path);
  auto helper = EcHelperKey::loadFile(path);
  ASSERT_OK(data);
  ASSERT_OK(control);
  ASSERT_OK(helper);
  ASSERT_TRUE((*data)->fileIdentity());
  ASSERT_TRUE((*control)->fileIdentity());
  ASSERT_TRUE((*helper)->fileIdentity());
  const auto original = *(*data)->fileIdentity();
  // Deterministic ordering: old role load -> atomic pathname replacement ->
  // later role load. This is not a timing-dependent race or loader fault hook.
  std::filesystem::rename(path, root / "retained-original.key");
  ASSERT_TRUE(writeKey(path, 'z'));
  const auto replacement = identityAt(path);
  ASSERT_NE(original, replacement);
  EXPECT_EQ(*(*data)->fileIdentity(), original);
  EXPECT_EQ(*(*control)->fileIdentity(), original);
  EXPECT_EQ(*(*helper)->fileIdentity(), original);
  auto reloaded = EcCapabilityKey::loadFile(path);
  ASSERT_OK(reloaded);
  ASSERT_TRUE((*reloaded)->fileIdentity());
  EXPECT_EQ(*(*reloaded)->fileIdentity(), replacement);
}

TEST(TestEcKeyFileIdentity, GcRejectsEveryLoadedRoleAliasDespitePathReplacement) {
  folly::test::TemporaryDirectory directory;
  const auto root = std::filesystem::path(directory.path().string());
  const std::array<std::filesystem::path, 3> paths{root / "data.key", root / "control.key", root / "helper.key"};
  for (size_t i = 0; i < paths.size(); ++i) ASSERT_TRUE(writeKey(paths[i], char('a' + i)));
  auto data = EcCapabilityKey::loadFile(paths[0]);
  auto control = EcScopeControlKey::loadFile(paths[1]);
  auto helper = EcHelperKey::loadFile(paths[2]);
  ASSERT_OK(data);
  ASSERT_OK(control);
  ASSERT_OK(helper);
  ASSERT_TRUE((*data)->fileIdentity());
  ASSERT_TRUE((*control)->fileIdentity());
  ASSERT_TRUE((*helper)->fileIdentity());
  const std::array<EcGcRoleFileIdentity, 3> loaded{gcRole(*(*data)->fileIdentity()),
                                                   gcRole(*(*control)->fileIdentity()),
                                                   gcRole(*(*helper)->fileIdentity())};
  for (size_t i = 0; i < paths.size(); ++i) {
    const auto alias = root / ("gc-alias-" + std::to_string(i));
    std::filesystem::create_hard_link(paths[i], alias);
    std::filesystem::rename(paths[i], root / ("retained-" + std::to_string(i)));
    ASSERT_TRUE(writeKey(paths[i], 'z'));
    ASSERT_NE(gcRole(identityAt(paths[i])), loaded[i]);
    ASSERT_EQ(gcRole(identityAt(alias)), loaded[i]);
    ASSERT_ERROR(EcGcKey::loadFile(alias, Uuid::random(), loaded), StatusCode::kInvalidConfig);
  }
}

TEST(TestEcKeyFileIdentity, DistinctInodesWithCopiedSecretRemainOutsideIdentityDetection) {
  folly::test::TemporaryDirectory directory;
  const auto root = std::filesystem::path(directory.path().string());
  const auto dataPath = root / "data.key";
  const auto gcPath = root / "gc.key";
  ASSERT_TRUE(writeKey(dataPath, 'x'));
  ASSERT_TRUE(writeKey(gcPath, 'x'));
  auto data = EcCapabilityKey::loadFile(dataPath);
  ASSERT_OK(data);
  ASSERT_TRUE((*data)->fileIdentity());
  const std::array<EcGcRoleFileIdentity, 1> loaded{gcRole(*(*data)->fileIdentity())};
  ASSERT_NE(loaded[0], gcRole(identityAt(gcPath)));
  // File identity detects reuse/aliases of one opened file, not equality of
  // secrets copied into distinct files. Provisioning must supply distinct keys.
  ASSERT_OK(EcGcKey::loadFile(gcPath, Uuid::random(), loaded));
}

}  // namespace
}  // namespace hf3fs::storage
