#include <array>
#include <cerrno>
#include <gtest/gtest.h>

#include "common/net/ib/IBDeviceList.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::net::detail {
namespace {

class TestIBDeviceList : public ::testing::Test {
 protected:
  void SetUp() override {
    devices_.fill(nullptr);
    count_ = 0;
    error_ = 0;
    returnNull_ = false;
    freeCalls_ = 0;
  }

  static ibv_device **get(int *count) {
    *count = count_;
    errno = error_;
    return returnNull_ ? nullptr : devices_.data();
  }

  static void free(ibv_device **devices) {
    EXPECT_EQ(devices, devices_.data());
    ++freeCalls_;
    errno = EIO;
  }

  static inline thread_local std::array<ibv_device *, 2> devices_{};
  static inline thread_local int count_ = 0;
  static inline thread_local int error_ = 0;
  static inline thread_local bool returnNull_ = false;
  static inline thread_local int freeCalls_ = 0;
};

TEST_F(TestIBDeviceList, MissingKernelSupportRequiresExplicitOptIn) {
  returnNull_ = true;
  error_ = ENOSYS;
  ASSERT_ERROR(loadIBDeviceList(false, get, free), RPCCode::kIBInitFailed);
  auto allowed = loadIBDeviceList(true, get, free);
  ASSERT_OK(allowed);
  EXPECT_EQ(allowed->count, 0);
  EXPECT_EQ(allowed->devices.get(), nullptr);
  EXPECT_EQ(freeCalls_, 0);
}

TEST_F(TestIBDeviceList, OtherEnumerationErrorsNeverDowngrade) {
  returnNull_ = true;
  for (const int error : {EPERM, ENOMEM, EIO, 0}) {
    error_ = error;
    SCOPED_TRACE(error);
    ASSERT_ERROR(loadIBDeviceList(false, get, free), RPCCode::kIBInitFailed);
    ASSERT_ERROR(loadIBDeviceList(true, get, free), RPCCode::kIBInitFailed);
  }
  EXPECT_EQ(freeCalls_, 0);
}

TEST_F(TestIBDeviceList, EmptyListRequiresExplicitOptInAndIsFreedOnce) {
  // errno is unspecified on success and must not turn an empty list into an error.
  error_ = EPERM;
  ASSERT_ERROR(loadIBDeviceList(false, get, free), RPCCode::kIBInitFailed);
  EXPECT_EQ(freeCalls_, 1);
  {
    auto allowed = loadIBDeviceList(true, get, free);
    ASSERT_OK(allowed);
    EXPECT_EQ(allowed->count, 0);
    EXPECT_EQ(allowed->devices.get(), devices_.data());
    EXPECT_EQ(freeCalls_, 1);
  }
  EXPECT_EQ(freeCalls_, 2);
}

TEST_F(TestIBDeviceList, InvalidCountIsRejectedAndFreed) {
  count_ = -1;
  ASSERT_ERROR(loadIBDeviceList(false, get, free), RPCCode::kIBInitFailed);
  ASSERT_ERROR(loadIBDeviceList(true, get, free), RPCCode::kIBInitFailed);
  EXPECT_EQ(freeCalls_, 2);
}

TEST_F(TestIBDeviceList, NonemptyListPreservesOwnershipUntilDevicesAreOpened) {
  ibv_device device{};
  devices_[0] = &device;
  count_ = 1;
  error_ = ENOSYS;
  for (const bool allow : {false, true}) {
    const int before = freeCalls_;
    {
      auto loaded = loadIBDeviceList(allow, get, free);
      ASSERT_OK(loaded);
      EXPECT_EQ(loaded->count, 1);
      EXPECT_EQ(loaded->devices.get()[0], &device);
      EXPECT_EQ(freeCalls_, before);
    }
    EXPECT_EQ(freeCalls_, before + 1);
  }
}

}  // namespace
}  // namespace hf3fs::net::detail
