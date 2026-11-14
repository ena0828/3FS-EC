#include <gtest/gtest.h>
#include <string_view>

#include "meta/base/Config.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta::server {
TEST(TestEcStorageTransportConfig, RejectsImplicitModesAndHotTransportChanges) {
  Config config;
  EXPECT_EQ(config.ec_storage_transport(), "tcp");
  ASSERT_OK(config.atomicallyUpdate(std::string_view{"ec_storage_transport = 'rdma'"}, false));
  EXPECT_EQ(config.ec_storage_transport(), "rdma");
  for (const auto value : {"auto", "RDMA", "", "tcp,rdma"}) {
    const auto text = std::string("ec_storage_transport = '") + value + "'";
    EXPECT_FALSE(config.atomicallyUpdate(std::string_view{text}, false));
    EXPECT_EQ(config.ec_storage_transport(), "rdma");
  }
  EXPECT_FALSE(config.atomicallyUpdate(std::string_view{"ec_storage_transport = 'tcp'"}, true));
  EXPECT_EQ(config.ec_storage_transport(), "rdma");
  ASSERT_OK(config.atomicallyUpdate(std::string_view{"ec_storage_transport = 'rdma'"}, true));
  ASSERT_OK(config.atomicallyUpdate(std::string_view{"ec_storage_transport = 'tcp'"}, false));
  EXPECT_EQ(config.ec_storage_transport(), "tcp");
}
}  // namespace hf3fs::meta::server
