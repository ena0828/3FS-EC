#include <gtest/gtest.h>
#include <string_view>

#include "fuse/FuseConfig.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::fuse {
TEST(TestEcFuseTransportConfig, ExplicitPolicyCannotChangeDuringAMount) {
  FuseConfig config;
  EXPECT_EQ(config.ec_storage_transport(), "tcp");
  EXPECT_TRUE(config.ec_read_quorum_first());
  ASSERT_OK(config.atomicallyUpdate(std::string_view{"ec_read_quorum_first = false"}, false));
  EXPECT_FALSE(config.ec_read_quorum_first());
  EXPECT_FALSE(config.atomicallyUpdate(std::string_view{"ec_read_quorum_first = true"}, true));
  EXPECT_FALSE(config.ec_read_quorum_first());
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
}  // namespace hf3fs::fuse
