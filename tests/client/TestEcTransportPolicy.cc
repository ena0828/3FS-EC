#include <chrono>
#include <cstdint>
#include <folly/experimental/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "client/storage/EcRequestControl.h"
#include "client/storage/StorageClientImpl.h"
#include "common/net/Client.h"
#include "common/net/RequestOptions.h"
#include "common/net/sync/ConnectionPool.h"
#include "common/serde/ClientContext.h"
#include "common/serde/RpcCallSizes.h"
#include "common/serde/Serde.h"
#include "fbs/mgmtd/NodeInfo.h"
#include "tests/FakeMgmtdClient.h"

namespace hf3fs::storage::client::test {
namespace {
using Policy = EcRequestControl::TransportPolicy;
using folly::coro::blockingWait;

void group(flat::NodeInfo &node, const char *service, std::initializer_list<net::Address> addresses) {
  flat::ServiceGroupInfo entry;
  entry.services.insert(service);
  entry.endpoints.assign(addresses.begin(), addresses.end());
  node.app.serviceGroups.push_back(std::move(entry));
}

net::Address address(uint16_t port, net::Address::Type type) {
  return net::Address{0x0100007f, port, type};
}

// The original independent five-field wire projection, deliberately without
// the new local transport requirement.
struct LegacyUserRequestOptions {
  SERDE_STRUCT_FIELD(timeout, std::optional<Duration>{});
  SERDE_STRUCT_FIELD(sendRetryTimes, std::optional<uint32_t>{});
  SERDE_STRUCT_FIELD(compression, std::optional<net::CompressionOptions>{});
  SERDE_STRUCT_FIELD(logLongRunningThreshold, std::optional<Duration>{});
  SERDE_STRUCT_FIELD(reportMetrics, std::optional<bool>{});
};

static_assert(serde::count<net::UserRequestOptions>() == 5);

TEST(TestEcTransportPolicy, ActualContextRejectsForcedTcpAndNullTransportBeforeEncoding) {
  net::Client::Config config;
  config.set_force_use_tcp(true);
  net::Client client(config);
  auto context = client.serdeCtx(address(9500, net::Address::RDMA));
  ASSERT_TRUE(context.addr().isTCP());
  net::UserRequestOptions options;
  options.requireRdma = true;
  serde::RpcCallSizes sizes{{123, true, true}, {456, true, true}};
  auto rejected = blockingWait(context.call<"EcPolicy", "guard", uint32_t, uint32_t, 88, 1>(
      7, &options, nullptr, &sizes));
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error().code(), StatusCode::kInvalidArg);
  EXPECT_FALSE(sizes.request.available);
  EXPECT_FALSE(sizes.response.available);
  EXPECT_EQ(sizes.request.bytes, 0);
  EXPECT_EQ(sizes.response.bytes, 0);

  // No start/socket/verbs device is needed. In the TransportPtr constructor
  // destAddr_ is not the source of truth, and null must fail without dereference.
  net::TransportPtr absent;
  serde::ClientContext nullContext(absent);
  auto nullRejected = blockingWait(nullContext.call<"EcPolicy", "guard", uint32_t, uint32_t, 88, 1>(
      7, &options));
  ASSERT_FALSE(nullRejected);
  EXPECT_EQ(nullRejected.error().code(), StatusCode::kInvalidArg);
}

TEST(TestEcTransportPolicy, SynchronousPoolCannotSatisfyRdmaEvenWithRdmaAddress) {
  net::sync::ConnectionPool::Config config;
  net::sync::ConnectionPool pool(config);
  folly::atomic_shared_ptr<const net::CoreRequestOptions> defaults{
      std::make_shared<net::CoreRequestOptions>()};
  serde::ClientContext context(pool, address(9500, net::Address::RDMA), defaults);
  net::UserRequestOptions options;
  options.requireRdma = true;
  // The real pool only creates TcpSocket: an address tag is not RDMA evidence.
  auto rejected = context.callSync<"EcPolicy", "guard", uint32_t, uint32_t, 88, 1>(7, &options);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error().code(), StatusCode::kInvalidArg);
  auto asyncRejected = blockingWait(context.call<"EcPolicy", "guard", uint32_t, uint32_t, 88, 1>(
      7, &options));
  ASSERT_FALSE(asyncRejected);
  EXPECT_EQ(asyncRejected.error().code(), StatusCode::kInvalidArg);
}

TEST(TestEcTransportPolicy, LocalRdmaRequirementPreservesOriginalFiveFieldWireAndCoreOptions) {
  net::UserRequestOptions current;
  LegacyUserRequestOptions legacy;
  current.timeout = legacy.timeout = 37_ms;
  current.sendRetryTimes = legacy.sendRetryTimes = 3u;
  current.compression = legacy.compression = net::CompressionOptions{2u, 123_B};
  current.logLongRunningThreshold = legacy.logLongRunningThreshold = 11_ms;
  current.reportMetrics = legacy.reportMetrics = true;
  const auto original = serde::serialize(legacy);
  const auto withoutRequirement = serde::serialize(current);
  EXPECT_EQ(std::string_view(withoutRequirement), std::string_view(original));
  current.requireRdma = true;
  const auto withRequirement = serde::serialize(current);
  EXPECT_EQ(std::string_view(withRequirement), std::string_view(original));

  net::UserRequestOptions decoded;
  ASSERT_TRUE(serde::deserialize(decoded, withRequirement));
  EXPECT_FALSE(decoded.requireRdma);
  net::CoreRequestOptions coreWithout, coreWith;
  current.requireRdma = false;
  coreWithout.merge(current);
  current.requireRdma = true;
  coreWith.merge(current);
  const auto before = serde::serialize(coreWithout);
  const auto after = serde::serialize(coreWith);
  EXPECT_EQ(std::string_view(before), std::string_view(after));
}

TEST(TestEcTransportPolicy, UnstartedStorageClientConstructsAndDestroys) {
  // A separate GTest RUN/OK boundary identifies constructor/destructor failure
  // without needing XML that a process crash cannot finish writing.
  StorageClient::Config config;
  hf3fs::tests::FakeMgmtdClient mgmtd;
  {
    // Two messengers embed large Services tables. Match the production
    // factory's heap allocation; no test body should place those on its stack.
    auto client = std::make_unique<StorageClientImpl>(ClientId{Uuid::zero(), "transport-policy-test"}, config, mgmtd);
    // Deliberately do not start the client or contact a service.
  }
  SUCCEED();
}

TEST(TestEcTransportPolicy, RejectsImplicitAndInvalidPoliciesBeforeControlledDataDispatch) {
  EXPECT_EQ(EcRequestControl{}.transport, Policy::TcpOnly);
  EXPECT_TRUE(isExplicitEcTransportPolicy(Policy::TcpOnly));
  EXPECT_TRUE(isExplicitEcTransportPolicy(Policy::RdmaOnly));
  StorageClient::Config config;
  hf3fs::tests::FakeMgmtdClient mgmtd;
  auto client = std::make_unique<StorageClientImpl>(ClientId{Uuid::zero(), "transport-policy-test"}, config, mgmtd);
  // No start(), socket or IB device: these public methods must reject the
  // policy before trying routing, grants or a network ClientContext.
  for (const auto policy : {Policy::Automatic, static_cast<Policy>(255)}) {
    ASSERT_FALSE(isExplicitEcTransportPolicy(policy));
    EcRequestControl control{std::chrono::steady_clock::now() + std::chrono::seconds(30), {}, policy};
    const auto rejected = [](auto outcome) {
      ASSERT_FALSE(outcome);
      EXPECT_EQ(outcome.error().code(), StatusCode::kNotImplemented);
    };
    rejected(blockingWait(client->authorizedReadEcFragmentControlled({}, control)));
    rejected(blockingWait(client->readEcBlockV2Controlled({}, control)));
    rejected(blockingWait(client->beginEcStageV2Controlled({}, control)));
    rejected(blockingWait(client->appendEcStageV2Controlled({}, control)));
    rejected(blockingWait(client->queryEcStageV2Controlled({}, control)));
    rejected(blockingWait(client->reconcileEcStageV2Controlled({}, control)));
    rejected(blockingWait(client->sealEcStageV2Controlled({}, control)));
  }
}

TEST(TestEcTransportPolicy, ExplicitTcpPolicyOnUnstartedClientReturnsNotInitialized) {
  StorageClient::Config config;
  hf3fs::tests::FakeMgmtdClient mgmtd;
  auto client = std::make_unique<StorageClientImpl>(ClientId{Uuid::zero(), "transport-policy-test"}, config, mgmtd);
  EcRequestControl control{std::chrono::steady_clock::now() + std::chrono::seconds(30), {}, Policy::TcpOnly};
  auto acceptedPolicy = blockingWait(client->readEcBlockV2Controlled({}, control));
  ASSERT_FALSE(acceptedPolicy);
  EXPECT_EQ(acceptedPolicy.error().code(), StorageClientCode::kNotInitialized);
}

TEST(TestEcTransportPolicy, ExplicitRdmaPolicyOnUnstartedClientReturnsNotInitialized) {
  StorageClient::Config config;
  hf3fs::tests::FakeMgmtdClient mgmtd;
  auto client = std::make_unique<StorageClientImpl>(ClientId{Uuid::zero(), "transport-policy-test"}, config, mgmtd);
  EcRequestControl control{std::chrono::steady_clock::now() + std::chrono::seconds(30), {}, Policy::RdmaOnly};
  auto acceptedPolicy = blockingWait(client->readEcBlockV2Controlled({}, control));
  ASSERT_FALSE(acceptedPolicy);
  EXPECT_EQ(acceptedPolicy.error().code(), StorageClientCode::kNotInitialized);
}

TEST(TestEcTransportPolicy, ExplicitRoutesFilterServiceAndNeverFallBack) {
  flat::NodeInfo node;
  group(node, "UnrelatedService", {address(9100, net::Address::RDMA), address(9101, net::Address::TCP)});
  group(node, "StorageSerde", {address(9200, net::Address::TCP)});
  group(node, "StorageSerde", {address(9300, net::Address::RDMA), address(9301, net::Address::TCP)});
  // These are the same selector and flag combinations used by the real call.
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, true, true, false),
            &node.app.serviceGroups[1].endpoints[0]);
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, true, false, true),
            &node.app.serviceGroups[2].endpoints[0]);
  // Disabling TCP must not disable the service filter for explicit EC RDMA.
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, false, false, true),
            &node.app.serviceGroups[2].endpoints[0]);
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, true, true, true), nullptr);
}

TEST(TestEcTransportPolicy, MissingExplicitEndpointDoesNotBorrowOtherServicesOrNetworks) {
  flat::NodeInfo tcpOnly;
  group(tcpOnly, "UnrelatedService", {address(9100, net::Address::RDMA)});
  group(tcpOnly, "StorageSerde", {address(9200, net::Address::TCP), address(9201, net::Address::IPoIB),
                                 address(9202, net::Address::UNIX)});
  EXPECT_EQ(detail::selectStorageRpcEndpoint(tcpOnly, true, false, true), nullptr);
  EXPECT_EQ(detail::selectStorageRpcEndpoint(tcpOnly, false, false, true), nullptr);

  flat::NodeInfo rdmaOnly;
  group(rdmaOnly, "UnrelatedService", {address(9101, net::Address::TCP)});
  group(rdmaOnly, "StorageSerde", {address(9300, net::Address::RDMA)});
  EXPECT_EQ(detail::selectStorageRpcEndpoint(rdmaOnly, true, true, false), nullptr);
  EXPECT_EQ(detail::selectStorageRpcEndpoint(flat::NodeInfo{}, true, false, true), nullptr);
}

TEST(TestEcTransportPolicy, LegacyAutomaticAndChunkRoutesKeepTheirOriginalPreference) {
  flat::NodeInfo node;
  group(node, "UnrelatedService", {address(9100, net::Address::RDMA)});
  group(node, "StorageSerde", {address(9200, net::Address::TCP)});
  group(node, "StorageSerde", {address(9300, net::Address::RDMA)});
  // Original chunk callers use no EC flags and retain their old group search.
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, false, false, false),
            &node.app.serviceGroups[0].endpoints[0]);
  // Original uncontrolled EC auto selection still prefers RDMA across groups.
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, true, false, false),
            &node.app.serviceGroups[2].endpoints[0]);
  node.app.serviceGroups.pop_back();
  EXPECT_EQ(detail::selectStorageRpcEndpoint(node, true, false, false),
            &node.app.serviceGroups[1].endpoints[0]);
}

}  // namespace
}  // namespace hf3fs::storage::client::test
