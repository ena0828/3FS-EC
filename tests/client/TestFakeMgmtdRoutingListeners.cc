#include <atomic>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <future>
#include <memory>

#include "tests/lib/UnitTestFabric.h"

namespace hf3fs::test {
namespace {
using namespace std::chrono_literals;

TEST(TestFakeMgmtdRoutingListeners, NamedRemovalStopsCallbacksAndReleasesCapture) {
  auto routing = std::make_shared<flat::RoutingInfo>();
  FakeMgmtdClient client(routing);
  auto held = std::make_shared<int>(0);
  std::weak_ptr<int> weak = held;
  size_t originalCalls = 0, duplicateCalls = 0;
  ASSERT_TRUE(client.addRoutingInfoListener("owner", [&, held](auto) {
    ++*held;
    ++originalCalls;
  }));
  held.reset();
  ASSERT_FALSE(weak.expired());
  // Production try_emplace rejects a duplicate name; it does not replace it.
  EXPECT_FALSE(client.addRoutingInfoListener("owner", [&](auto) { ++duplicateCalls; }));
  client.setRoutingInfo(routing);
  EXPECT_EQ(originalCalls, 1);
  EXPECT_EQ(duplicateCalls, 0);
  ASSERT_TRUE(client.removeRoutingInfoListener("owner"));
  EXPECT_TRUE(weak.expired());
  EXPECT_FALSE(client.removeRoutingInfoListener("owner"));
  client.setRoutingInfo(routing);
  EXPECT_EQ(originalCalls, 1);
  EXPECT_EQ(duplicateCalls, 0);
  ASSERT_TRUE(client.addRoutingInfoListener("owner", [&](auto) { ++duplicateCalls; }));
  client.setRoutingInfo(routing);
  EXPECT_EQ(originalCalls, 1);
  EXPECT_EQ(duplicateCalls, 1);
  EXPECT_TRUE(client.removeRoutingInfoListener("owner"));
}

TEST(TestFakeMgmtdRoutingListeners, RemovalWaitsForAlreadyRunningCallback) {
  auto routing = std::make_shared<flat::RoutingInfo>();
  FakeMgmtdClient client(routing);
  std::promise<void> entered, release, removing;
  auto enteredFuture = entered.get_future();
  auto released = release.get_future().share();
  auto removingFuture = removing.get_future();
  std::atomic<size_t> calls{0};
  ASSERT_TRUE(client.addRoutingInfoListener("owner", [&](auto) {
    if (calls.fetch_add(1) == 0) {
      entered.set_value();
      released.wait();
    }
  }));
  std::future<bool> removal;
  auto dispatch = std::async(std::launch::async, [&] { client.setRoutingInfo(routing); });
  bool unblocked = false;
  auto unblock = [&] {
    if (!unblocked) {
      unblocked = true;
      release.set_value();
    }
  };
  SCOPE_EXIT {
    unblock();
    if (dispatch.valid()) dispatch.wait();
    if (removal.valid()) removal.wait();
  };
  ASSERT_EQ(enteredFuture.wait_for(5s), std::future_status::ready);
  removal = std::async(std::launch::async, [&] {
    removing.set_value();
    return client.removeRoutingInfoListener("owner");
  });
  ASSERT_EQ(removingFuture.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(removal.wait_for(30ms), std::future_status::timeout);
  unblock();
  ASSERT_EQ(dispatch.wait_for(5s), std::future_status::ready);
  dispatch.get();
  ASSERT_EQ(removal.wait_for(5s), std::future_status::ready);
  ASSERT_TRUE(removal.get());
  client.setRoutingInfo(routing);
  EXPECT_EQ(calls.load(), 1);
}

}  // namespace
}  // namespace hf3fs::test
