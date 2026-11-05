#include <chrono>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/GtestHelpers.h>
#include <gtest/gtest.h>
#include <thread>

#include "common/utils/BoundedQueue.h"
#include "common/utils/Coroutine.h"

namespace hf3fs::test {
namespace {

using namespace std::chrono_literals;

TEST(TestBoundedQueue, Normal) {
  BoundedQueue<int> queue(4);
  ASSERT_TRUE(queue.empty());

  queue.enqueue(1);
  queue.enqueue(2);
  queue.enqueue(3);
  queue.enqueue(4);
  ASSERT_TRUE(queue.full());
  ASSERT_FALSE(queue.try_enqueue(5));

  // 1. sync.
  {
    std::jthread dequeue([&] {
      std::this_thread::sleep_for(100ms);
      ASSERT_EQ(queue.dequeue(), 1);
    });

    auto start = std::chrono::steady_clock::now();
    queue.enqueue(5);
    auto elapsed = std::chrono::steady_clock::now() - start;
    ASSERT_LE(50ms, elapsed);
    ASSERT_LE(elapsed, 150ms);
  }

  // 2. async.
  {
    std::jthread dequeue([&] {
      std::this_thread::sleep_for(100ms);
      ASSERT_EQ(folly::coro::blockingWait(queue.co_dequeue()), 2);
    });

    auto start = std::chrono::steady_clock::now();
    folly::coro::blockingWait(queue.co_enqueue(6));
    auto elapsed = std::chrono::steady_clock::now() - start;
    ASSERT_LE(50ms, elapsed);
    ASSERT_LE(elapsed, 150ms);
  }

  // 3. try enqueue/dequeue.
  {
    ASSERT_FALSE(queue.try_enqueue(7));
    ASSERT_EQ(queue.try_dequeue(), std::optional<int>{3});
    ASSERT_TRUE(queue.try_enqueue(7));

    int value;
    ASSERT_TRUE(queue.try_dequeue(value));
    ASSERT_EQ(value, 4);

    ASSERT_EQ(queue.size(), 3);

    queue.dequeue(value);
    ASSERT_EQ(value, 5);

    folly::coro::blockingWait(queue.co_dequeue(value));
    ASSERT_EQ(value, 6);

    ASSERT_EQ(queue.try_dequeue(), std::optional<int>{7});
    ASSERT_EQ(queue.try_dequeue(), std::optional<int>{});
    ASSERT_FALSE(queue.try_dequeue());
  }
}

TEST(TestBoundedQueue, NonwaitingCommitOnlyForAcceptedItems) {
  struct Item {
    int value;
    bool *committed;
  };
  BoundedQueue<Item> queue(1);
  bool first = false;
  bool second = false;
  unsigned commits = 0;
  EXPECT_TRUE(queue.try_enqueueWithCommit(Item{1, &first}, [&]() noexcept {
    first = true;
    ++commits;
  }));
  EXPECT_FALSE(queue.try_enqueueWithCommit(Item{2, &second}, [&]() noexcept {
    second = true;
    ++commits;
  }));
  EXPECT_EQ(commits, 1);
  EXPECT_FALSE(second);
  auto one = queue.dequeue();
  EXPECT_EQ(one.value, 1);
  EXPECT_TRUE(*one.committed);
  EXPECT_TRUE(queue.try_enqueueWithCommit(Item{2, &second}, [&]() noexcept {
    second = true;
    ++commits;
  }));
  auto two = queue.dequeue();
  EXPECT_EQ(two.value, 2);
  EXPECT_TRUE(*two.committed);
  EXPECT_EQ(commits, 2);
  EXPECT_TRUE(queue.empty());
}

}  // namespace
}  // namespace hf3fs::test
