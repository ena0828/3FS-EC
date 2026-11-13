#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <exception>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Collect.h>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "common/net/Client.h"
#include "common/net/MessageHeader.h"
#include "common/net/WriteItem.h"
#include "common/serde/ClientContext.h"
#include "common/serde/RpcCallSizes.h"
#include "common/utils/ZSTD.h"

namespace hf3fs::net::test {
namespace {

using namespace std::chrono_literals;

struct Payload {
  SERDE_STRUCT_FIELD(value, std::string{});
};

void require(bool ok, const char *message) {
  if (!ok) throw std::runtime_error(message);
}

struct Received {
  uint64_t uuid = 0;
  Payload payload;
  serde::RpcFrameSize frame;
  uint64_t decodedBytes = 0;
};

struct Encoded {
  uint64_t uuid = 0;
  std::vector<uint8_t> bytes;
  serde::RpcFrameSize frame;
};

// The peer controls response order and invalid input, but all calls still pass
// through the production ClientContext, TCP reader, Processor and Waiter.
// Request sizes come from bytes actually read; response sizes come from the
// one buffer actually sent, never from a second serialization of a payload.
class TcpPeer {
 public:
  TcpPeer() {
    listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(listener_ >= 0, "create peer socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(listener_, 1) != 0) {
      ::close(listener_);
      listener_ = -1;
      throw std::runtime_error("bind/listen peer");
    }
    socklen_t length = sizeof(address);
    if (::getsockname(listener_, reinterpret_cast<sockaddr *>(&address), &length) != 0) {
      ::close(listener_);
      listener_ = -1;
      throw std::runtime_error("read peer address");
    }
    address_ = Address{address.sin_addr.s_addr, ntohs(address.sin_port), Address::TCP};
  }

  ~TcpPeer() {
    stopping_ = true;
    release();
    ::shutdown(listener_, SHUT_RDWR);
    if (auto fd = connected_.load(); fd >= 0) ::shutdown(fd, SHUT_RDWR);
    if (worker_.joinable()) worker_.join();
    if (auto fd = connected_.load(); fd >= 0) ::close(fd);
    if (listener_ >= 0) ::close(listener_);
  }

  Address address() const { return address_; }

  void start(std::function<void(TcpPeer &)> action) {
    worker_ = std::thread([this, action = std::move(action)] {
      try {
        pollfd pending{listener_, POLLIN, 0};
        int ready;
        do {
          ready = ::poll(&pending, 1, 10000);
        } while (ready < 0 && errno == EINTR && !stopping_);
        require(ready > 0 && (pending.revents & POLLIN), "peer accept deadline");
        int fd = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
        require(fd >= 0, "accept peer connection");
        connected_ = fd;
        require(!stopping_, "peer stopped before accept");
        timeval timeout{5, 0};
        require(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "peer receive deadline");
        require(::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
                "peer send deadline");
        action(*this);
      } catch (...) {
        error_ = std::current_exception();
      }
      // Keep the accepted connection open until destruction. Closing it here
      // could race a queued final response in the client's normal read loop.
    });
  }

  void join() {
    require(worker_.joinable(), "peer was not started");
    worker_.join();
    if (error_) std::rethrow_exception(error_);
  }

  void release() {
    std::lock_guard lock(gateMutex_);
    released_ = true;
    gate_.notify_all();
  }

  void waitRelease() {
    std::unique_lock lock(gateMutex_);
    require(gate_.wait_for(lock, 10s, [&] { return released_; }), "late response gate deadline");
    require(!stopping_, "late response gate cancelled");
  }

  Received receive() {
    MessageHeader header{};
    readAll(&header, sizeof(header));
    require(header.isSerdeMessage() && header.size > 0 && header.size <= 2 * 1024 * 1024,
            "unexpected request header");
    std::vector<uint8_t> body(header.size);
    readAll(body.data(), body.size());
    require(header.checksum == Checksum::calcSerde(body.data(), body.size(), header.isCompressed()),
            "request checksum");
    Received result;
    result.frame = {sizeof(header) + body.size(), true, header.isCompressed()};
    if (header.isCompressed()) {
      auto bound = ZSTD_decompressBound(body.data(), body.size());
      require(bound > 0 && bound <= 2 * 1024 * 1024, "request decompression bound");
      std::vector<uint8_t> decoded(bound);
      auto size = ZSTD_decompress(decoded.data(), decoded.size(), body.data(), body.size());
      require(!ZSTD_isError(size), "request decompression");
      decoded.resize(size);
      body = std::move(decoded);
    }
    result.decodedBytes = body.size();
    serde::MessagePacket<> packet;
    require(bool(serde::deserialize(packet, std::string_view(reinterpret_cast<char *>(body.data()), body.size()))),
            "request packet decode");
    require(packet.isRequest() && packet.serviceId == 88 && packet.methodId == 1, "request identity");
    require(bool(serde::deserialize(result.payload, packet.payload)), "request payload decode");
    result.uuid = packet.uuid;
    received.push_back(result);
    return result;
  }

  template <class T>
  Encoded encode(const Received &request, const T &response, bool compressed = false) {
    serde::MessagePacket packet(response);
    packet.uuid = request.uuid;
    packet.serviceId = 88;
    packet.methodId = 1;
    CoreRequestOptions options;
    options.compression = {compressed ? 1u : 0u, 0_B};
    auto buffer = SerdeBuffer::create(packet, options);
    return {packet.uuid,
            {buffer->buff(), buffer->buff() + buffer->length()},
            {buffer->length(), true, buffer->header().isCompressed()}};
  }

  Encoded echo(const Received &request, bool compressed = false) {
    Result<Payload> response = request.payload;
    return encode(request, response, compressed);
  }

  void send(const Encoded &frame) {
    size_t done = 0;
    while (done != frame.bytes.size()) {
      auto n = ::send(connected_.load(), frame.bytes.data() + done, frame.bytes.size() - done, MSG_NOSIGNAL);
      if (n < 0 && errno == EINTR) continue;
      require(n > 0, "send peer frame");
      done += size_t(n);
    }
    sent.push_back(frame.frame);
    sentUuids.push_back(frame.uuid);
  }

  std::vector<Received> received;
  std::vector<serde::RpcFrameSize> sent;
  std::vector<uint64_t> sentUuids;

 private:
  void readAll(void *buffer, size_t length) {
    size_t done = 0;
    while (done != length) {
      auto n = ::recv(connected_.load(), static_cast<uint8_t *>(buffer) + done, length - done, 0);
      if (n < 0 && errno == EINTR) continue;
      require(n > 0, "receive peer frame");
      done += size_t(n);
    }
  }

  int listener_ = -1;
  std::atomic<int> connected_{-1};
  std::atomic<bool> stopping_{false};
  Address address_;
  std::thread worker_;
  std::exception_ptr error_;
  std::mutex gateMutex_;
  std::condition_variable gate_;
  bool released_ = false;
};

class TestEcRpcFrameSizes : public testing::Test {
 protected:
  void SetUp() override {
    config_.io_worker().transport_pool().set_max_connections(1);
    // One reader preserves the order of the duplicate/late frames and the
    // subsequent barrier response on their single TCP stream.
    config_.thread_pool().set_num_io_threads(1);
    config_.thread_pool().set_num_proc_threads(1);
    client_ = std::make_unique<Client>(config_);
    ASSERT_TRUE(client_->start());
    options_.timeout = 5_s;
    options_.sendRetryTimes = 0;
    options_.logLongRunningThreshold = 0_ms;
    options_.reportMetrics = false;
  }

  void TearDown() override { client_->stopAndJoin(); }

  static auto call(serde::ClientContext &ctx,
                   const Payload &payload,
                   const UserRequestOptions &options,
                   serde::RpcCallSizes *sizes) {
    return ctx.call<"FrameSizes", "exchange", Payload, Payload, 88, 1>(payload, &options, nullptr, sizes);
  }

  static void sameFrame(const serde::RpcFrameSize &actual, const serde::RpcFrameSize &expected) {
    EXPECT_EQ(actual.available, expected.available);
    EXPECT_EQ(actual.bytes, expected.bytes);
    EXPECT_EQ(actual.compressed, expected.compressed);
  }

  Client::Config config_;
  std::unique_ptr<Client> client_;
  UserRequestOptions options_;
};

TEST_F(TestEcRpcFrameSizes, ActualEncodedFramesIncludeHeaderAcrossCompression) {
  for (bool compressed : {false, true}) {
    TcpPeer peer;
    peer.start([&](auto &p) { p.send(p.echo(p.receive(), compressed)); });
    auto ctx = client_->serdeCtx(peer.address());
    Payload input;
    input.value.assign(128 * 1024, 'x');
    options_.compression = CompressionOptions{compressed ? 1u : 0u, 0_B};
    serde::RpcCallSizes sizes;
    auto result = folly::coro::blockingWait(call(ctx, input, options_, &sizes));
    peer.join();
    ASSERT_TRUE(result);
    EXPECT_EQ(result->value, input.value);
    ASSERT_EQ(peer.received.size(), 1);
    ASSERT_EQ(peer.sent.size(), 1);
    sameFrame(sizes.request, peer.received[0].frame);
    sameFrame(sizes.response, peer.sent[0]);
    EXPECT_TRUE(sizes.request.available);
    EXPECT_TRUE(sizes.response.available);
    EXPECT_EQ(sizes.request.compressed, compressed);
    EXPECT_EQ(sizes.response.compressed, compressed);
    EXPECT_GE(sizes.request.bytes, kMessageHeaderSize);
    EXPECT_GE(sizes.response.bytes, kMessageHeaderSize);
    if (compressed) {
      EXPECT_LT(sizes.request.bytes, peer.received[0].decodedBytes);
    } else {
      EXPECT_EQ(sizes.request.bytes, kMessageHeaderSize + peer.received[0].decodedBytes);
    }
  }
}

TEST_F(TestEcRpcFrameSizes, ReverseRepliesOnOneConnectionKeepUuidAttribution) {
  TcpPeer peer;
  peer.start([](auto &p) {
    p.send(p.echo(p.receive()));  // Establish exactly one connection before parallel calls.
    auto first = p.receive();
    auto second = p.receive();
    p.send(p.echo(second));
    p.send(p.echo(first));
  });
  auto ctx = client_->serdeCtx(peer.address());
  Payload warmup;
  warmup.value = "warmup";
  ASSERT_TRUE(folly::coro::blockingWait(call(ctx, warmup, options_, nullptr)));
  Payload first;
  first.value = "first";
  Payload second;
  second.value.assign(4096, 'b');
  serde::RpcCallSizes a, b;
  auto [ra, rb] = folly::coro::blockingWait(
      folly::coro::collectAll(call(ctx, first, options_, &a), call(ctx, second, options_, &b)));
  peer.join();
  ASSERT_TRUE(ra);
  ASSERT_TRUE(rb);
  EXPECT_EQ(ra->value, first.value);
  EXPECT_EQ(rb->value, second.value);
  ASSERT_EQ(peer.received.size(), 3);
  ASSERT_EQ(peer.sent.size(), 3);
  EXPECT_NE(peer.received[1].uuid, peer.received[2].uuid);
  EXPECT_EQ(peer.sentUuids[1], peer.received[2].uuid);
  EXPECT_EQ(peer.sentUuids[2], peer.received[1].uuid);
  for (size_t i = 1; i != 3; ++i) {
    const auto &sizes = peer.received[i].payload.value == first.value ? a : b;
    sameFrame(sizes.request, peer.received[i].frame);
    sameFrame(sizes.response, peer.sent[3 - i]);
  }
  EXPECT_NE(a.request.bytes, b.request.bytes);
  EXPECT_NE(a.response.bytes, b.response.bytes);
}

TEST_F(TestEcRpcFrameSizes, BusinessAndDecodeErrorsRetainValidFrameSamples) {
  for (bool malformedInner : {false, true}) {
    TcpPeer peer;
    peer.start([&](auto &p) {
      auto request = p.receive();
      if (malformedInner) {
        // Valid outer Packet, but a Result success flag with no Rsp body.
        p.send(p.encode(request, true));
      } else {
        Result<Payload> error = makeError(RPCCode::kInvalidMessageType, "controlled business error");
        p.send(p.encode(request, error));
      }
    });
    auto ctx = client_->serdeCtx(peer.address());
    Payload input;
    input.value = "error";
    serde::RpcCallSizes sizes;
    auto result = folly::coro::blockingWait(call(ctx, input, options_, &sizes));
    peer.join();
    ASSERT_FALSE(result);
    if (malformedInner) {
      EXPECT_EQ(result.error().code(), StatusCode::kSerdeInsufficientLength);
    } else {
      EXPECT_EQ(result.error().code(), RPCCode::kInvalidMessageType);
    }
    ASSERT_EQ(peer.received.size(), 1);
    ASSERT_EQ(peer.sent.size(), 1);
    sameFrame(sizes.request, peer.received[0].frame);
    sameFrame(sizes.response, peer.sent[0]);
    EXPECT_TRUE(sizes.response.available);  // Packet arrival is independent of business success.
  }
}

TEST_F(TestEcRpcFrameSizes, TimeoutLateAndDuplicateRepliesDoNotRewriteCompletedOutputs) {
  for (bool destroyOutput : {false, true}) {
    TcpPeer peer;
    peer.start([](auto &p) {
      p.send(p.echo(p.receive()));  // Exclude cold connection establishment from the short timeout.
      auto timedOut = p.receive();
      p.waitRelease();
      auto late = p.echo(timedOut);
      p.send(late);
      p.send(late);
      auto next = p.echo(p.receive());
      p.send(next);
      p.send(next);  // A duplicate after a normal response must also lose UUID arbitration.
      p.send(p.echo(p.receive()));
    });
    auto ctx = client_->serdeCtx(peer.address());
    Payload warmup;
    warmup.value = "warmup";
    ASSERT_TRUE(folly::coro::blockingWait(call(ctx, warmup, options_, nullptr)));
    Payload input;
    input.value = "late";
    auto shortOptions = options_;
    shortOptions.timeout = 500_ms;
    auto old = std::make_unique<serde::RpcCallSizes>();
    auto timedOut = folly::coro::blockingWait(call(ctx, input, shortOptions, old.get()));
    ASSERT_FALSE(timedOut);
    ASSERT_EQ(timedOut.error().code(), RPCCode::kTimeout);
    EXPECT_TRUE(old->request.available);
    EXPECT_FALSE(old->response.available);
    auto saved = *old;
    if (destroyOutput) old.reset();  // Exercise late arrivals after the output owner's lifetime.
    peer.release();
    Payload next;
    next.value.assign(1024, 'n');
    serde::RpcCallSizes second;
    ASSERT_TRUE(folly::coro::blockingWait(call(ctx, next, options_, &second)));
    auto secondSaved = second;
    Payload barrier;
    barrier.value = "barrier";
    serde::RpcCallSizes third;
    ASSERT_TRUE(folly::coro::blockingWait(call(ctx, barrier, options_, &third)));
    peer.join();
    ASSERT_EQ(peer.received.size(), 4);
    ASSERT_EQ(peer.sent.size(), 6);
    sameFrame(saved.request, peer.received[1].frame);
    if (old) {
      sameFrame(old->request, saved.request);
      sameFrame(old->response, saved.response);
    }
    sameFrame(second.request, secondSaved.request);
    sameFrame(second.response, secondSaved.response);
    sameFrame(second.response, peer.sent[3]);
    sameFrame(third.request, peer.received[3].frame);
    sameFrame(third.response, peer.sent[5]);
  }
}

TEST_F(TestEcRpcFrameSizes, InvalidOuterFrameHasNoResponseSample) {
  for (bool corruptChecksum : {true, false}) {
    TcpPeer peer;
    peer.start([&](auto &p) {
      auto frame = p.echo(p.receive());
      MessageHeader header;
      std::memcpy(&header, frame.bytes.data(), sizeof(header));
      if (corruptChecksum) {
        header.checksum ^= 0x100u;  // Valid framing and serde magic, invalid CRC.
      } else {
        // CRC-valid complete frame whose one-byte body cannot contain a Packet.
        header.size = 1;
        frame.bytes.resize(kMessageHeaderSize + header.size);
        frame.bytes[kMessageHeaderSize] = 0x80;  // Unterminated outer table-length varint.
        header.checksum = Checksum::calcSerde(frame.bytes.data() + kMessageHeaderSize, header.size);
        frame.frame.bytes = frame.bytes.size();
      }
      std::memcpy(frame.bytes.data(), &header, sizeof(header));
      p.send(frame);
    });
    auto ctx = client_->serdeCtx(peer.address());
    Payload input;
    input.value = "invalid-outer";
    serde::RpcCallSizes sizes;
    sizes.response = {12345, true, true};  // Entry resets an old observation even on failure.
    auto result = folly::coro::blockingWait(call(ctx, input, options_, &sizes));
    peer.join();
    ASSERT_FALSE(result);
    ASSERT_EQ(peer.received.size(), 1);
    ASSERT_EQ(peer.sent.size(), 1);
    sameFrame(sizes.request, peer.received[0].frame);
    EXPECT_FALSE(sizes.response.available);
    EXPECT_EQ(sizes.response.bytes, 0);
    EXPECT_FALSE(sizes.response.compressed);
  }
}

}  // namespace
}  // namespace hf3fs::net::test
