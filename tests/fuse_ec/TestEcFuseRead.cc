#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <limits>
#include <map>
#include <new>
#include <string_view>
#include <sys/stat.h>
#include <vector>

#include "client/storage/StorageClientInMem.h"
#include "fbs/meta/MockService.h"
#include "fuse/EcFuseRead.h"
#include "fuse/FuseOps.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec::detail {
struct EcReadSpoolExclusiveTestAccess {
  static Result<EcReadSpoolSnapshot> inject(EcReadSpool &spool, void (*hook)(void *), void *context) {
    return spool.inspectExclusiveImpl(hook, context);
  }
};
}  // namespace hf3fs::client::ec::detail
namespace hf3fs::fuse {
namespace {
using namespace client::ec;
using folly::coro::blockingWait;
struct Calls {
  size_t auth = 0, describe = 0, acquire = 0, replicated = 0;
  std::vector<std::string_view> events;
  bool wrongLayout = false;
  meta::EcFileState file;
  std::map<Uuid, meta::EcRangeSnapshot> ranges;
};
// Metadata-only mock: successful data is restricted to the actual zero-EOF
// path. Nonempty native Storage bytes belong to the independent mount test.
class Service : public meta::MockMetaService {
 public:
  explicit Service(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &req) override {
    ++calls_->auth;
    calls_->events.emplace_back("authenticate");
    if (req.user.uid != flat::Uid(123) || req.user.token != "owner-token")
      co_return makeError(StatusCode::kAuthenticationFail);
    auto user = req.user;
    user.token.clear();
    co_return meta::AuthRsp{user};
  }
  CoTryTask<meta::DescribeEcFileV2Rsp> describeEcFileV2(serde::CallContext &,
                                                        const meta::DescribeEcFileV2Req &req) override {
    ++calls_->describe;
    calls_->events.emplace_back("describe");
    if (req.object != calls_->file.object || req.access != meta::AccessType::READ || req.uuid.is_nil())
      co_return makeError(StatusCode::kTokenMismatch);
    meta::DescribeEcFileV2Rsp rsp;
    rsp.file = calls_->file;
    if (calls_->wrongLayout) rsp.file.layout.shardBytes *= 2;
    co_return rsp;
  }
  CoTryTask<meta::EcRangeRsp> acquireEcRangeV2(serde::CallContext &, const meta::AcquireEcRangeV2Req &req) override {
    ++calls_->acquire;
    calls_->events.emplace_back("acquire");
    meta::EcRangeSnapshot snapshot;
    snapshot.requestId = req.uuid;
    snapshot.rangeId = req.rangeId;
    snapshot.owner = {req.user.uid, req.client.uuid};
    snapshot.selection = req.selection;
    snapshot.file = calls_->file;
    if (snapshot.file.length != 0) co_return makeError(StatusCode::kFoundBug);
    calls_->ranges[req.rangeId] = snapshot;
    meta::EcRangeRsp rsp;
    rsp.snapshot = snapshot;
    co_return rsp;
  }
  CoTryTask<meta::EcRangeRsp> queryEcRangeV2(serde::CallContext &, const meta::QueryEcRangeV2Req &req) override {
    auto it = calls_->ranges.find(req.rangeId);
    if (it == calls_->ranges.end()) co_return makeError(StatusCode::kKVStoreNotFound);
    if (it->second.requestId != req.uuid || it->second.owner.client != req.client.uuid ||
        it->second.owner.uid != req.user.uid || !serde::equals(it->second.selection, req.selection))
      co_return makeError(StatusCode::kTokenMismatch);
    meta::EcRangeRsp rsp;
    rsp.snapshot = it->second;
    co_return rsp;
  }

 private:
  std::shared_ptr<Calls> calls_;
};
class FailingStorage : public storage::client::StorageClientInMem {
 public:
  FailingStorage(const Config &cfg, hf3fs::client::ICommonMgmtdClient &mgmtd, std::shared_ptr<Calls> calls)
      : StorageClientInMem(ClientId::random(), cfg, mgmtd),
        calls_(std::move(calls)) {}
  CoTryTask<void> batchRead(std::span<storage::client::ReadIO> reads,
                            const flat::UserInfo &,
                            const storage::client::ReadOptions &,
                            std::vector<storage::client::ReadIO *> *) override {
    if (reads.empty()) co_return makeError(StatusCode::kFoundBug);
    ++calls_->replicated;
    co_return makeError(StatusCode::kIOError);
  }

 private:
  std::shared_ptr<Calls> calls_;
};
class TestEcFuseRead : public ::testing::Test {
 protected:
  void SetUp() override {
    calls_->file.object = {meta::InodeId(101), Uuid::random()};
    calls_->file.layout.incarnation = calls_->file.object.incarnation;
    calls_->file.layout.shardBytes = 8;
    calls_->file.epoch = 1;
    meta::Layout layout;
    layout.chains = calls_->file.layout;
    inode_ = meta::Inode{calls_->file.object.inode,
                         {meta::File{layout}, meta::Acl{user_.uid, user_.gid, meta::Permission{0600}}}};
    cfg_.set_network_type(net::Address::TCP);
    cfg_.retry_default().set_retry_init_wait(0_ms);
    mgmtd_ = tests::FakeMgmtdClient::create({}, 1, 0);
    storage_ = std::make_shared<FailingStorage>(storageCfg_, *mgmtd_, calls_);
    auto made = EcReadSpool::create(path("spool"), "fuse-read-test", {});
    ASSERT_OK(made);
    spool_ = std::move(*made);
    serde::ClientMockContext mock;
    mock.setService(std::make_unique<Service>(calls_));
    meta_ = std::make_shared<meta::client::MetaClient>(ClientId(spool_->clientNamespace()),
                                                       cfg_,
                                                       std::make_unique<meta::client::MetaClient::StubFactory>(mock),
                                                       mgmtd_,
                                                       storage_,
                                                       false);
    connect();
  }
  void connect() {
    auto connected = EcReadDispatcher::connect(spool_, meta_, storage_, mgmtd_, pool_, {});
    ASSERT_OK(connected);
    dispatcher_ = std::move(*connected);
    adapter_ = std::make_shared<EcFuseReadAdapter>(dispatcher_);
  }
  void TearDown() override {
    adapter_.reset();
    if (dispatcher_) {
      auto report = blockingWait(dispatcher_->stop());
      EXPECT_TRUE(report.localJoined);
      EXPECT_TRUE(report.lowerJoinConfirmed);
      if (!report.localJoined || !report.lowerJoinConfirmed) std::terminate();
      dispatcher_.reset();
    }
    if (meta_) meta_->stop();
  }
  static EcStripeControl control() { return {std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; }
  std::filesystem::path path(const char *name) const { return std::filesystem::path(temp_.path().string()) / name; }
  folly::test::TemporaryDirectory temp_;
  folly::CPUThreadPoolExecutor pool_{2};
  meta::client::MetaClient::Config cfg_;
  storage::client::StorageClient::Config storageCfg_;
  flat::UserInfo user_{flat::Uid(123), flat::Gid(123), "owner-token"};
  meta::Inode inode_;
  std::shared_ptr<Calls> calls_ = std::make_shared<Calls>();
  std::shared_ptr<tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<FailingStorage> storage_;
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::shared_ptr<EcReadSpool> spool_;
  std::shared_ptr<EcReadDispatcher> dispatcher_;
  std::shared_ptr<EcFuseReadAdapter> adapter_;
};
TEST_F(TestEcFuseRead, FlagsAndCopiedIdentityUseActualAuthentication) {
  for (int flag : {O_WRONLY, O_RDWR, O_TRUNC, O_APPEND, O_CREAT, O_EXCL, O_PATH, O_TMPFILE}) {
    auto rejected = blockingWait(adapter_->open(inode_, user_, flag, control()));
    ASSERT_ERROR(rejected, StatusCode::kNotImplemented);
  }
  EXPECT_EQ(calls_->auth, 0);
  auto pending = adapter_->open(inode_, user_, O_RDONLY | O_NONBLOCK, control());
  inode_.id = meta::InodeId(999);  // Factory must already own the original identity.
  auto handle = blockingWait(std::move(pending));
  ASSERT_OK(handle);
  EXPECT_EQ(handle->described().object, calls_->file.object);
  EXPECT_EQ(calls_->auth, 1);
  EXPECT_EQ(calls_->describe, 1);
  inode_.id = calls_->file.object.inode;
  auto deniedUser = user_;
  deniedUser.token = "wrong";
  auto denied = blockingWait(adapter_->open(inode_, deniedUser, O_RDONLY, control()));
  ASSERT_ERROR(denied, StatusCode::kAuthenticationFail);
  calls_->wrongLayout = true;
  auto mismatch = blockingWait(adapter_->open(inode_, user_, O_RDONLY, control()));
  ASSERT_ERROR(mismatch, StatusCode::kDataCorruption);
}
TEST_F(TestEcFuseRead, WindowBoundsAndZeroEofPreserveReceiptAndOutputLease) {
  auto layout = calls_->file.layout;
  ASSERT_EQ(*ecReadWindowLength(layout, 79, 641, true), 561);
  ASSERT_ERROR(ecReadWindowLength(layout, 79, 641, false), StatusCode::kNotImplemented);
  ASSERT_ERROR(ecReadWindowLength(layout, UINT64_MAX, 1, true), StatusCode::kInvalidArg);
  ASSERT_EQ(*ecReadWindowLength(layout, UINT64_MAX, 0, false), 0);
  layout.shardBytes = 1u << 20;
  ASSERT_EQ(*ecReadWindowLength(layout, 0, uint64_t{64} << 20, true), uint64_t{32} << 20);
  auto opened = blockingWait(adapter_->open(inode_, user_, O_RDONLY, control()));
  ASSERT_OK(opened);
  auto read = blockingWait(adapter_->read(*opened, user_, 0, 100, false, control()));
  ASSERT_OK(read);
  ASSERT_TRUE(read->localJoined);
  ASSERT_TRUE(read->data);
  EXPECT_TRUE(read->data->bytes().empty());
  EXPECT_TRUE(read->cleanup.allReleased);
  EXPECT_EQ(read->cleanup.expectedPins, 0);
  EXPECT_FALSE(read->receipt.rangeId.is_nil());
  EXPECT_EQ(calls_->acquire, 1);
  auto busy = blockingWait(adapter_->read(*opened, user_, 0, 0, false, control()));
  ASSERT_FALSE(busy);
  read->data.reset();
  auto after = blockingWait(adapter_->read(*opened, user_, 0, 0, false, control()));
  ASSERT_OK(after);
  ASSERT_TRUE(after->data);
  after->data.reset();
}
TEST_F(TestEcFuseRead, ExclusiveInspectionRejectsAttachmentAndReleasesAfterException) {
  ASSERT_FALSE(spool_->inspectExclusive());
  auto stopped = blockingWait(dispatcher_->stop());
  ASSERT_TRUE(stopped.localJoined && stopped.lowerJoinConfirmed);
  adapter_.reset();
  dispatcher_.reset();
  EXPECT_THROW(client::ec::detail::EcReadSpoolExclusiveTestAccess::inject(
                   *spool_,
                   [](void *) { throw std::bad_alloc(); },
                   nullptr),
               std::bad_alloc);
  auto local = spool_->inspectExclusive();
  ASSERT_OK(local);
  EXPECT_EQ(local->retainedRuns, 0);
  using Self = decltype(this);
  struct Probe {
    Self self;
    bool rejected = false;
  } probe{this};
  auto inspected = client::ec::detail::EcReadSpoolExclusiveTestAccess::inject(
      *spool_,
      [](void *value) {
        auto &p = *static_cast<Probe *>(value);
        auto other = EcReadDispatcher::connect(p.self->spool_,
                                               p.self->meta_,
                                               p.self->storage_,
                                               p.self->mgmtd_,
                                               p.self->pool_,
                                               {});
        p.rejected = !other;
      },
      &probe);
  ASSERT_OK(inspected);
  EXPECT_TRUE(probe.rejected);
  connect();
  ASSERT_FALSE(spool_->inspectExclusive());
}
TEST_F(TestEcFuseRead, PrivateArchiveOutsideSpoolAndExistingFlockAreRequired) {
  auto second = EcReadSpool::open(path("spool"), "fuse-read-test", {});
  ASSERT_FALSE(second);
  std::filesystem::create_directory(path("archive"));
  ASSERT_EQ(::chmod(path("archive").c_str(), 0700), 0);
  ASSERT_OK(validateEcArchiveDirectory(path("archive"), spool_->directory()));
  ASSERT_ERROR(validateEcArchiveDirectory(spool_->directory(), spool_->directory()), StatusCode::kInvalidArg);
  ASSERT_EQ(::chmod(path("archive").c_str(), 0755), 0);
  ASSERT_ERROR(validateEcArchiveDirectory(path("archive"), spool_->directory()), StatusCode::kInvalidArg);
}
TEST_F(TestEcFuseRead, ActualRingMixedReplicatedFailureKeepsEcSuccessAndInvalidIndex) {
  auto &global = getFuseClientsInstance();
  ASSERT_FALSE(global.ecReads);
  global.ecReads = adapter_;
  auto clear = folly::makeGuard([&] { global.ecReads.reset(); });
  const auto shmName = "/hf3fs-ec-adapter-" + Uuid::random().toHexString();
  auto shm =
      std::make_shared<lib::ShmBuf>(Path(shmName), size_t{4096}, size_t{4096}, -1, user_.uid, getpid(), getppid());
  blockingWait(shm->registerForIO({}, *storage_, [] {}));
  auto registered = blockingWait(lib::ShmBufForIO(shm, 0).memh(16));
  ASSERT_OK(registered);
  ASSERT_NE(*registered, nullptr);
  std::vector<uint64_t> ringBytes((IoRing::bytesRequired(8) + 7) / 8, 0);
  auto ring = std::make_shared<IoRing>(nullptr,
                                       "mixed",
                                       user_,
                                       true,
                                       reinterpret_cast<uint8_t *>(ringBytes.data()),
                                       ringBytes.size() * 8,
                                       0,
                                       1,
                                       0_ms,
                                       0);
  auto ecInode = std::make_shared<RcInode>(inode_);
  auto replica =
      std::make_shared<RcInode>(meta::Inode{meta::InodeId(102),
                                            {meta::File{meta::Layout::newChainList(4096, {flat::ChainId(1)})},
                                             meta::Acl{user_.uid, user_.gid, meta::Permission{0600}}}});
  for (int i = 0; i != 2; ++i) {
    ring->ringSection[i].ioLen = 16;
    ASSERT_TRUE(ring->addSqe(i, nullptr));
  }
  ASSERT_TRUE(ring->addSqe(INT32_MAX, nullptr));
  auto jobs = ring->jobsToProc(1);
  ASSERT_EQ(jobs.size(), 1);
  FuseConfig config;
  config.set_max_uid(256);
  UserConfig users;
  users.init(config);
  storage::client::IoOptions io;
  blockingWait(ring->process(
      jobs[0].sqeProcTail,
      jobs[0].toProc,
      *storage_,
      io,
      users,
      [&](auto &out, const IoArgs *, const IoSqe *, int count) {
        for (int i = 0; i != count; ++i) out.push_back(i == 1 ? replica : ecInode);
      },
      [&](auto &out, const IoArgs *, const IoSqe *, int count) {
        for (int i = 0; i != count; ++i) out.emplace_back(lib::ShmBufForIO(shm, 0));
      }));
  ASSERT_EQ(ring->cqeCount(), 3);
  EXPECT_EQ(ring->cqeSection[0].result, 0);
  EXPECT_EQ(ring->cqeSection[1].result, -static_cast<int64_t>(StatusCode::toErrno(StatusCode::kIOError)));
  EXPECT_EQ(ring->cqeSection[2].result, -static_cast<int64_t>(StatusCode::toErrno(StatusCode::kInvalidArg)));
  EXPECT_EQ(calls_->replicated, 1);
  EXPECT_EQ(calls_->acquire, 1);
}
TEST_F(TestEcFuseRead, ActualRingRejectsEcWriteBeforeLegacyMutationAndRegistration) {
  const auto shmName = "/hf3fs-ec-adapter-" + Uuid::random().toHexString();
  auto shm =
      std::make_shared<lib::ShmBuf>(Path(shmName), size_t{4096}, size_t{4096}, -1, user_.uid, getpid(), getppid());
  // Deliberately unregistered: EC rejection must precede memh/legacy beginWrite.
  std::vector<uint64_t> ringBytes((IoRing::bytesRequired(4) + 7) / 8, 0);
  auto ring = std::make_shared<IoRing>(nullptr,
                                       "write-reject",
                                       user_,
                                       false,
                                       reinterpret_cast<uint8_t *>(ringBytes.data()),
                                       ringBytes.size() * 8,
                                       0,
                                       1,
                                       0_ms,
                                       0);
  ring->ringSection[0].ioLen = 16;
  ASSERT_TRUE(ring->addSqe(0, nullptr));
  auto jobs = ring->jobsToProc(1);
  ASSERT_EQ(jobs.size(), 1);
  auto cached = std::make_shared<RcInode>(inode_);
  FuseConfig config;
  config.set_max_uid(256);
  UserConfig users;
  users.init(config);
  storage::client::IoOptions io;
  blockingWait(ring->process(
      jobs[0].sqeProcTail,
      jobs[0].toProc,
      *storage_,
      io,
      users,
      [&](auto &out, const IoArgs *, const IoSqe *, int) { out.push_back(cached); },
      [&](auto &out, const IoArgs *, const IoSqe *, int) { out.emplace_back(lib::ShmBufForIO(shm, 0)); }));
  ASSERT_EQ(ring->cqeCount(), 1);
  EXPECT_EQ(ring->cqeSection[0].result, -static_cast<int64_t>(StatusCode::toErrno(StatusCode::kNotImplemented)));
  EXPECT_EQ(cached->dynamicAttr.rlock()->written, 0);
  EXPECT_EQ(calls_->auth, 0);
}
TEST_F(TestEcFuseRead, ClaimedSqeAndArgumentsRemainOwnedAfterSharedMemoryChanges) {
  auto &global = getFuseClientsInstance();
  ASSERT_FALSE(global.ecReads);
  global.ecReads = adapter_;
  auto clear = folly::makeGuard([&] { global.ecReads.reset(); });
  const auto shmName = "/hf3fs-ec-snapshot-" + Uuid::random().toHexString();
  auto shm =
      std::make_shared<lib::ShmBuf>(Path(shmName), size_t{4096}, size_t{4096}, -1, user_.uid, getpid(), getppid());
  std::vector<uint64_t> memory((IoRing::bytesRequired(4) + 7) / 8, 0);
  auto ring = std::make_shared<IoRing>(nullptr,
                                       "snapshot",
                                       user_,
                                       true,
                                       reinterpret_cast<uint8_t *>(memory.data()),
                                       memory.size() * 8,
                                       0,
                                       1,
                                       0_ms,
                                       0);
  const void *const originalUserdata = reinterpret_cast<void *>(uintptr_t{17});
  ring->ringSection[0].fileIid = inode_.id.u64();
  ring->ringSection[0].ioLen = 16;
  ASSERT_TRUE(ring->addSqe(0, originalUserdata));
  auto jobs = ring->jobsToProc(1);
  ASSERT_EQ(jobs.size(), 1);
  auto cached = std::make_shared<RcInode>(inode_);
  FuseConfig config;
  config.set_max_uid(256);
  UserConfig users;
  users.init(config);
  storage::client::IoOptions io;
  blockingWait(ring->process(
      jobs[0].sqeProcTail,
      jobs[0].toProc,
      *storage_,
      io,
      users,
      [&](auto &out, const IoArgs *arguments, const IoSqe *sqes, int count) {
        EXPECT_EQ(count, 1);
        EXPECT_EQ(arguments[sqes[0].index].ioLen, 16);
        // This runs after process copied the claimed values, before its first
        // authentication await. Mutations must not change buffer validation,
        // extent selection or the eventual CQE index/userdata.
        ring->ringSection[0].ioLen = UINT64_MAX;
        ring->ringSection[0].fileOff = UINT64_MAX;
        ring->sqeSection[0] = IoSqe{INT32_MAX, nullptr};
        out.push_back(cached);
      },
      [&](auto &out, const IoArgs *arguments, const IoSqe *sqes, int count) {
        EXPECT_EQ(count, 1);
        EXPECT_EQ(arguments[sqes[0].index].ioLen, 16);
        EXPECT_EQ(arguments[sqes[0].index].fileOff, 0);
        out.emplace_back(lib::ShmBufForIO(shm, 0));
      }));
  ASSERT_EQ(ring->cqeCount(), 1);
  EXPECT_EQ(ring->cqeSection[0].index, 0);
  EXPECT_EQ(ring->cqeSection[0].userdata, originalUserdata);
  EXPECT_EQ(ring->cqeSection[0].result, 0);  // Real zero-EOF adapter path.
  // Open authenticates before Describe; read reauthenticates, and the first
  // lower stripe-client connection authenticates before acquiring the range.
  EXPECT_EQ(calls_->auth, 3);
  EXPECT_EQ(calls_->describe, 1);
  EXPECT_EQ(calls_->acquire, 1);
  EXPECT_EQ(calls_->events,
            (std::vector<std::string_view>{"authenticate", "describe", "authenticate", "authenticate", "acquire"}));
}
}  // namespace
}  // namespace hf3fs::fuse
