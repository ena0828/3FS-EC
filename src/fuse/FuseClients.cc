#include "FuseClients.h"

#include <exception>
#include <folly/Random.h>
#include <folly/ScopeGuard.h>
#include <folly/executors/IOThreadPoolExecutor.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/functional/Partial.h>
#include <folly/logging/xlog.h>
#include <fuse3/fuse_lowlevel.h>
#include <limits>
#include <memory>
#include <thread>
#include <utility>

#include "common/app/ApplicationBase.h"
#include "common/monitor/Recorder.h"
#include "common/utils/BackgroundRunner.h"
#include "common/utils/Coroutine.h"
#include "common/utils/Duration.h"
#include "common/utils/FileUtils.h"
#include "common/utils/SysResource.h"
#include "fbs/meta/Common.h"
#include "fbs/mgmtd/Rpc.h"
#include "stubs/MetaService/MetaServiceStub.h"
#include "stubs/common/RealStubFactory.h"
#include "stubs/mgmtd/MgmtdServiceStub.h"

namespace hf3fs::fuse {
namespace {
monitor::ValueRecorder dirtyInodesCnt("fuse.dirty_inodes");

Result<Void> establishClientSession(client::IMgmtdClientForClient &mgmtdClient) {
  return folly::coro::blockingWait([&]() -> CoTryTask<void> {
    auto retryInterval = std::chrono::milliseconds(10);
    constexpr auto maxRetryInterval = std::chrono::milliseconds(1000);
    Result<Void> res = Void{};
    for (int i = 0; i < 40; ++i) {
      res = co_await mgmtdClient.extendClientSession();
      if (res) break;
      XLOGF(CRITICAL, "Try to establish client session failed: {}\nretryCount: {}", res.error(), i);
      co_await folly::coro::sleep(retryInterval);
      retryInterval = std::min(2 * retryInterval, maxRetryInterval);
    }
    co_return res;
  }());
}
}  // namespace

FuseClients::~FuseClients() {
  // Entry points must perform checked shutdown while all external configuration
  // and globals remain alive. A destructor cannot recover an unknown join.
  if (!stop()) std::terminate();
}

Result<Void> FuseClients::init(const flat::AppInfo &appInfo,
                               const String &mountPoint,
                               const String &tokenFile,
                               FuseConfig &fuseConfig) {
  config = &fuseConfig;
  fullyStopped = false;
  const auto &transport = fuseConfig.ec_storage_transport();
  if (transport != "tcp" && transport != "rdma")
    return makeError(StatusCode::kInvalidConfig, "EC storage transport must be tcp or rdma");
  ecStorageTransport = transport == "rdma" ? storage::client::EcRequestControl::TransportPolicy::RdmaOnly
                                           : storage::client::EcRequestControl::TransportPolicy::TcpOnly;
  if (fuseConfig.batch_io_coros() <= 0 || fuseConfig.io_jobq_size() <= 0 || fuseConfig.io_jobq_sizes().hi() <= 0 ||
      fuseConfig.io_jobq_sizes().lo() <= 0)
    return makeError(StatusCode::kInvalidArg, "owned ring shutdown requires consumers and nonempty queues");
  if (fuseConfig.ec_read().enable()) {
    ecHighWorkers = fuseConfig.io_worker_coros().hi();
    ecLowWorkers = fuseConfig.io_worker_coros().lo();
    if (ecHighWorkers <= 0 || ecLowWorkers <= 0 || int64_t(ecHighWorkers) + ecLowWorkers >= fuseConfig.batch_io_coros())
      return makeError(StatusCode::kInvalidArg, "EC mount requires a consumer for every priority queue");
    if (fuseConfig.enable_writeback_cache())
      return makeError(StatusCode::kInvalidArg, "EC mount read requires writeback cache disabled");
    const auto &ec = fuseConfig.ec_read();
    client::ec::EcReadSpool::Limits limits{ec.retained_runs(), ec.outstanding_runs(), ec.logical_spool_bytes()};
    auto opened = ec.create_state() ? client::ec::EcReadSpool::create(ec.state_directory(), appInfo.clusterId, limits)
                                    : client::ec::EcReadSpool::open(ec.state_directory(), appInfo.clusterId, limits);
    RETURN_ON_ERROR(opened);
    ecSpool = std::move(*opened);
    ecOperationTime = std::chrono::seconds(ec.maximum_operation_seconds());
    ecRetireCompleted = ec.retire_completed();
    if (ecRetireCompleted) {
      ecArchiveDirectory = ec.archive_directory();
      RETURN_ON_ERROR(validateEcArchiveDirectory(ecArchiveDirectory, ecSpool->directory()));
    }
    ecExecutor = std::make_unique<folly::CPUThreadPoolExecutor>(2);
  }

  if (fuseConfig.ec_file().enable()) {
    const auto &ec = fuseConfig.ec_file();
    if (ecSpool || fuseConfig.enable_writeback_cache() || !ec.retained_sessions() || ec.retained_sessions() > 4096 ||
        !ec.maximum_operation_seconds() || ec.maximum_operation_seconds() > 3600 || !ec.shard_bytes() ||
        ec.shard_bytes() > (1u << 20))
      return makeError(StatusCode::kInvalidConfig,
                       "mode4 mount requires its own durable namespace and disabled writeback cache");
    ecHighWorkers = fuseConfig.io_worker_coros().hi();
    ecLowWorkers = fuseConfig.io_worker_coros().lo();
    if (ecHighWorkers <= 0 || ecLowWorkers <= 0 || int64_t(ecHighWorkers) + ecLowWorkers >= fuseConfig.batch_io_coros())
      return makeError(StatusCode::kInvalidConfig, "mode4 mount needs owned priority consumers");
    auto state = EcFileMountState::open({ec.state_directory(),
                                         appInfo.clusterId,
                                         ec.create_state(),
                                         ec.retained_sessions(),
                                         Uuid::zero(),
                                         ec.maximum_input_bytes()});
    RETURN_ON_ERROR(state);
    ecFileState = std::move(*state);
  }

  fuseMount = appInfo.clusterId;
  XLOGF_IF(FATAL,
           fuseMount.size() >= 32,
           "FUSE only support mount name shorter than 32 characters, but {} got.",
           fuseMount);

  fuseMountpoint = Path(mountPoint).lexically_normal();

  if (fuseConfig.remount_prefix()) {
    fuseRemountPref = Path(*fuseConfig.remount_prefix()).lexically_normal();
  }

  if (const char *env_p = std::getenv("HF3FS_FUSE_TOKEN")) {
    XLOGF(INFO, "Use token from env var");
    fuseToken = std::string(env_p);
  } else {
    XLOGF(INFO, "Use token from config");
    auto tokenRes = loadFile(tokenFile);
    RETURN_ON_ERROR(tokenRes);
    fuseToken = folly::trimWhitespace(*tokenRes);
  }
  enableWritebackCache = fuseConfig.enable_writeback_cache();
  memsetBeforeRead = fuseConfig.memset_before_read();
  maxIdleThreads = fuseConfig.max_idle_threads();
  int logicalCores = std::thread::hardware_concurrency();
  if (logicalCores != 0) {
    maxThreads = std::min(fuseConfig.max_threads(), (logicalCores + 1) / 2);
  } else {
    maxThreads = fuseConfig.max_threads();
  }
  bufPool = net::RDMABufPool::create(fuseConfig.io_bufs().max_buf_size(), fuseConfig.rdma_buf_pool_size());

  iovs.init(fuseRemountPref.value_or(fuseMountpoint), fuseConfig.iov_limit());
  iors.init(fuseConfig.iov_limit());
  userConfig.init(fuseConfig);

  if (!client) {
    client = std::make_unique<net::Client>(fuseConfig.client());
    RETURN_ON_ERROR(client->start());
  }
  auto ctxCreator = [this](net::Address addr) { return client->serdeCtx(addr); };
  if (!mgmtdClient) {
    mgmtdClient = std::make_shared<client::MgmtdClientForClient>(
        appInfo.clusterId,
        std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(ctxCreator),
        fuseConfig.mgmtd());
  }

  auto physicalHostnameRes = SysResource::hostname(/*physicalMachineName=*/true);
  RETURN_ON_ERROR(physicalHostnameRes);

  auto containerHostnameRes = SysResource::hostname(/*physicalMachineName=*/false);
  RETURN_ON_ERROR(containerHostnameRes);

  // Mgmtd's clientStart belongs to this process. Replicated file sessions and
  // reliable Storage updates must use the same registered process identity.
  auto clientId = ClientId::random(*physicalHostnameRes);
  if ((ecFileState && clientId.uuid == ecFileState->clientNamespace()) ||
      (ecSpool && clientId.uuid == ecSpool->clientNamespace()))
    return makeError(StatusCode::kInvalidArg, "process and durable EC client identities must differ");

  mgmtdClient->setClientSessionPayload({clientId.uuid.toHexString(),
                                        flat::NodeType::FUSE,
                                        flat::ClientSessionData::create(
                                            /*universalId=*/*physicalHostnameRes,
                                            /*description=*/fmt::format("fuse: {}", *containerHostnameRes),
                                            appInfo.serviceGroups,
                                            appInfo.releaseVersion),
                                        // TODO: use real user info
                                        flat::UserInfo{}});

  mgmtdClient->setConfigListener(ApplicationBase::updateConfig);

  folly::coro::blockingWait(mgmtdClient->start(&client->tpg().bgThreadPool().randomPick()));
  folly::coro::blockingWait(mgmtdClient->refreshRoutingInfo(/*force=*/false));
  RETURN_ON_ERROR(establishClientSession(*mgmtdClient));

  storageClient = storage::client::StorageClient::create(clientId, fuseConfig.storage(), *mgmtdClient);
  if (!storageClient) return makeError(StatusCode::kIOError, "failed to start process Storage client");

  metaClient =
      std::make_shared<meta::client::MetaClient>(clientId,
                                                 fuseConfig.meta(),
                                                 std::make_unique<meta::client::MetaClient::StubFactory>(ctxCreator),
                                                 mgmtdClient,
                                                 storageClient,
                                                 true /* dynStripe */);
  metaClient->start(client->tpg().bgThreadPool());
  if (ecFileState || ecSpool) {
    // Only EC managers receive this durable namespace. It is not a Mgmtd
    // process session and must not own legacy file sessions or reliable updates.
    auto ecClientId =
        ClientId(ecFileState ? ecFileState->clientNamespace() : ecSpool->clientNamespace(), *physicalHostnameRes);
    ecStorageClient = storage::client::StorageClient::create(ecClientId, fuseConfig.storage(), *mgmtdClient);
    if (!ecStorageClient) return makeError(StatusCode::kIOError, "failed to start durable EC Storage client");
    ecMetaClient =
        std::make_shared<meta::client::MetaClient>(ecClientId,
                                                   fuseConfig.meta(),
                                                   std::make_unique<meta::client::MetaClient::StubFactory>(ctxCreator),
                                                   mgmtdClient,
                                                   ecStorageClient,
                                                   true /* dynStripe */);
    ecMetaClient->start(client->tpg().bgThreadPool());
  }
  if (ecSpool) {
    client::ec::EcReadDispatcher::Limits limits{ecOperationTime,
                                                std::chrono::seconds(fuseConfig.ec_read().cleanup_attempt_seconds())};
    auto connected =
        client::ec::EcReadDispatcher::connect(ecSpool, ecMetaClient, ecStorageClient, mgmtdClient, *ecExecutor, limits);
    RETURN_ON_ERROR(connected);
    ecDispatcher = std::move(*connected);
    ecReads = std::make_shared<EcFuseReadAdapter>(ecDispatcher);
  }

  if (ecFileState) {
    ecRmw = std::make_shared<storage::client::EcRmwTransport>(fuseConfig.client());
    RETURN_ON_ERROR(ecRmw->start());
    auto mounted = EcFileMount::start(ecFileState,
                                      {ecMetaClient,
                                       ecStorageClient,
                                       mgmtdClient,
                                       ecRmw,
                                       [this](const flat::UserInfo &u) { return userConfig.getConfig(u).readonly(); }},
                                      flat::Token(fuseToken),
                                      std::chrono::seconds(fuseConfig.ec_file().maximum_operation_seconds()),
                                      ecStorageTransport);
    RETURN_ON_ERROR(mounted);
    ecFiles = std::move(*mounted);
    // Store the owner before recovery: all failure/exception exits reach the
    // same checked FuseClients::stop before session hooks or globals teardown.
    RETURN_ON_ERROR(folly::coro::blockingWait(ecFiles->recoverState()));
  }

  iojqs.reserve(3);
  iojqs.emplace_back(new BoundedQueue<IoRingJob>(fuseConfig.io_jobq_sizes().hi()));
  iojqs.emplace_back(new BoundedQueue<IoRingJob>(fuseConfig.io_jobq_size()));
  iojqs.emplace_back(new BoundedQueue<IoRingJob>(fuseConfig.io_jobq_sizes().lo()));

  jitter = fuseConfig.submit_wait_jitter();

  auto &tp = client->tpg().bgThreadPool();
  auto coros = fuseConfig.batch_io_coros();
  for (int i = 0; i < coros; ++i) {
    auto exec = &tp.get(i % tp.size());
    ioScope.add(co_withCancellation(cancelIos.getToken(), ioRingWorker(i, coros)).scheduleOn(exec));
  }

  ioWatches.reserve(3);
  for (int i = 0; i < 3; ++i) {
    ioWatches.emplace_back(folly::partial(&FuseClients::watch, this, i));
  }

  periodicSyncWorker = std::make_unique<CoroutinesPool<InodeId>>(config->periodic_sync().worker());
  periodicSyncWorker->start(folly::partial(&FuseClients::periodicSync, this), tp);

  periodicSyncRunner = std::make_unique<BackgroundRunner>(&tp.pickNextFree());
  periodicSyncRunner->start("PeriodSync", folly::partial(&FuseClients::periodicSyncScan, this), [&]() {
    return config->periodic_sync().interval() * folly::Random::randDouble(0.7, 1.3);
  });

  onFuseConfigUpdated = fuseConfig.addCallbackGuard([&fuseConfig = fuseConfig, this] {
    memsetBeforeRead = fuseConfig.memset_before_read();
    jitter = std::chrono::duration_cast<std::chrono::nanoseconds>(fuseConfig.submit_wait_jitter());
  });

  notifyInvalExec =
      std::make_unique<folly::IOThreadPoolExecutor>(fuseConfig.notify_inval_threads(),
                                                    std::make_shared<folly::NamedThreadFactory>("NotifyInvalThread"));

  return Void{};
}

Result<Void> FuseClients::stop() noexcept {
  if (fullyStopped) return Void{};
  try {
    onFuseConfigUpdated.reset();
    // Stop new claims first. Watchers may be blocked enqueueing an already
    // claimed batch; consumers must remain running until those watchers join.
    ioClaimsClosed.store(true);
    for (auto &t : ioWatches) t.request_stop();
    for (size_t i = 0; i != ioWatches.size(); ++i) sem_post(iors.sems[i].get());
    // Wake idle consumers into an all-queue drain before joining watchers.
    // They cannot exit while a watcher may still enqueue a claimed batch.
    ioStopping.store(true);
    cancelIos.requestCancellation();
    ioWatches.clear();
    ioWatchesJoined.store(true);
    if (!ioJoined) {
      if (ioJoinStarted) return makeError(StatusCode::kIOError);
      ioJoinStarted = true;
      folly::coro::blockingWait(folly::coro::co_withCancellation(CancellationToken{}, ioScope.joinAsync()));
      ioJoined = true;
    }
    if (periodicSyncRunner) {
      folly::coro::blockingWait(periodicSyncRunner->stopAll());
      periodicSyncRunner.reset();
    }
    if (periodicSyncWorker) {
      periodicSyncWorker->stopAndJoin();
      periodicSyncWorker.reset();
    }
    // Pending invalidations can access d.se, which the outer FUSE guard has
    // not yet destroyed. join drains them before session/config teardown.
    if (notifyInvalExec) {
      notifyInvalExec->join();
      notifyInvalExec.reset();
    }
    if (ecFiles) {
      RETURN_ON_ERROR(ecFiles->stop());
      if (!ecFiles->remoteCleanupComplete()) reportEcLocalMaintenanceFailure();
      ecFiles.reset();
    }
    if (ecRmw) {
      ecRmw->stopAndJoin();
      ecRmw.reset();
    }
    ecFileState.reset();
    if (ecDispatcher) {
      auto report = folly::coro::blockingWait(ecDispatcher->stop());
      if (!report.localJoined || !report.lowerJoinConfirmed) return makeError(StatusCode::kIOError);
      ecReads.reset();
      ecDispatcher.reset();
    }
    ecExecutor.reset();
    ecSpool.reset();
    // EC managers and all their local work have joined. Keep the shared routing
    // source, network and configuration alive until both client pairs stop.
    if (ecMetaClient) {
      ecMetaClient->stop();
      ecMetaClient.reset();
    }
    if (ecStorageClient) {
      ecStorageClient->stop();
      ecStorageClient.reset();
    }
    if (metaClient) {
      metaClient->stop();
      metaClient.reset();
    }
    if (storageClient) {
      storageClient->stop();
      storageClient.reset();
    }
    if (mgmtdClient) {
      folly::coro::blockingWait(mgmtdClient->stop());
      mgmtdClient.reset();
    }
    if (client) {
      client->stopAndJoin();
      client.reset();
    }
    fullyStopped = true;
    return Void{};
  } catch (...) {
    // No client/config/global destruction follows a failure at the application
    // boundary. The caller must execute the explicit top-level fail-stop path.
    return makeError(StatusCode::kIOError);
  }
}

client::ec::EcStripeControl FuseClients::ecControl() const {
  return {std::chrono::steady_clock::now() + ecOperationTime, cancelIos.getToken(), ecStorageTransport};
}
CoTask<void> FuseClients::retireDeliveredEcRead(client::ec::EcReadReceipt receipt, flat::UserInfo user, bool allT2) {
  if (!ecRetireCompleted || !allT2 || !ecDispatcher) co_return;
  // Invoked only after successful reply/CQE publication and payload destruction.
  // The original dispatcher rechecks current Query44 and every signed T2 tuple.
  const auto archive = ecArchiveDirectory / fmt::format("{}-{:020}-{}.json",
                                                        receipt.clientNamespace.toHexString(),
                                                        receipt.sequence,
                                                        receipt.rangeId.toHexString());
  auto retired = co_await ecDispatcher->retire(receipt, std::move(user), archive, ecControl());
  if (!retired)
    XLOGF(ERR,
          "EC local retirement pending: owner={} sequence={} range={} code={}",
          receipt.ownerUid,
          receipt.sequence,
          receipt.rangeId,
          retired.error().code());
}

CoTask<void> FuseClients::ioRingWorker(int i, int ths) {
  // a worker thread has its own priority, but it can also execute jobs from queues with a higher priority
  // checkHigher is used to make sure the job queue with the thread's own priority doesn't starve
  bool checkHigher = true;

  while (true) {
    bool drained = false;
    auto res = co_await folly::coro::co_awaitTry([this, &checkHigher, &drained, i, ths]() -> CoTask<void> {
      IoRingJob job;
      // EC scheduling uses the validated startup partition; a hot user option
      // cannot remove its only queue consumer. Closing drains all priorities.
      auto hiThs = (ecReads || ecFiles) ? ecHighWorkers : config->io_worker_coros().hi();
      auto loThs = (ecReads || ecFiles) ? ecLowWorkers : config->io_worker_coros().lo();
      auto prio = i < hiThs ? 0 : i < (ths - loThs) ? 1 : 2;
      if (ioStopping.load()) {
        bool found = false;
        for (auto &queue : iojqs) {
          if (auto queued = queue->try_dequeue()) {
            job = std::move(*queued);
            found = true;
            break;
          }
        }
        if (!found) {
          if (ioWatchesJoined.load())
            drained = true;
          else
            co_await folly::coro::co_withCancellation(CancellationToken{}, folly::coro::sleep(1_ms));
          co_return;
        }
      } else if (!config->enable_priority()) {
        job = co_await iojqs[prio]->co_dequeue();
      } else {
        bool gotJob = false;

        // if checkHigher, dequeue from a higher job queue if it is full
        while (!gotJob) {
          if (checkHigher) {
            for (int nprio = 0; nprio < prio; ++nprio) {
              if (iojqs[nprio]->full()) {
                auto dres = iojqs[nprio]->try_dequeue();
                if (dres) {
                  // got a job from higher priority queue, next time pick a same priority job unless the queue is empty
                  checkHigher = false;
                  gotJob = true;
                  job = std::move(*dres);
                  break;
                }
              }
            }

            if (gotJob) {
              break;
            }
          }

          // if checkHigher, check from higher prio to lower; otherwise, reverse the checking direction
          for (int nprio = checkHigher ? 0 : prio; checkHigher ? nprio <= prio : nprio >= 0;
               nprio += checkHigher ? 1 : -1) {
            auto [sres, dres] =
                co_await folly::coro::collectAnyNoDiscard(folly::coro::sleep(config->io_job_deq_timeout()),
                                                          iojqs[nprio]->co_dequeue());
            if (dres.hasValue()) {
              // if the job is the thread's own priority, next time it can check from higher priority queues
              if (!checkHigher && nprio == prio) {
                checkHigher = true;
              }
              gotJob = true;
              job = std::move(*dres);
              break;
            } else if (sres.hasValue()) {
              continue;
            } else {
              dres.throwUnlessValue();
            }
          }
        }
      }

      while (true) {
        auto lookupFiles =
            [this](std::vector<std::shared_ptr<RcInode>> &ins, const IoArgs *args, const IoSqe *sqes, int sqec) {
              auto lastIid = 0ull;

              std::lock_guard lock(inodesMutex);
              for (int i = 0; i < sqec; ++i) {
                auto idn = args[sqes[i].index].fileIid;
                if (i && idn == lastIid) {
                  ins.emplace_back(ins.back());
                  continue;
                }

                lastIid = idn;
                auto iid = meta::InodeId(idn);
                auto it = inodes.find(iid);
                ins.push_back(it == inodes.end() ? (std::shared_ptr<RcInode>()) : it->second);
              }
            };
        auto lookupBufs =
            [this](std::vector<Result<lib::ShmBufForIO>> &bufs, const IoArgs *args, const IoSqe *sqe, int sqec) {
              auto lastId = Uuid::zero();
              std::shared_ptr<lib::ShmBuf> lastShm;

              std::lock_guard lock(iovs.shmLock);
              for (int i = 0; i < sqec; ++i) {
                auto &arg = args[sqe[i].index];
                Uuid id;
                memcpy(id.data, arg.bufId, sizeof(id.data));

                std::shared_ptr<lib::ShmBuf> shm;
                if (i && id == lastId) {
                  shm = lastShm;
                } else {
                  auto it = iovs.shmsById.find(id);
                  if (it == iovs.shmsById.end()) {
                    bufs.emplace_back(makeError(StatusCode::kInvalidArg, "buf id not found"));
                    continue;
                  }

                  auto iovd = it->second;
                  shm = iovs.iovs->table[iovd].load();
                  if (!shm) {
                    bufs.emplace_back(makeError(StatusCode::kInvalidArg, "buf id not found"));
                    continue;
                  } else if (arg.bufOff > shm->size || arg.ioLen > shm->size - arg.bufOff) {
                    bufs.emplace_back(makeError(StatusCode::kInvalidArg, "invalid buf off and/or io len"));
                    continue;
                  }

                  lastId = id;
                  lastShm = shm;
                }

                if (arg.bufOff > shm->size || arg.ioLen > shm->size - arg.bufOff ||
                    arg.bufOff > uint64_t(std::numeric_limits<off_t>::max()) ||
                    arg.ioLen > uint64_t(std::numeric_limits<off_t>::max()) - arg.bufOff) {
                  bufs.emplace_back(makeError(StatusCode::kInvalidArg, "invalid bounded shared-memory slice"));
                  continue;
                }
                bufs.emplace_back(lib::ShmBufForIO(std::move(shm), arg.bufOff));
              }
            };

        co_await folly::coro::co_withCancellation(CancellationToken{},
                                                  job.ior->process(job.sqeProcTail,
                                                                   job.toProc,
                                                                   *storageClient,
                                                                   config->storage_io(),
                                                                   userConfig,
                                                                   std::move(lookupFiles),
                                                                   std::move(lookupBufs)));
        if (ioClaimsClosed.load()) break;

        if (iojqs[0]->full() || job.ior->priority != prio) {
          sem_post(iors.sems[job.ior->priority].get());  // wake the watchers
        } else {
          auto jobs = job.ior->jobsToProc(1);
          if (!jobs.empty()) {
            job = jobs.front();
            if (!iojqs[0]->try_enqueue(job)) {
              continue;
            }
          }
        }

        break;
      }
    }());
    if (UNLIKELY(res.hasException())) {
      XLOGF(INFO, "io worker #{} cancelled", i);
      if (res.hasException<OperationCancelled>()) {
        if (ioStopping.load()) continue;
        break;
      } else {
        XLOGF(FATAL, "got exception in io worker #{}", i);
      }
    }
    if (drained) break;
  }
}

void FuseClients::watch(int prio, std::stop_token stop) {
  while (!stop.stop_requested()) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
      continue;
    }

    auto nsec = ts.tv_nsec + jitter.load().count();
    ts.tv_nsec = nsec % 1000000000;
    ts.tv_sec += nsec / 1000000000;
    if (sem_timedwait(iors.sems[prio].get(), &ts) < 0 && errno == ETIMEDOUT) {
      continue;
    }

    auto gotJobs = false;
    do {
      gotJobs = false;

      auto n = iors.ioRings->slots.nextAvail.load();
      for (int i = 0; i < n && !stop.stop_requested() && !ioClaimsClosed.load(); ++i) {
        auto ior = iors.ioRings->table[i].load();

        if (ior && ior->priority == prio) {
          auto jobs = ior->jobsToProc(config->max_jobs_per_ioring());
          for (auto &&job : jobs) {
            gotJobs = true;
            iojqs[prio]->enqueue(std::move(job));
          }
        }
      }
    } while (gotJobs && !stop.stop_requested() && !ioClaimsClosed.load());
  }
}

CoTask<void> FuseClients::periodicSyncScan() {
  if (!config->periodic_sync().enable() || config->readonly()) {
    co_return;
  }

  XLOGF(INFO, "periodicSyncScan run");
  std::set<InodeId> dirty;
  {
    auto guard = dirtyInodes.lock();
    auto limit = config->periodic_sync().limit();
    dirtyInodesCnt.set(guard->size());
    if (guard->size() <= limit) {
      dirty = std::exchange(*guard, {});
    } else {
      XLOGF(WARN, "dirty inodes {} > limit {}", guard->size(), limit);
      auto iter = guard->find(lastSynced);
      while (dirty.size() < limit) {
        if (iter == guard->end()) {
          iter = guard->begin();
          XLOGF_IF(FATAL, iter == guard->end(), "iter == guard->end() shouldn't happen");
        } else {
          auto inode = *iter;
          lastSynced = inode;
          iter = guard->erase(iter);
          dirty.insert(inode);
        }
      }
    }
  }

  for (auto inode : dirty) {
    co_await periodicSyncWorker->enqueue(inode);
  }

  co_return;
}

}  // namespace hf3fs::fuse
