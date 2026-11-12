#include "IoRing.h"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <type_traits>
#include <utility>

#include "PioV.h"
#include "common/utils/UtcTime.h"
#include "fbs/meta/Schema.h"
#include "fuse/FuseClients.h"
#include "fuse/FuseOps.h"
#include "lib/api/hf3fs_usrbio.h"

namespace hf3fs::fuse {
std::vector<IoRingJob> IoRing::jobsToProc(int maxJobs) {
  std::vector<IoRingJob> jobs;

  std::lock_guard lock(cqeMtx_);
  auto spt = sqeProcTail_;
  auto sqes = sqeCount();

  auto cqeAvail = entries - 1 - processing_ - cqeCount();
  while (sqes && (int)jobs.size() < maxJobs) {
    int toProc;
    if (ioDepth > 0) {
      toProc = ioDepth;
      if (toProc > sqes || toProc > cqeAvail) {  // even if we finish the io, we got no place to store the results
        break;
      }
    } else {
      toProc = std::min(sqes, cqeAvail);
      if (ioDepth < 0) {
        auto iod = -ioDepth;
        if (toProc > iod) {
          toProc = iod;
        } else if (toProc < iod && timeout.count()) {
          auto now = SteadyClock::now();
          if (!lastCheck_) {  // first time to find the (not enough) ios, wait till timeout
            lastCheck_ = now;
            break;
          } else if (*lastCheck_ + timeout > now) {  // ios not enough to fill a batch, and time has not run out
            break;
          }
        }

        lastCheck_ = std::nullopt;
      }
    }

    if (jobs.empty()) {
      jobs.reserve(ioDepth ? std::min(maxJobs, sqes / abs(ioDepth) + 1) : 1);
    }

    jobs.emplace_back(IoRingJob{shared_from_this(), spt, toProc});

    spt = (spt + toProc) % entries;
    sqeProcTails_.push_back(spt);
    processing_ += toProc;
    sqes -= toProc;
    cqeAvail -= toProc;
  }

  sqeProcTail_ = spt;
  return jobs;
}

CoTask<void> IoRing::process(
    int spt,
    int toProc,
    storage::client::StorageClient &storageClient,
    const storage::client::IoOptions &storageIo,
    UserConfig &userConfig,
    std::function<void(std::vector<std::shared_ptr<RcInode>> &, const IoArgs *, const IoSqe *, int)> &&lookupFiles,
    std::function<void(std::vector<Result<lib::ShmBufForIO>> &, const IoArgs *, const IoSqe *, int)> &&lookupBufs) {
  static monitor::LatencyRecorder overallLatency("usrbio.piov.overall", monitor::TagSet{{"mount_name", mountName}});
  static monitor::LatencyRecorder prepareLatency("usrbio.piov.prepare", monitor::TagSet{{"mount_name", mountName}});
  static monitor::LatencyRecorder submitLatency("usrbio.piov.submit", monitor::TagSet{{"mount_name", mountName}});
  static monitor::LatencyRecorder completeLatency("usrbio.piov.complete", monitor::TagSet{{"mount_name", mountName}});
  static monitor::DistributionRecorder ioSizeDist("usrbio.piov.io_size", monitor::TagSet{{"mount_name", mountName}});
  static monitor::DistributionRecorder ioDepthDist("usrbio.piov.io_depth", monitor::TagSet{{"mount_name", mountName}});
  static monitor::DistributionRecorder totalBytesDist("usrbio.piov.total_bytes",
                                                      monitor::TagSet{{"mount_name", mountName}});
  static monitor::DistributionRecorder distinctFilesDist("usrbio.piov.distinct_files",
                                                         monitor::TagSet{{"mount_name", mountName}});
  static monitor::DistributionRecorder distinctBufsDist("usrbio.piov.distinct_bufs",
                                                        monitor::TagSet{{"mount_name", mountName}});
  static monitor::CountRecorder bwCount("usrbio.piov.bw", monitor::TagSet{{"mount_name", mountName}});

  auto start = SteadyClock::now(), overallStart = start;
  std::string ioType = forRead_ ? "read" : "write";
  auto uids = std::to_string(userInfo_.uid.toUnderType());

  auto &config = userConfig.getConfig(userInfo_);

  // Snapshot each claimed SQE/argument once before any await. No later access
  // to caller-mutable ring parameters may expand a validated buffer or extent.
  std::vector<IoSqe> sqes(toProc), lookupSqes(toProc);
  std::vector<IoArgs> arguments(toProc);
  std::vector<bool> validIndex(toProc, false);
  for (int i = 0; i != toProc; ++i) {
    sqes[i] = sqeSection[(spt + i) % entries];
    validIndex[i] = sqes[i].index >= 0 && sqes[i].index < entries - 1;
    if (validIndex[i]) arguments[i] = ringSection[sqes[i].index];
    lookupSqes[i] = IoSqe{i, sqes[i].userdata};
  }
  std::vector<ssize_t> res;
  std::vector<std::optional<client::ec::EcReadReceipt>> deliveredEc(toProc);
  if (!forRead_ && config.readonly()) {
    res = std::vector<ssize_t>(toProc, static_cast<ssize_t>(-StatusCode::kReadOnlyMode));
  } else {
    res = std::vector<ssize_t>(toProc, 0);

    size_t iod = 0, totalBytes = 0;
    std::set<uint64_t> distinctFiles;
    std::set<Uuid> distinctBufs;

    std::vector<std::shared_ptr<RcInode>> inodes;
    inodes.reserve(toProc);
    lookupFiles(inodes, arguments.data(), lookupSqes.data(), toProc);

    std::vector<Result<lib::ShmBufForIO>> bufs;
    bufs.reserve(toProc);
    lookupBufs(bufs, arguments.data(), lookupSqes.data(), toProc);

    lib::agent::PioV ioExec(storageClient, config.chunk_size_limit(), res);
    std::vector<bool> replicated(toProc, false);
    std::vector<uint64_t> truncateVers;
    if (!forRead_) {
      truncateVers.resize(toProc, 0);
    }

    for (int i = 0; i < toProc; ++i) {
      if (!validIndex[i]) {
        res[i] = -static_cast<ssize_t>(StatusCode::kInvalidArg);
        continue;
      }
      const auto &args = arguments[i];

      ++iod;
      totalBytes += args.ioLen;
      distinctFiles.insert(args.fileIid);

      Uuid id;
      memcpy(id.data, args.bufId, sizeof(id.data));
      distinctBufs.insert(id);

      ioSizeDist.addSample(args.ioLen, monitor::TagSet{{"io", ioType}, {"uid", uids}});

      if (!inodes[i]) {
        res[i] = -static_cast<ssize_t>(MetaCode::kNotFile);
        continue;
      }

      if (!bufs[i]) {
        res[i] = -static_cast<ssize_t>(bufs[i].error().code());
        continue;
      }

      if (inodes[i]->inode.isFile() && inodes[i]->inode.asFile().layout.isErasureCoded()) {
        auto &clients = getFuseClientsInstance();
        if (clients.ecFiles) {
          if (flags_ & HF3FS_IOR_ALLOW_READ_UNCOMMITTED) {
            res[i] = -static_cast<ssize_t>(StatusCode::kNotImplemented);
            continue;
          }
          try {
            auto opened = co_await clients.ecFiles->open(inodes[i]->inode, userInfo_, forRead_ ? O_RDONLY : O_WRONLY);
            if (!opened) {
              res[i] = -static_cast<ssize_t>(opened.error().code());
              continue;
            }
            if (forRead_) {
              auto read = co_await clients.ecFiles->read(opened->handle, userInfo_, args.fileOff, args.ioLen, false);
              if (!read)
                res[i] = -static_cast<ssize_t>(read.error().code());
              else if (read->data.size() > args.ioLen)
                res[i] = -static_cast<ssize_t>(StatusCode::kDataCorruption);
              else {
                if (read->data.size()) std::memcpy(bufs[i]->ptr(), read->data.bytes().data(), read->data.size());
                res[i] = static_cast<ssize_t>(read->data.size());
                inodes[i]->dynamicAttr.wlock()->ecObservedLength = read->length;
              }
              // Payload is destroyed here, after copy to the owned ring's Shm
              // lease; the worker never receives the Shm pointer or SQE.
            } else {
              auto written =
                  co_await clients.ecFiles->write(opened->handle,
                                                  userInfo_,
                                                  args.fileOff,
                                                  {reinterpret_cast<const uint8_t *>(bufs[i]->ptr()), args.ioLen});
              res[i] = written ? static_cast<ssize_t>(*written) : -static_cast<ssize_t>(written.error().code());
              if (written) inodes[i]->dynamicAttr.wlock()->ecObservedLength.reset();
            }
            auto closed = co_await clients.ecFiles->release(opened->handle, userInfo_);
            if (!closed) reportEcLocalMaintenanceFailure();  // Result bytes remain valid; debt remains durable.
          } catch (...) {
            res[i] = -static_cast<ssize_t>(StatusCode::kIOError);
          }
          continue;
        }
        if (!forRead_ || !clients.ecReads || (flags_ & HF3FS_IOR_ALLOW_READ_UNCOMMITTED)) {
          res[i] = -static_cast<ssize_t>(StatusCode::kNotImplemented);
          continue;
        }
        try {
          auto opened = co_await clients.ecReads->open(inodes[i]->inode, userInfo_, O_RDONLY, clients.ecControl());
          if (!opened) {
            res[i] = -static_cast<ssize_t>(opened.error().code());
            continue;
          }
          auto read = co_await clients.ecReads
                          ->read(std::move(*opened), userInfo_, args.fileOff, args.ioLen, false, clients.ecControl());
          if (!read) {
            res[i] = -static_cast<ssize_t>(read.error().code());
            continue;
          }
          if (!read->localJoined || !read->data) {
            res[i] = -static_cast<ssize_t>(read->readFailure ? read->readFailure->code() : StatusCode::kIOError);
            continue;
          }
          const auto bytes = read->data->bytes();
          if (bytes.size() > args.ioLen) {
            res[i] = -static_cast<ssize_t>(StatusCode::kDataCorruption);
            continue;
          }
          if (!bytes.empty()) std::memcpy(bufs[i]->ptr(), bytes.data(), bytes.size());
          inodes[i]->dynamicAttr.wlock()->ecObservedLength = read->data->snapshot().file.length;
          res[i] = static_cast<ssize_t>(bytes.size());
          if (read->cleanup.localJoined && read->cleanup.allReleased) deliveredEc[i] = read->receipt;
          read->data.reset();  // Before CQE and any local retirement; no borrowed buffer enters F5.
        } catch (...) {
          res[i] = -static_cast<ssize_t>(StatusCode::kIOError);
        }
        continue;
      }
      // Only the replicated PioV path needs a registered Storage IOBuffer.
      // EC data is an owned CPU payload copied to the already bounded ShmBuf.
      auto memh = co_await bufs[i]->memh(args.ioLen);
      if (!memh) {
        res[i] = -static_cast<ssize_t>(memh.error().code());
        continue;
      } else if (!bufs[i]->ptr() || !*memh) {
        XLOGF(ERR, "{} is null when doing usrbio", *memh ? "buf ptr" : "memh");
        res[i] = -static_cast<ssize_t>(ClientAgentCode::kIovShmFail);
        continue;
      }

      replicated[i] = true;
      if (!forRead_) {
        auto beginWrite =
            co_await inodes[i]->beginWrite(userInfo_, *getFuseClientsInstance().metaClient, args.fileOff, args.ioLen);
        if (beginWrite.hasError()) {
          res[i] = -static_cast<ssize_t>(beginWrite.error().code());
          continue;
        }
        truncateVers[i] = *beginWrite;
      }

      auto addRes = forRead_
                        ? ioExec.addRead(i, inodes[i]->inode, 0, args.fileOff, args.ioLen, bufs[i]->ptr(), **memh)
                        : ioExec.addWrite(i, inodes[i]->inode, 0, args.fileOff, args.ioLen, bufs[i]->ptr(), **memh);
      if (!addRes) {
        res[i] = -static_cast<ssize_t>(addRes.error().code());
      }
    }

    auto now = SteadyClock::now();
    prepareLatency.addSample(now - start, monitor::TagSet{{"io", ioType}, {"uid", uids}});
    start = now;

    ioDepthDist.addSample(iod, monitor::TagSet{{"io", ioType}, {"uid", uids}});
    totalBytesDist.addSample(totalBytes, monitor::TagSet{{"io", ioType}, {"uid", uids}});
    distinctFilesDist.addSample(distinctFiles.size(), monitor::TagSet{{"io", ioType}, {"uid", uids}});
    distinctBufsDist.addSample(distinctBufs.size(), monitor::TagSet{{"io", ioType}, {"uid", uids}});

    auto readOpt = storageIo.read();
    if (flags_ & HF3FS_IOR_ALLOW_READ_UNCOMMITTED) {
      readOpt.set_allowReadUncommitted(true);
    }
    Result<Void> execRes = Void{};
    if (std::any_of(replicated.begin(), replicated.end(), [](bool value) { return value; })) {
      execRes = co_await (forRead_ ? ioExec.executeRead(userInfo_, readOpt)
                                   : ioExec.executeWrite(userInfo_, storageIo.write()));
    }

    now = SteadyClock::now();
    submitLatency.addSample(now - start, monitor::TagSet{{"io", ioType}, {"uid", uids}});
    start = now;

    if (!execRes) {
      for (size_t i = 0; i != res.size(); ++i) {
        if (replicated[i] && res[i] >= 0) res[i] = -static_cast<ssize_t>(execRes.error().code());
      }
    } else {
      ioExec.finishIo(!(flags_ & HF3FS_IOR_FORBID_READ_HOLES));
    }

    if (!forRead_) {
      for (int i = 0; i < toProc; ++i) {
        auto &inode = inodes[i];
        if (!inode || !replicated[i]) {
          continue;
        }
        auto off = arguments[i].fileOff;
        auto r = res[i];
        inode->finishWrite(userInfo_.uid, truncateVers[i], off, r);
      }
    }
  }

  auto newSpt = (spt + toProc) % entries;

  {
    // lock for between threads (io workers)
    // atomics for between processes (io worker & io generator)
    std::lock_guard lock(cqeMtx_);
    if (sqeProcTails_.empty()) {
      XLOGF(FATAL, "bug?! sqeProcTails_ is empty");
    }

    if (sqeProcTails_.front() != newSpt) {
      sqeDoneTails_.insert(newSpt);
    } else {
      sqeTail = newSpt;
      sqeProcTails_.pop_front();
      while (!sqeDoneTails_.empty()) {
        if (sqeProcTails_.empty()) {
          XLOGF(FATAL, "bug?! sqeProcTails_ is empty");
        }
        auto first = sqeProcTails_.front();
        auto it = sqeDoneTails_.find(first);
        if (it == sqeDoneTails_.end()) {
          break;
        } else {
          sqeTail = first;
          sqeProcTails_.pop_front();
          sqeDoneTails_.erase(it);
        }
      }
    }

    for (int i = 0; i < toProc; ++i) {
      auto &sqe = sqes[i];
      auto r = res[i];
      auto addRes = addCqe(sqe.index, r >= 0 ? r : -static_cast<ssize_t>(StatusCode::toErrno(-r)), sqe.userdata);
      if (!addRes) {
        XLOGF(FATAL, "failed to add cqe");
      }
    }

    processing_ -= toProc;
  }

  sem_post(cqeSem.get());

  // CQEs have been published and the registered buffers are no longer touched.
  // Maintenance is still owned by this ring worker and joined during shutdown.
  for (const auto &receipt : deliveredEc) {
    if (!receipt) continue;
    try {
      co_await getFuseClientsInstance().retireDeliveredEcRead(*receipt, userInfo_, true);
    } catch (...) {
      reportEcLocalMaintenanceFailure();
    }
  }

  size_t doneBytes = 0;
  for (auto r : res) {
    if (r > 0) {
      doneBytes += r;
    }
  }
  bwCount.addSample(doneBytes, monitor::TagSet{{"io", ioType}, {"uid", uids}});

  auto now = SteadyClock::now();
  completeLatency.addSample(now - start, monitor::TagSet{{"io", ioType}, {"uid", uids}});
  overallLatency.addSample(now - overallStart, monitor::TagSet{{"io", ioType}, {"uid", uids}});
}
}  // namespace hf3fs::fuse
