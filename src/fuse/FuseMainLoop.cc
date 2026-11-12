#include "FuseMainLoop.h"

#include <cstdlib>
#include <folly/ScopeGuard.h>
#include <folly/logging/xlog.h>
#include <unistd.h>

#include "FuseOps.h"

namespace hf3fs::fuse {
void checkedFuseShutdownOrExit(FuseClients &clients) noexcept {
  try {
    if (clients.stop()) return;
  } catch (...) {
    // The boundary remains nonthrowing even if a later implementation changes
    // the stop signature. No formatting/allocation is needed to report failure.
  }
  constexpr char message[] =
      "3FS FUSE shutdown did not confirm local joins; preserve the configured EC spool; "
      "terminating with failure before session/config/global teardown.\n";
  (void)::write(STDERR_FILENO, message, sizeof(message) - 1);
  std::_Exit(EXIT_FAILURE);
}

void checkedFuseShutdownOrExit() noexcept { checkedFuseShutdownOrExit(getFuseClientsInstance()); }

int fuseMainLoop(const String &programName,
                 bool allowOther,
                 const String &mountpoint,
                 size_t maxbufsize,
                 const String &clusterId) {
  auto &d = getFuseClientsInstance();
  const auto &ops = getFuseOps();

  // Resource state precedes both guards. No push_back/std::function allocation
  // may strand a session after an acquisition, and no hook borrows a later local.
  struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
  struct fuse_cmdline_opts opts {};
  fuse_session *session = nullptr;
  bool signalsInstalled = false, mounted = false;
  auto sessionCleanup = folly::makeGuard([&]() noexcept {
    if (mounted) fuse_session_unmount(session);
    if (signalsInstalled) fuse_remove_signal_handlers(session);
    if (session) fuse_session_destroy(session);
    d.se = nullptr;
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
  });
  // Declared after the session hook guard, hence executed before all hooks on
  // every return/exception. This also precedes ApplicationBase::memory shutdown.
  auto checkedShutdown = folly::makeGuard([]() noexcept { checkedFuseShutdownOrExit(); });

  std::vector<std::string> fuseArgs;
  fuseArgs.push_back(programName);
  if (allowOther) {
    fuseArgs.push_back("-o");
    fuseArgs.push_back("allow_other");
    fuseArgs.push_back("-o");
    fuseArgs.push_back("default_permissions");
  }
  fuseArgs.push_back("-o");
  fuseArgs.push_back("auto_unmount");
  fuseArgs.push_back("-o");
  fuseArgs.push_back(fmt::format("max_read={}", maxbufsize));
  fuseArgs.push_back(mountpoint);
  fuseArgs.push_back("-o");
  fuseArgs.push_back("subtype=hf3fs");
  fuseArgs.push_back("-o");
  fuseArgs.push_back("fsname=hf3fs." + clusterId);
  std::vector<char *> fuseArgsPtr;
  for (auto &arg : fuseArgs) {
    fuseArgsPtr.push_back(const_cast<char *>(arg.c_str()));
  }

  args = FUSE_ARGS_INIT((int)fuseArgsPtr.size(), fuseArgsPtr.data());
  struct fuse_loop_config *config = fuse_loop_cfg_create();
  SCOPE_EXIT { fuse_loop_cfg_destroy(config); };

  if (fuse_parse_cmdline(&args, &opts) != 0) {
    return 1;
  }

  if (opts.show_help) {
    printf("This is hf3fs fuse!\n");
    fuse_cmdline_help();
    fuse_lowlevel_help();
    return 0;
  } else if (opts.show_version) {
    printf("What's my version?\n");
    fuse_lowlevel_version();
    return 0;
  }

  if (opts.mountpoint == nullptr) {
    printf("No mountpoint.\n");
    return 1;
  }

  d.se = fuse_session_new(&args, &ops, sizeof(ops), NULL);
  if (d.se == nullptr) {
    return 1;
  }
  session = d.se;

  if (fuse_set_signal_handlers(d.se) != 0) {
    return 1;
  }
  signalsInstalled = true;

  if (fuse_session_mount(d.se, opts.mountpoint) != 0) {
    return 1;
  }

  mounted = true;

  int ret = -1;
  if (opts.singlethread) {
    ret = fuse_session_loop(d.se);
  } else {
    fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
    fuse_loop_cfg_set_idle_threads(config, d.maxIdleThreads);
    fuse_loop_cfg_set_max_threads(config, d.maxThreads);
    ret = fuse_session_loop_mt(d.se, config);
  }

  return ret ? 1 : 0;
}
}  // namespace hf3fs::fuse
