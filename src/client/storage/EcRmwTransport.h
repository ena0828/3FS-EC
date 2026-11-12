#pragma once

#include "client/storage/EcRequestControl.h"
#include "common/net/Client.h"
#include "fbs/meta/EcRmw.h"

namespace hf3fs::storage::client {
// Dedicated real serde transport shared by Meta, Storage's internal binder,
// and the ordinary patch client. No callback can synthesize an RPC result.
// Config and network runtime outlive all owned calls; stop after callers join.
class EcRmwTransport final : public std::enable_shared_from_this<EcRmwTransport> {
 public:
  explicit EcRmwTransport(const net::Client::Config &config)
      : client_(config) {}
  Result<Void> start() { return client_.start("EcRmwTransport"); }
  void stopAndJoin() { client_.stopAndJoin(); }
  CoTryTask<EcRmwStatus> install(net::Address, EcRmwInstallReq, EcRequestControl);
  CoTryTask<EcRmwStatus> put(net::Address, EcRmwPutReq, EcRequestControl);
  CoTryTask<EcRmwStatus> action(net::Address, EcRmwActionReq, EcRequestControl);
  CoTryTask<meta::BindEcRmwOutputRsp> bind(net::Address, meta::BindEcRmwOutputReq, EcRequestControl);

 private:
  template <class Req, class Rsp, auto Method>
  static CoTryTask<Rsp> call(std::shared_ptr<EcRmwTransport>, net::Address, Req, EcRequestControl, bool irreversible);
  template <class Req, auto Method>
  static CoTryTask<EcRmwStatus>
  status(std::shared_ptr<EcRmwTransport>, net::Address, Req, EcRequestControl, Uuid, EcSha256, bool);
  net::Client client_;
};
}  // namespace hf3fs::storage::client
