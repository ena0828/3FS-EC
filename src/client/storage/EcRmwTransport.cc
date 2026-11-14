#include "EcRmwTransport.h"

#include <type_traits>

#include <folly/experimental/coro/WithCancellation.h>

#include "common/serde/ClientContext.h"
#include "fbs/meta/Service.h"
#include "fbs/storage/Service.h"

namespace hf3fs::storage::client {
namespace {
Result<Void> ready(const net::Address &a, const EcRequestControl &c, bool metaControl) {
  const bool matching = c.transport == EcRequestControl::TransportPolicy::TcpOnly
                            ? a.type == net::Address::TCP
                            : c.transport == EcRequestControl::TransportPolicy::RdmaOnly &&
                                  a.type == net::Address::RDMA && !metaControl;
  if (!matching ||
      c.deadline == std::chrono::steady_clock::time_point::max())
    return makeError(StatusCode::kInvalidArg);
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  if (c.deadline - std::chrono::steady_clock::now() > std::chrono::seconds(300))
    return makeError(StatusCode::kInvalidArg);
  return Void{};
}
Status normalized(Status error, bool unknown) {
  if (unknown) return error.convert(StorageCode::kEcSealOutcomeUnknown);
  if (error.code() == RPCCode::kTimeout) return error.convert(StorageClientCode::kTimeout);
  return error;
}
}  // namespace
template <class Req, class Rsp, auto Method>
CoTryTask<Rsp> EcRmwTransport::call(std::shared_ptr<EcRmwTransport> self,
                                    net::Address address,
                                    Req request,
                                    EcRequestControl control,
                                    bool irreversible) {
  bool dispatched = false;
  try {
    auto checked = ready(address, control, std::is_same_v<Req, meta::BindEcRmwOutputReq>);
    if (!checked) co_return makeError(std::move(checked.error()));
    const auto remaining = control.deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero()) co_return makeError(StorageClientCode::kTimeout);
    net::UserRequestOptions options;
    options.timeout = Duration(remaining);
    options.sendRetryTimes = 0;
    options.requireRdma = address.type == net::Address::RDMA;
    auto context = self->client_.serdeCtx(address);
    dispatched = true;
    // Native finite Waiter completes before the frame/request/control dies.
    // Cancellation cannot abandon a borrowed request or falsely report drain.
    auto result = co_await folly::coro::co_withCancellation({}, Method(context, request, &options, nullptr));
    if (!result) co_return makeError(normalized(std::move(result.error()), irreversible));
    checked = ready(address, control, std::is_same_v<Req, meta::BindEcRmwOutputReq>);
    if (!checked) co_return makeError(normalized(std::move(checked.error()), irreversible));
    co_return std::move(*result);
  } catch (const std::bad_alloc &) {
    co_return makeError(dispatched && irreversible ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(dispatched && irreversible ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
template <class Req, auto Method>
CoTryTask<EcRmwStatus> EcRmwTransport::status(std::shared_ptr<EcRmwTransport> self,
                                              net::Address a,
                                              Req request,
                                              EcRequestControl control,
                                              Uuid id,
                                              EcSha256 digest,
                                              bool irreversible) {
  auto result = co_await call<Req, EcRmwStatusRsp, Method>(std::move(self),
                                                           a,
                                                           std::move(request),
                                                           std::move(control),
                                                           irreversible);
  if (!result) co_return makeError(std::move(result.error()));
  if (!result->result) co_return makeError(std::move(result->result.error()));
  if (result->result->planId != id || result->result->planDigest != digest)
    co_return makeError(irreversible ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kTokenMismatch);
  co_return std::move(*result->result);
}
CoTryTask<EcRmwStatus> EcRmwTransport::install(net::Address a, EcRmwInstallReq request, EcRequestControl control) {
  const auto id = request.plan.input.planId;
  const auto digest = request.grant.claims.planDigest;
  return status<EcRmwInstallReq, StorageSerde<>::installEcRmw<serde::ClientContext>>(shared_from_this(),
                                                                                     a,
                                                                                     std::move(request),
                                                                                     std::move(control),
                                                                                     id,
                                                                                     digest,
                                                                                     false);
}
CoTryTask<EcRmwStatus> EcRmwTransport::put(net::Address a, EcRmwPutReq request, EcRequestControl control) {
  const auto id = request.planId;
  const auto digest = request.grant.claims.planDigest;
  return status<EcRmwPutReq, StorageSerde<>::putEcRmw<serde::ClientContext>>(shared_from_this(),
                                                                             a,
                                                                             std::move(request),
                                                                             std::move(control),
                                                                             id,
                                                                             digest,
                                                                             false);
}
CoTryTask<EcRmwStatus> EcRmwTransport::action(net::Address a, EcRmwActionReq request, EcRequestControl control) {
  const auto id = request.planId;
  const auto digest = request.grant.claims.planDigest;
  const bool submit = request.action == EcRmwActionRequest::Submit;
  return status<EcRmwActionReq, StorageSerde<>::actionEcRmw<serde::ClientContext>>(shared_from_this(),
                                                                                   a,
                                                                                   std::move(request),
                                                                                   std::move(control),
                                                                                   id,
                                                                                   digest,
                                                                                   submit);
}
CoTryTask<meta::BindEcRmwOutputRsp> EcRmwTransport::bind(net::Address a,
                                                         meta::BindEcRmwOutputReq request,
                                                         EcRequestControl control) {
  return call<meta::BindEcRmwOutputReq,
              meta::BindEcRmwOutputRsp,
              meta::MetaSerde<>::bindEcRmwOutput<serde::ClientContext>>(shared_from_this(),
                                                                        a,
                                                                        std::move(request),
                                                                        std::move(control),
                                                                        true);
}
}  // namespace hf3fs::storage::client
