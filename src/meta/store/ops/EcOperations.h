#pragma once

#include <memory>

#include "fbs/meta/Service.h"

namespace hf3fs::meta::server {
class EcPublishEvidence;
class EcCoordinator;

struct EcBeginContext : BeginEcMutationReq {
  // Reads only the in-memory routing snapshot; never performs network I/O.
  const EcCoordinator *coordinator = nullptr;
};

// The extra evidence is deliberately not part of ReqBase's wire fields.
struct EcPublishCommit : PublishEcMutationReq {
  std::shared_ptr<const EcPublishEvidence> evidence;
};
}  // namespace hf3fs::meta::server
