#pragma once

#include "client/cli/common/Dispatcher.h"

namespace hf3fs::client::cli {
CoTryTask<void> registerEcRevisionRetirementHandlers(Dispatcher &);
}  // namespace hf3fs::client::cli
