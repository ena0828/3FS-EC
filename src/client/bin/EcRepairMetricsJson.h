#pragma once

#include <folly/json.h>
#include <string>

#include "client/ec/EcRepairObservation.h"

namespace hf3fs::client::ec {

// Best-effort rendering is separated from required business JSON. If any
// telemetry allocation/formatting fails, emit the already-rendered business
// result plus literal unavailable fields, without changing its exit status.
inline std::string repairMetricsJson(const EcRepairSample &m) {
  folly::dynamic out = folly::dynamic::object("schema", 1)("scope", "this_call")(
      "action", unsigned(m.action))("journal_state_observed", m.journalStateObserved)("had_journal_state", m.hadJournalState)(
      "prior_journal_sequence_decimal", std::to_string(m.priorJournalSequence))(
      "elapsed_ns_decimal", std::to_string(m.elapsedNs))("configured_window", unsigned(m.configuredWindow))(
      "block_actors_applicable", m.blockActorsApplicable)("cancellation_requested", m.cancellationRequested)(
      "deadline_expired", m.deadlineExpired)("overflow", m.overflow)("clock_anomaly", m.clockAnomaly)(
      "wire_bytes", nullptr)("rpc_encoded_bytes", nullptr)("transport_retry_attempts", nullptr)(
      "server_queue_depth", nullptr)("persisted_in_business_journal", false)(
      "codec_scope", "local wall spans include validation; not pure arithmetic CPU time")(
      "helper_server_compute", nullptr)("points", folly::dynamic::object());
  for (size_t n = 0; n != m.points.size(); ++n) {
    const auto &p = m.points[n];
    out["points"][kEcRepairPointNames[n]] = folly::dynamic::object(
        "entered_decimal", std::to_string(p.entered))("finished_decimal", std::to_string(p.finished))(
        "succeeded_decimal", std::to_string(p.succeeded))("span_ns_decimal", std::to_string(p.spanNs))(
        "active_decimal", std::to_string(p.active))("peak_active_decimal", std::to_string(p.peakActive))(
        "api_invocations_decimal", std::to_string(p.apiInvocations))(
        "submitted_payload_bytes_decimal", std::to_string(p.submittedPayloadBytes))(
        "validated_returned_payload_bytes_decimal", std::to_string(p.validatedReturnedPayloadBytes));
  }
  const auto clockSample = [](const storage::client::EcRpcClockSample &sample,
                              const std::array<const char *, 3> &names) {
    folly::dynamic value = folly::dynamic::object("valid_samples_decimal", std::to_string(sample.valid))(
        "missing_or_nonpositive_samples_decimal", std::to_string(sample.missing))(
        "reversed_samples_decimal", std::to_string(sample.reversed))(
        "out_of_range_samples_decimal", std::to_string(sample.outOfRange));
    for (size_t i = 0; i != names.size(); ++i) value[names[i]] = std::to_string(sample.spanNs[i]);
    return value;
  };
  folly::dynamic rpc = folly::dynamic::object("schema", 1)("coverage", "controlled_client_to_storage_first_hop")(
      "clock", "per_host_utc_microseconds_checked_then_ns")("missing_samples_are_censored", true)(
      "frame_counts_are_not_dispatch_counts", true)("outer_ok_is_not_business_success", true)(
      "messenger_invocations_are_not_dispatch_or_retry_counts", true)(
      "spans_overlap_and_are_not_total_wall_time", true)(
      "limiter_clock", "steady_clock")(
      "limiter_scope", "entry through acquire and guard release; active scopes include waiting and holding")(
      "helper_limiters", "not_applicable; helper has separate non-waiting admission, not measured here")(
      "server_received_to_waked_scope", "outer_decode_complete_to_payload_decode_start")(
      "helper_downstream", "included_in_outer_server_span_not_individually_observed")(
      "encoded_frame_header_bytes", 8)("encoded_frames_use_actual_compression", true)(
      "encoded_request_scope", "actual first-hop frame constructed; not send, socket delivery or remote commit")(
      "encoded_response_scope", "complete validated outer packet correlated by UUID; missing and late replies censored")(
      "selected_repair_and_healthy_copy_rpc_slots_merged", true)("helper_downstream_bytes", nullptr)(
      "overflow", m.storageRpc.overflow)("clock_anomaly", m.storageRpc.clockAnomaly)(
      "wire_bytes", nullptr)("encoded_bytes", nullptr)("transport_retry_attempts", nullptr)(
      "complete_server_queue", nullptr)("methods", folly::dynamic::object());
  const auto methodsJson = [&](const storage::client::EcRpcSample &sampled) {
    folly::dynamic methods = folly::dynamic::object();
    for (size_t n = 0; n != sampled.methods.size(); ++n) {
      const auto &sample = sampled.methods[n];
      methods[storage::client::kEcRpcMethodNames[n]] = folly::dynamic::object(
          "frame_entered_decimal", std::to_string(sample.entered))(
          "frame_finished_decimal", std::to_string(sample.finished))(
          "frame_active_decimal", std::to_string(sample.active))(
          "outer_ok_decimal", std::to_string(sample.outerOk))(
          "outer_error_decimal", std::to_string(sample.outerError))(
          "without_outer_result_decimal", std::to_string(sample.withoutResult))(
          "messenger_invocations_decimal", std::to_string(sample.messengerInvocations))(
          "frames_without_messenger_decimal", std::to_string(sample.withoutMessenger))(
          "observed_encoded_request_frames_decimal", std::to_string(sample.observedEncodedRequestFrames))(
          "request_frame_bytes_decimal", std::to_string(sample.requestFrameBytes))(
          "missing_encoded_request_frames_decimal", std::to_string(sample.missingEncodedRequestFrames))(
          "compressed_request_frames_decimal", std::to_string(sample.compressedRequestFrames))(
          "observed_encoded_response_frames_decimal", std::to_string(sample.observedEncodedResponseFrames))(
          "response_frame_bytes_decimal", std::to_string(sample.responseFrameBytes))(
          "missing_encoded_response_frames_decimal", std::to_string(sample.missingEncodedResponseFrames))(
          "compressed_response_frames_decimal", std::to_string(sample.compressedResponseFrames))(
          "limiters", nullptr)(
          "client", clockSample(sample.client, {"called_to_serialized_ns_decimal", "serialized_to_received_ns_decimal",
                                               "received_to_waked_ns_decimal"}))(
          "server", clockSample(sample.server, {"received_to_waked_ns_decimal", "waked_to_processed_ns_decimal",
                                               "processed_to_serialized_ns_decimal"}));
      if (n != size_t(storage::client::EcRpcMethod::Helper) &&
          n != size_t(storage::client::EcRpcMethod::HelperDirect)) {
        auto &limiters = methods[storage::client::kEcRpcMethodNames[n]]["limiters"];
        limiters = folly::dynamic::object();
        constexpr std::array<const char *, 2> names{"per_server", "global"};
        for (size_t i = 0; i != names.size(); ++i) {
          const auto &l = sample.limiters[i];
          limiters[names[i]] = folly::dynamic::object("entered_decimal", std::to_string(l.entered))(
              "acquired_decimal", std::to_string(l.acquired))("finished_decimal", std::to_string(l.finished))(
              "without_permit_decimal", std::to_string(l.withoutPermit))(
              "active_scopes_decimal", std::to_string(l.active))("peak_active_scopes_decimal", std::to_string(l.peakActive))(
              "entry_to_acquired_ns_decimal", std::to_string(l.acquiredWaitNs))(
              "entry_to_unacquired_exit_ns_decimal", std::to_string(l.unacquiredSpanNs))(
              "acquired_to_exit_ns_decimal", std::to_string(l.heldNs));
        }
      }
    }
    return methods;
  };
  rpc["methods"] = methodsJson(m.storageRpc);
  const auto phaseJson = [&](const storage::client::EcRpcSample &sampled) -> folly::dynamic {
    return folly::dynamic::object("overflow", sampled.overflow)("clock_anomaly", sampled.clockAnomaly)(
        "methods", methodsJson(sampled));
  };
  rpc["by_phase"] = folly::dynamic::object("schema", 1)(
      "attribution", "explicit selected-repair or healthy-copy call path, not RPC method name")(
      "scope", "this_call; recovery/replay RPCs stay with their actual phase")(
      "totals", "parent methods retain both phases; phase peaks are not additive")(
      "selected_repair", phaseJson(m.selectedRepairRpc))("healthy_copy", phaseJson(m.healthyCopyRpc));
  out["storage_rpc"] = std::move(rpc);
  return folly::toJson(out);
}
}  // namespace hf3fs::client::ec
