#!/usr/bin/env python3
"""Test double only: creates local journal-shaped files, never contacts 3FS."""
import hashlib
import copy
import json
import os
from pathlib import Path
import sys
import time
import uuid


def dump(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def latest(run):
    return load(sorted(run.glob("state-*.json"))[-1])


def write_object(record):
    inode = int(hashlib.sha256(record["remotePath"].encode()).hexdigest()[:14], 16) + 1
    return {"version": 2, "object": {"inode": inode, "incarnation": str(uuid.uuid4())},
            "shardBytes": record["shardBytes"], "allowColocated": True, "epoch": 1,
            "nextGeneration": 2, "nextRevision": 2, "length": record["inputBytes"], "deleting": False,
            "creator": {"uid": 1000, "client": record["clientNamespace"]},
            "createRequest": record["createRequest"]}


def initial_state(record, obj, revision):
    return {"version": 1, "sequence": 0, "ownerUid": 1000, "object": obj, "revision": revision,
            "mutationPublished": record["action"] != "read", "state": "Published", "readOutput": "",
            "errorCode": 0, "error": "", "coreElapsedNanoseconds": 7, "dataPhaseElapsedNanoseconds": None,
            "logicalBytes": record["inputBytes"], "shardBytes": record["shardBytes"],
            "blocksPerShard": (record["shardBytes"] + 65535) // 65536,
            "acknowledgedEndpoints": 0, "expectedEndpoints": 0,
            "maxOperations": 1, "applicationByteBudget": 67108864, "writeFragmentWindow": 2,
            "readBlockWindow": 1, "workerThreads": 2, "deadlineSeconds": 300,
            "metaRpcTimeoutMillis": 5000, "metaRetryTotalMillis": 60000}


def metrics_fixture(record, command):
    """Parser fixture only: counters are invented, never native measurements."""
    def decimals(names, count=0):
        return {key + '_decimal': str(count) for key in names.split()}
    points = {}
    for key in ('query_rpc begin_rpc prepare_rpc selected_repair healthy_copy publish_rpc close_debt_rpc journal_append '
                'native_begin native_read native_append native_seal native_helper copy_read copy_begin copy_reconcile '
                'copy_append copy_seal block_actor ordered_append_wait central_codec_recover client_block_advance').split():
        points[key] = decimals('entered finished succeeded span_ns active peak_active api_invocations '
                               'submitted_payload_bytes validated_returned_payload_bytes')
    methods = {}
    for key in ('read_block begin_stage append_stage query_stage reconcile_stage seal_stage helper helper_direct').split():
        method = decimals('frame_entered frame_finished frame_active outer_ok outer_error without_outer_result '
                          'messenger_invocations frames_without_messenger observed_encoded_request_frames request_frame_bytes '
                          'missing_encoded_request_frames compressed_request_frames observed_encoded_response_frames '
                          'response_frame_bytes missing_encoded_response_frames compressed_response_frames')
        for host, spans in (('client', 'called_to_serialized_ns serialized_to_received_ns received_to_waked_ns'),
                            ('server', 'received_to_waked_ns waked_to_processed_ns processed_to_serialized_ns')):
            method[host] = decimals('valid_samples missing_or_nonpositive_samples reversed_samples out_of_range_samples ' + spans)
        method['limiters'] = None if key in ('helper', 'helper_direct') else {
            name: decimals('entered acquired finished without_permit active_scopes peak_active_scopes '
                           'entry_to_acquired_ns entry_to_unacquired_exit_ns acquired_to_exit_ns')
            for name in ('per_server', 'global')}
        methods[key] = method
    empty = {'overflow': False, 'clock_anomaly': False, 'methods': copy.deepcopy(methods)}
    fresh = command == 'new-repair'
    if fresh:
        row = methods['begin_stage']
        for key in ('frame_entered', 'frame_finished', 'outer_ok', 'messenger_invocations',
                    'observed_encoded_request_frames', 'observed_encoded_response_frames'):
            row[key + '_decimal'] = '1'
        row.update(request_frame_bytes_decimal='16', response_frame_bytes_decimal='16')
        for host in ('client', 'server'):
            row[host]['missing_or_nonpositive_samples_decimal'] = '1'
        for limiter in row['limiters'].values():
            for key in ('entered', 'acquired', 'finished', 'peak_active_scopes'):
                limiter[key + '_decimal'] = '1'
    rpc = {'schema': 1, 'coverage': 'controlled_client_to_storage_first_hop', 'encoded_frame_header_bytes': 8,
           'overflow': False, 'clock_anomaly': False, 'methods': methods,
           'by_phase': {'schema': 1, 'selected_repair': {'overflow': False, 'clock_anomaly': False,
                                                      'methods': copy.deepcopy(methods)}, 'healthy_copy': empty}}
    rpc.update({key: True for key in ('missing_samples_are_censored', 'frame_counts_are_not_dispatch_counts',
                'outer_ok_is_not_business_success', 'messenger_invocations_are_not_dispatch_or_retry_counts',
                'spans_overlap_and_are_not_total_wall_time', 'encoded_frames_use_actual_compression',
                'selected_repair_and_healthy_copy_rpc_slots_merged')})
    rpc.update({key: None for key in ('helper_downstream_bytes', 'wire_bytes', 'encoded_bytes',
                                    'transport_retry_attempts', 'complete_server_queue')})
    sample = {'schema': 1, 'scope': 'this_call', 'action': 1, 'configured_window': record['blockWindow'],
              'block_actors_applicable': record['strategy'] != 'central', 'points': points, 'storage_rpc': rpc,
              'prior_journal_sequence_decimal': '0', 'elapsed_ns_decimal': '11'}
    sample.update({key: False for key in ('journal_state_observed', 'had_journal_state', 'cancellation_requested',
                  'deadline_expired', 'overflow', 'clock_anomaly', 'persisted_in_business_journal')})
    sample.update({key: None for key in ('wire_bytes', 'rpc_encoded_bytes', 'transport_retry_attempts',
                                       'server_queue_depth', 'helper_server_compute')})
    return {'schema': 1, 'kind': 'ec_flat_repair_metrics', 'command': command, 'operation': record['operation'],
            'plan': record['planId'], 'strategy': record['strategy'], 'delivery': record.get('delivery', 'return'),
            'observation_boundary': 'owned_flat_repair; excludes public admission, CLI journal and shutdown',
            'repair_scope': 'selected_replacement_shards; unchanged shards are not copied', 'repair_invoked': True,
            'data_phase_entered': fresh, 'owned_repair_published': True, 'local_manager_joined': True,
            'telemetry_unavailable': False, 'metrics': sample}


def main():
    options = dict(arg[2:].split("=", 1) for arg in sys.argv[1:] if arg.startswith("--") and "=" in arg)
    command = sys.argv[-1]
    run = Path(options["config.run_dir"])
    root = Path(options["cfg"]).parent.parent
    mode = os.environ.get("EC_FAKE_MODE", "normal")
    store = root / "fake-store"
    store.mkdir(exist_ok=True)
    with (root / "fake-invocations.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"command": command, "run": str(run), "options": options}) + "\n")
    if mode == "delayed":
        (root / "fake-started").write_text("started")
        time.sleep(0.7)
    if command.startswith("new-"):
        run.mkdir(mode=0o700)
        action = command[4:]
        record = {"version": 1, "action": action, "cluster": "FAKE_ONLY",
                  "clientNamespace": str(uuid.uuid4()), "expectedOwnerUid": None,
                  "inputPath": "", "inputBytes": 0, "inputSha256": "", "remotePath": "",
                  "shardBytes": 0, "object": None, "expectedRevision": 0,
                  "strategy": "", "replacementMask": 0, "sourceOrder": [], "blockWindow": 1,
                  "command": "fake", "resumeCommand": "fake"}
        for key in ("createRequest", "operation", "beginRequest", "bindRequest", "publishRequest",
                    "getRequest", "prepareRepairRequest", "pin", "acquireRequest", "releaseRequest", "planId"):
            record[key] = str(uuid.uuid4())
        if action == "write":
            path = Path(options["config.input_file"])
            data = path.read_bytes()
            record.update(inputPath=str(path), inputBytes=len(data), inputSha256=hashlib.sha256(data).hexdigest(),
                          remotePath=options["config.remote_path"], shardBytes=int(options["config.shard_bytes"]))
            obj = write_object(record)
            (store / f"{obj['object']['inode']}.bin").write_bytes(data)
            revision = 1
        else:
            source = Path(options["config.source_run"])
            sr, so = load(source / "record.json"), latest(source)
            obj, revision = so["object"], so["revision"]
            record.update(clientNamespace=sr["clientNamespace"], expectedOwnerUid=so["ownerUid"],
                          object=obj, expectedRevision=revision, inputBytes=sr["inputBytes"],
                          inputSha256=sr["inputSha256"], shardBytes=sr["shardBytes"])
            if action == "repair":
                record.update(strategy=options["config.strategy"], replacementMask=int(options["config.replacement_mask"]),
                              sourceOrder=json.loads(options["config.source_order"]),
                              blockWindow=int(options["config.block_window"]))
                if options.get("config.delivery") == "direct" and mode != "delivery-downgrade":
                    record.update(version=3, delivery="direct")
                revision += 1
        dump(run / "record.json", record)
        if mode == "record-only":
            # Native CLI writes its immutable record before token/client/auth
            # setup; an early error may leave no state-N.json at all.
            print("FAKE early initialization failure after fixed record, before observation", file=sys.stderr)
            return 2
        state = initial_state(record, obj, revision)
        if action == "read":
            data = (store / f"{obj['object']['inode']}.bin").read_bytes()
            if mode == "corrupt-read":
                data = bytes([data[0] ^ 1]) + data[1:]
            name = f"read-{uuid.uuid4().hex}.bin"
            (run / name).write_bytes(data)
            state.update(state="ReadReadyLocalCleaned", readOutput=name)
        if mode == "false-published" and action == "write":
            state.update(state="Created", mutationPublished=False)
        if mode == "unknown" and action == "write":
            state.update(state="MutationPending", mutationPublished=False, errorCode=4085)
    else:
        record = load(run / "record.json")
        if mode == "record-only-no-observation" and command == "resume":
            print("Local manager joined; active_operations=0 reserved_application_bytes=0.")
            return 0
        if command == "resume" and not any(run.glob("state-*.json")) and record["action"] == "write":
            state = initial_state(record, write_object(record), 1)
            state["sequence"] = -1  # Increment below publishes the first state at zero.
        else:
            state = latest(run)
        if mode == "stale-release" and command == "release":
            print("Local manager joined; active_operations=0 reserved_application_bytes=0.")
            return 0
        if mode == "mutated-record" and command == "release":
            record["operation"] = str(uuid.uuid4())
            (run / "record.json").write_text(json.dumps(record))
        state["sequence"] += 1
        if command == "release":
            state.update(state="ReadReleased", acknowledgedEndpoints=12, expectedEndpoints=12, errorCode=0)
            if mode == "incomplete-release":
                state["acknowledgedEndpoints"] = 11
        elif command == "resume":
            state.update(state="Published", mutationPublished=True, errorCode=0)
        else:
            raise RuntimeError("Unsupported fake command")
    dump(run / f"state-{state['sequence']:020d}.json", state)
    print("FAKE CLI ONLY; not storage evidence")
    print("Local manager joined; active_operations=0 reserved_application_bytes=0.")
    if command == 'new-repair' and mode == 'metrics-business-failure':
        return 7
    if (options.get('config.repair_metrics') == 'true' and record['action'] == 'repair'
            and command in ('new-repair', 'resume') and mode != 'metrics-missing'):
        print(json.dumps(metrics_fixture(record, command)))
    if mode == "delayed":
        (root / "fake-exited").write_text("exited")
    return 1 if mode == "unknown" and command == "new-write" else 0


if __name__ == "__main__":
    sys.exit(main())
