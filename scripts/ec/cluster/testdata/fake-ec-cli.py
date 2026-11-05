#!/usr/bin/env python3
"""Test double only: creates local journal-shaped files, never contacts 3FS."""
import hashlib
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


def main():
    options = dict(arg[2:].split("=", 1) for arg in sys.argv[1:] if arg.startswith("--") and "=" in arg)
    command = sys.argv[-1]
    run = Path(options["config.run_dir"])
    root = Path(options["cfg"]).parent.parent
    mode = os.environ.get("EC_FAKE_MODE", "normal")
    store = root / "fake-store"
    store.mkdir(exist_ok=True)
    with (root / "fake-invocations.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"command": command, "run": str(run)}) + "\n")
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
    if mode == "delayed":
        (root / "fake-exited").write_text("exited")
    return 1 if mode == "unknown" and command == "new-write" else 0


if __name__ == "__main__":
    sys.exit(main())
