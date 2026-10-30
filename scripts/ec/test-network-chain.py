#!/usr/bin/env python3
"""Independent multi-process TCP chain checks; ordinary files, not native 3FS.

Run with --binary PATH_TO_network_chain --output NEW_TASK_DIRECTORY.
The harness never builds software or kills processes it did not start. Source
directories share a physical filesystem and are not security sandboxes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import threading
import time


def crc_table():
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        table.append(value)
    return table


CRC_TABLE = crc_table()


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value = CRC_TABLE[(value ^ byte) & 255] ^ (value >> 8)
    return value ^ 0xFFFFFFFF


def multiply(a, b):
    # Independent polynomial convolution followed by long division.
    product = 0
    for bit in range(8):
        if b & (1 << bit):
            product ^= a << bit
    for bit in range(14, 7, -1):
        if product & (1 << bit):
            product ^= 0x11D << (bit - 8)
    return product


def inverse(a):
    return next(b for b in range(1, 256) if multiply(a, b) == 1)


def code_patterns(k, m):
    data = [hashlib.shake_256(f"network-chain-source-{i}".encode()).digest(4096)
            for i in range(k)]
    result = list(data)
    for row in range(k, k + m):
        parity = bytearray(4096)
        for col, source in enumerate(data):
            coefficient = inverse(row ^ col)
            table = bytes(multiply(coefficient, b) for b in range(256))
            for pos, byte in enumerate(source.translate(table)):
                parity[pos] ^= byte
        result.append(bytes(parity))
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class Child:
    def __init__(self, name, command, directory):
        self.name, self.command = name, command
        self.events, self.lock, self.ready_queue = [], threading.Lock(), queue.Queue()
        self.stdout = (directory / f"{name}.stdout.jsonl").open("w", encoding="utf-8")
        self.stderr = (directory / f"{name}.stderr.txt").open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.stderr,
                                        text=True, bufsize=1)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            for line in self.process.stdout:
                self.stdout.write(line)
                self.stdout.flush()
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event["observed_monotonic"] = time.monotonic()
                with self.lock:
                    self.events.append(event)
                if event.get("event") == "ready":
                    self.ready_queue.put(event)
        finally:
            self.ready_queue.put(None)
            self.process.stdout.close()

    def ready(self):
        event = self.ready_queue.get(timeout=10)
        if not event or event.get("pid") != self.process.pid:
            raise RuntimeError(f"{self.name}: exited or invalid READY")
        return event

    def read_bytes(self):
        with self.lock:
            return max((e["bytes"] for e in self.events if e.get("event") == "source"), default=0)

    def successes(self):
        with self.lock:
            return [e for e in self.events if e.get("event") == "result" and e.get("ok")]

    def close(self):
        forced = False
        if self.process.poll() is None:
            forced = True
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=3)
        self.stdout.close()
        self.stderr.close()
        return forced


def endpoint(text):
    host, port = text.rsplit(":", 1)
    return host, int(port)


def receive(sock, count):
    output = bytearray()
    while len(output) < count:
        part = sock.recv(count - len(output))
        if not part:
            raise EOFError("connection ended inside frame")
        output.extend(part)
    return bytes(output)


class Proxy:
    """Fault injection at the last helper -> sink edge, with bounded frames."""
    def __init__(self, downstream, mode, timeout):
        self.downstream, self.mode, self.timeout = downstream, mode, timeout
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.server.settimeout(timeout)
        self.address = f"127.0.0.1:{self.server.getsockname()[1]}"
        self.accepted, self.release = threading.Event(), threading.Event()
        self.fired, self.error, self.sockets = False, None, []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            incoming, _ = self.server.accept()
            outgoing = socket.create_connection(endpoint(self.downstream), timeout=self.timeout)
            self.sockets = [incoming, outgoing]
            for sock in self.sockets:
                sock.settimeout(self.timeout)
            self.accepted.set()
            if self.mode == "slow":
                self.fired = True
                if not self.release.wait(self.timeout):
                    raise TimeoutError("slow downstream gate not released")
            while True:
                header = bytearray(receive(incoming, 128))
                count = struct.unpack_from("<I", header, 12)[0]
                if count > 32 * 1024 * 1024:
                    raise ValueError("proxy refuses unbounded frame")
                body = bytearray(receive(incoming, count))
                kind = header[10]
                if kind == 1 and not self.fired:
                    self.fired = True
                    if self.mode == "disconnect":
                        outgoing.sendall(header + body)
                        return
                    if self.mode == "truncated":
                        outgoing.sendall(header + body[:max(0, len(body)//2)])
                        return
                    if self.mode == "bad-header":
                        header[40] ^= 1
                    elif self.mode == "bad-body":
                        body[-1] ^= 1
                    elif self.mode in ("wrong-session", "wrong-sequence", "oversize"):
                        if self.mode == "wrong-session":
                            header[40] ^= 1
                        elif self.mode == "wrong-sequence":
                            struct.pack_into("<Q", header, 24, 9)
                        else:
                            struct.pack_into("<I", header, 12, 0x7FFFFFFF)
                        struct.pack_into("<I", header, 124, crc32c(header[:124]))
                    elif self.mode == "duplicate":
                        outgoing.sendall(header + body)
                outgoing.sendall(header + body)
                if kind == 2:  # Finish: forward bounded terminal response upstream.
                    ack = receive(outgoing, 128)
                    size = struct.unpack_from("<I", ack, 12)[0]
                    if size > 32 * 1024 * 1024:
                        raise ValueError("unbounded terminal response")
                    incoming.sendall(ack + receive(outgoing, size))
                    return
        except (OSError, EOFError, ValueError, TimeoutError) as exc:
            self.error = str(exc)
        finally:
            for sock in self.sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
            self.server.close()

    def close(self):
        self.release.set()
        for sock in self.sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server.close()
        self.thread.join(timeout=3)


CASES = ["single", "double", "tail", "empty", "source-corrupt", "source-short",
         "bad-header", "bad-body", "wrong-session", "wrong-sequence", "oversize",
         "duplicate", "truncated", "disconnect", "kill", "slow"]


def run_case(binary, directory, case, timeout):
    directory.mkdir()
    k, m, length, slice_len = 10, 2, 11469, 4096
    targets = [2, 11] if case == "double" else [2]
    if case == "double":
        targets.reverse()  # target ordering is part of the contract.
    if case == "tail":
        k, m, length, slice_len, targets = 3, 2, 8193, 1024, [4, 1]
    if case == "empty":
        length = 0
    if case in ("slow", "kill"):
        k, m, length, slice_len, targets = 3, 2, 8*1024*1024, 16384, [4, 1]
    healthy = [i for i in range(k+m) if i not in targets][:k]
    # Reverse helper order to exercise index-vs-position correctness.
    healthy.reverse()
    patterns = code_patterns(k, m)
    hashes, source_paths, sidecars = {}, {}, {}
    expected_crcs = {}
    for shard in healthy + targets:
        data = (patterns[shard] * ((length + 4095)//4096))[:length]
        hashes[shard] = hashlib.sha256(data).hexdigest()
        if shard in targets:
            expected_crcs[shard] = crc32c(data)
            continue
        own = directory / f"source-{shard}"
        own.mkdir()
        source_paths[shard] = own / "source.bin"
        sidecars[shard] = own / "slices.crc32c"
        source_paths[shard].write_bytes(data)
        sidecars[shard].write_text("".join(f"{crc32c(data[p:p+slice_len]):08x}\n"
                                          for p in range(0, length, slice_len)), encoding="ascii")
    conf = dict(k=k, m=m, shard_len=length, slice_len=slice_len,
                healthy=",".join(map(str, healthy)), targets=",".join(map(str, targets)),
                job=1, stripe=17, generation=3, epoch=1)
    # Digest also binds input integrity evidence; config remains trusted, not authenticated.
    canonical = dict(conf, source_sha256={str(i): hashes[i] for i in healthy},
                     target_crc32c={str(i): f"{expected_crcs[i]:08x}" for i in targets},
                     codec="systematic-cauchy-gf256-11d")
    canonical_bytes = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    conf["plan"] = hashlib.sha256(canonical_bytes).hexdigest()
    (directory / "canonical-plan.json").write_bytes(canonical_bytes)
    plan = directory / "plan.conf"
    plan.write_text("".join(f"{key}={value}\n" for key, value in conf.items()), encoding="ascii")
    expected = directory / "expected.conf"
    expected.write_text("".join(f"{i}={expected_crcs[i]:08x}\n" for i in targets), encoding="ascii")
    if case == "source-corrupt":
        path = source_paths[healthy[0]]
        with path.open("r+b") as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(bytes([first[0] ^ 1]))
    if case == "source-short":
        with source_paths[healthy[-1]].open("r+b") as stream:
            stream.truncate(length-1)
    actual_before = {str(i): hashlib.sha256(p.read_bytes()).hexdigest()
                     for i, p in source_paths.items()}
    children, helpers, proxy = [], {}, None
    result = dict(case=case, passed=False, config=conf, source_sha256=hashes,
                  sources={str(i): str(p) for i, p in source_paths.items()},
                  physical_disk_isolation=False, native_3fs=False,
                  source_isolation="distinct directories and CLI inputs; same UID and filesystem")
    output = directory / "recovered"
    expected_success = case in ("single", "double", "tail", "empty", "slow")
    common = [str(binary), "--plan", str(plan), "--timeout-ms", str(int(timeout*1000))]
    start = time.monotonic()
    try:
        sink_command = common + ["--role", "sink", "--listen", "127.0.0.1:0",
                                 "--output", str(output), "--expected", str(expected)]
        if case == "kill":
            sink_command += ["--delay-ms", "20"]
        sink = Child("sink", sink_command, directory)
        children.append(sink)
        downstream = sink.ready()["listen"]
        if case not in ("single", "double", "tail", "empty", "source-corrupt", "source-short", "kill"):
            proxy = Proxy(downstream, case, timeout)
            downstream = proxy.address
        for position in reversed(range(k)):
            shard = healthy[position]
            command = common + ["--role", "helper", "--position", str(position),
                                "--source", str(source_paths[shard]), "--crc", str(sidecars[shard]),
                                "--next", downstream]
            if position:
                command += ["--listen", "127.0.0.1:0"]
            child = Child(f"helper-{position}", command, directory)
            children.append(child)
            helpers[position] = child
            ready = child.ready()
            if position:
                downstream = ready["listen"]
        pids = [child.process.pid for child in children]
        if len(set(pids)) != k+1 or os.getpid() in pids:
            raise AssertionError("helpers and sink must have distinct child PIDs")
        result["independent_pids"] = pids
        if case == "slow":
            if not proxy.accepted.wait(5):
                raise AssertionError("slow proxy was not connected")
            time.sleep(0.9)
            before = {i: c.read_bytes() for i, c in helpers.items()}
            time.sleep(0.6)
            after = {i: c.read_bytes() for i, c in helpers.items()}
            proxy.release.set()
            result["backpressure"] = dict(before=before, after=after, gate_seconds=1.5)
            if not (0 < before[k-1] == after[k-1] < length):
                raise AssertionError("last helper did not exhibit bounded read progress while sink stalled")
        if case == "kill":
            limit = time.monotonic()+5
            while helpers[1].read_bytes() == 0 and time.monotonic() < limit:
                time.sleep(0.01)
            victim = helpers[1]
            if victim.process.poll() is not None or victim.read_bytes() == 0:
                raise AssertionError("helper kill was not injected during an active repair")
            victim.process.kill()
            result["killed_pid"] = victim.process.pid
        deadline = start + timeout + 5
        for child in children:
            child.process.wait(timeout=max(0.1, deadline-time.monotonic()))
            child.reader.join(timeout=2)
        exits = [child.process.returncode for child in children]
        if expected_success:
            if any(code != 0 for code in exits) or not all(c.successes() for c in children):
                raise AssertionError(f"expected all participants to succeed, got {exits}")
            for target in targets:
                recovered = output / f"shard-{target}"
                if recovered.stat().st_size != length or hashlib.sha256(recovered.read_bytes()).hexdigest() != hashes[target]:
                    raise AssertionError(f"target {target}: independent byte digest mismatch")
            if sorted(p.name for p in output.iterdir()) != sorted(f"shard-{i}" for i in targets):
                raise AssertionError("unexpected output files")
        else:
            if any(child.successes() for child in children) or any(code == 0 for code in exits):
                raise AssertionError(f"failure incorrectly acknowledged: {exits}")
            if output.exists():
                raise AssertionError("pre-seal failure published an output directory")
        if proxy and not proxy.fired:
            raise AssertionError("proxy fault/gate was never exercised")
        actual_after = {str(i): hashlib.sha256(p.read_bytes()).hexdigest()
                        for i, p in source_paths.items()}
        if actual_before != actual_after:
            raise AssertionError("helper modified an input file")
        result["source_bytes_unchanged"] = True
        result["passed"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if proxy:
            proxy.close()
            result["proxy"] = dict(mode=proxy.mode, exercised=proxy.fired, diagnostic=proxy.error)
        participants = []
        for child in children:
            forced = child.close()
            participants.append(dict(name=child.name, pid=child.process.pid, parent_pid=os.getpid(),
                                     command=child.command, exit=child.process.returncode,
                                     cleanup_forced=forced, source_bytes_read=child.read_bytes()))
            if forced:
                result["passed"] = False
                result.setdefault("error", "participant did not exit within its deadline")
        result["participants"] = participants
        result["elapsed_seconds"] = time.monotonic()-start
        result["remaining_stage_directories"] = [p.name for p in directory.glob(".recovered.stage-*")]
        if result["remaining_stage_directories"]:
            result["passed"] = False
            result.setdefault("error", "unexpected stage remains after a pre-seal failure or successful case")
        write_json(directory / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    binary, output = args.binary.resolve(strict=True), args.output.resolve()
    cases = args.cases.split(",")
    if not 3 <= args.timeout <= 300 or not cases or len(set(cases)) != len(cases) or any(c not in CASES for c in cases):
        parser.error("invalid timeout or cases")
    if crc32c(b"123456789") != 0xE3069283:
        raise RuntimeError("CRC oracle self-check failed")
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for case in cases:
        result = run_case(binary, output/case, case, args.timeout)
        results.append(result)
        print(json.dumps({"case":case, "passed":result["passed"], "error":result.get("error")}), flush=True)
        write_json(output/"summary.json", {"passed":all(r["passed"] for r in results),
                                          "completed":len(results), "requested":cases,
                                          "binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
                                          "results":results})
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
