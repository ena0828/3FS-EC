#!/usr/bin/env python3
"""Small deterministic POSIX acceptance test; requires an existing FUSE mount."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def content(label, size):
    return hashlib.shake_256(label.encode("ascii")).digest(size)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["write", "verify"])
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    mount = root / "mnt"
    subprocess.run(["mountpoint", "-q", str(mount)], check=True)
    mount_type = subprocess.check_output(["findmnt", "-n", "-o", "FSTYPE", "--target", str(mount)], text=True).strip()
    if mount_type != "fuse.hf3fs":
        raise RuntimeError(f"Expected fuse.hf3fs, got {mount_type}")
    test_dir = mount / "ec-local-acceptance"
    manifest_path = root / "state" / "file-checksums.json"
    if args.mode == "write":
        test_dir.mkdir(exist_ok=False)
        records = {}
        for size in [0, 1, 114688, 524325, 3145745]:
            name = f"payload-{size}.bin"
            payload = content(name, size)
            path = test_dir / name
            with path.open("xb", buffering=0) as out:
                remaining = memoryview(payload)
                while remaining:
                    written = out.write(remaining)
                    if not written:
                        raise RuntimeError("Write made no progress")
                    remaining = remaining[written:]
                os.fsync(out.fileno())
            records[name] = {"bytes": size, "sha256": hashlib.sha256(payload).hexdigest()}
        edited = test_dir / "edited.bin"
        payload = bytearray(content("edited", 2 * 524288 + 333))
        with edited.open("xb", buffering=0) as out:
            if out.write(payload) != len(payload):
                raise RuntimeError("Short initial write")
            patch = content("cross-chunk-patch", 8192)
            offset = 524288 - 73
            if os.pwrite(out.fileno(), patch, offset) != len(patch):
                raise RuntimeError("Short pwrite")
            payload[offset:offset + len(patch)] = patch
            out.truncate(len(payload) - 37)
            payload = payload[:-37]
            os.fsync(out.fileno())
        edited.rename(test_dir / "edited-renamed.bin")
        records["edited-renamed.bin"] = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        manifest_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    records = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in records.items():
        path = test_dir / name
        observed = {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        if observed != expected:
            raise RuntimeError(f"File verification failed: {name}, expected={expected}, observed={observed}")
        print(f"PASS {name} bytes={observed['bytes']} sha256={observed['sha256']}")
    print(f"PASS {args.mode}: {len(records)} files through {mount_type}; no throughput claim")


if __name__ == "__main__":
    main()
