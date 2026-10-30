#!/usr/bin/env python3
"""Copy built services and resolved non-glibc libraries into a prepared guest bundle."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


SERVICES = (
    "storage_main", "mgmtd_main", "meta_main", "admin_cli",
    "hf3fs_fuse_main", "monitor_collector_main",
)
GLIBC_NAMES = {
    "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1",
    "libresolv.so.2", "libutil.so.1", "libanl.so.1", "libBrokenLocale.so.1",
    "libmvec.so.1", "libthread_db.so.1",
    "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ec-example", type=Path, help="Optional compiled POSIX EC example and its runtime libraries")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run inside the Linux build environment")
    build, output = args.build.resolve(), args.output.resolve()
    if not (output / "cluster.json").is_file():
        parser.error("--output must be a bundle already prepared by cluster/generate.py")
    for directory in (output / "bin", output / "lib", output / "provenance"):
        if directory.is_symlink() or not directory.resolve().is_relative_to(output):
            parser.error(f"Refusing a redirected bundle directory: {directory}")

    environment = dict(os.environ)
    environment["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    environment["LD_LIBRARY_PATH"] = "/usr/local/lib" + (
        ":" + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else ""
    )
    environment.pop("LD_PRELOAD", None)
    copies, omitted, diagnostics = {}, {}, {}

    def include(source, relative, kind):
        source = source.resolve(strict=True)
        checksum = digest(source)
        previous = copies.get(relative)
        if previous and previous["sha256"] != checksum:
            raise RuntimeError(f"Conflicting library contents for {relative}")
        destination = output / relative
        if destination.is_symlink():
            raise RuntimeError(f"Refusing to overwrite bundle symlink: {destination}")
        if destination.exists() and (not destination.is_file() or digest(destination) != checksum):
            raise RuntimeError(f"Refusing to overwrite different existing contents: {destination}")
        copies[relative] = {"source": str(source), "sha256": checksum,
                            "size_bytes": source.stat().st_size, "kind": kind,
                            "reused": destination.exists()}

    binaries = [(name, build / "bin" / name, "service") for name in SERVICES]
    if args.ec_example:
        binaries.append(("ec_posix_pipeline", args.ec_example.resolve(strict=True), "example"))
    for name, binary, kind in binaries:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"Missing built executable: {binary}")
        include(binary, f"bin/{name}", kind)
        result = subprocess.run(["ldd", str(binary)], env=environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        diagnostics[name] = result.stdout
        if "not found" in result.stdout:
            raise RuntimeError(f"Unresolved runtime library for {name}:\n{result.stdout}")
        for line in result.stdout.splitlines():
            match = re.match(r"\s*(\S+)\s+=>\s+(/\S+)\s+\(", line)
            direct = re.match(r"\s*(/\S+)\s+\(", line)
            if match:
                soname, source = match.groups()
            elif direct:
                source = direct.group(1)
                soname = Path(source).name
            else:
                continue
            source_path = Path(source).resolve(strict=True)
            if soname in GLIBC_NAMES:
                omitted[soname] = {"source": str(source_path), "sha256": digest(source_path),
                                   "reason": "Use the matching Ubuntu guest glibc and loader"}
            else:
                include(source_path, f"lib/{soname}", "shared-library")

    # Complete preflight before writing any payload; existing FDB files are
    # reused only when their content hash exactly matches the selected input.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    record = output / "provenance" / f"services-{stamp}"
    record.mkdir(parents=True, exist_ok=False)
    for relative, item in copies.items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not item["reused"]:
            with Path(item["source"]).open("rb") as source_stream, destination.open("xb") as destination_stream:
                shutil.copyfileobj(source_stream, destination_stream)
            destination.chmod(0o755 if item["kind"] in {"service", "example"} else 0o644)
        if digest(destination) != item["sha256"]:
            raise RuntimeError(f"Copied content verification failed: {destination}")
    for name, text in diagnostics.items():
        (record / f"ldd-{name}.txt").write_text(text)
    manifest = {"build_directory": str(build), "bundle_directory": str(output),
                "created_utc": stamp, "files": copies, "guest_system_libraries": omitted,
                "ld_library_path_during_inspection": environment["LD_LIBRARY_PATH"],
                "scope": "ELF DT_NEEDED closure; runtime dlopen providers remain guest dependencies"}
    (record / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"services": len(SERVICES), "ec_example": bool(args.ec_example),
                      "payload_files": len(copies), "manifest": str(record / "manifest.json")}))


if __name__ == "__main__":
    main()
