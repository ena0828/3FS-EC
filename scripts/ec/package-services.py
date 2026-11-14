#!/usr/bin/env python3
"""Copy built services and resolved non-glibc libraries into a prepared guest bundle."""
import argparse
import datetime
import hashlib
import importlib.util
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
NATIVE_V2_SERVICES = ("storage_main", "mgmtd_main", "meta_main", "admin_cli", "ec_stripe_cli")
GLIBC_NAMES = {
    "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1",
    "libresolv.so.2", "libutil.so.1", "libanl.so.1", "libBrokenLocale.so.1",
    "libmvec.so.1", "libthread_db.so.1",
    "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def selected_services(manifest, native_v2=False, native_gc=False, ec_file_mount=False):
    is_v2 = manifest.get("profile") in {"native-v2-local-1-storage-12-targets", "native-v2-local-12-storage-12-targets"}
    is_gc = manifest.get("profile") in {"native-gc-local-1-storage-12-targets", "native-gc-local-12-storage-12-targets", "native-gc-local-14-storage-14-targets"}
    if native_v2 != is_v2 or native_gc != is_gc:
        raise ValueError("--native-v2/--native-gc must match the prepared bundle profile")
    file_api = manifest.get("file_api", False)
    if type(file_api) is not bool or (file_api and not is_gc):
        raise ValueError("File API must be explicitly prepared on a native GC profile")
    if type(ec_file_mount) is not bool or (ec_file_mount and not (is_gc and file_api)):
        raise ValueError("--ec-file-mount requires an already prepared native GC --file-api bundle")
    services = NATIVE_V2_SERVICES if native_v2 or native_gc else SERVICES
    if file_api:
        services += ("ec_file_cli",)
    if ec_file_mount:
        services += ("hf3fs_fuse_main", "ec_mount_read_probe")
    return services


def transport_provenance(manifest):
    """Add explicit RDMA intent without expanding the ELF/provider closure."""
    if "data_transport" not in manifest:
        return {}
    scripts = Path(__file__).with_name("cluster")
    old_path = list(sys.path)
    try:
        sys.path.insert(0, str(scripts))
        spec = importlib.util.spec_from_file_location("package_native_v2_config", scripts / "native_v2_config.py")
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        transport = config.transport_settings(manifest)
        if manifest.get("profile") not in config.PROFILES.values():
            raise ValueError("RDMA packaging requires an explicitly prepared native profile")
    finally:
        sys.path[:] = old_path
    return {"data_transport_requested": transport, "transport_validation": "configuration_only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    native_profile = parser.add_mutually_exclusive_group()
    native_profile.add_argument("--native-v2", action="store_true", help="Package the prepared native V2 profile including ec_stripe_cli, without FUSE")
    native_profile.add_argument("--native-gc", action="store_true", help="Package the explicitly prepared native GC profile using the same five services")
    parser.add_argument("--ec-file-mount", action="store_true", help="Explicitly package mode4 FUSE and its probe for a native GC --file-api bundle; never mounts")
    parser.add_argument("--ec-example", type=Path, help="Optional compiled POSIX EC example and its runtime libraries")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run inside the Linux build environment")
    build, output = args.build.resolve(), args.output.resolve()
    if not (output / "cluster.json").is_file():
        parser.error("--output must be a bundle already prepared by cluster/generate.py")
    bundle_manifest = json.loads((output / "cluster.json").read_text())
    try:
        services = selected_services(bundle_manifest, args.native_v2, args.native_gc, args.ec_file_mount)
        transport = transport_provenance(bundle_manifest)
    except ValueError as error:
        parser.error(str(error))
    for directory in (output / "bin", output / "lib", output / "provenance", output / "scripts"):
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

    binaries = [(name, build / "bin" / name, "service") for name in services]
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

    if bundle_manifest.get("file_api") is True:
        script = Path(__file__).with_name("cluster") / "file-cli-acceptance.py"
        if not script.is_file():
            raise RuntimeError(f"Missing file API acceptance source: {script}")
        include(script, "scripts/file-cli-acceptance.py", "script")

    if bundle_manifest.get("profile") == "native-gc-local-14-storage-14-targets" and bundle_manifest.get("file_api") is True:
        script = Path(__file__).with_name("cluster") / "spare-fault-acceptance.py"
        if not script.is_file():
            raise RuntimeError(f"Missing spare Storage acceptance source: {script}")
        include(script, "scripts/spare-fault-acceptance.py", "script")

    if args.ec_file_mount:
        for name in ("prepare-fuse-file.py", "prepare-fuse-read.py", "generate.py", "native_v2_config.py",
                     "mode4-mount-acceptance.py", "mode4-usrbio-acceptance.py", "fuse-read-acceptance.py",
                     "mode4-lifecycle-acceptance.py"):
            script = Path(__file__).with_name("cluster") / name
            if not script.is_file():
                raise RuntimeError(f"Missing mode4 preparation source: {script}; integrate the mount candidate first")
            include(script, f"scripts/{name}", "script")

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
                "scope": "ELF DT_NEEDED closure; runtime dlopen providers remain guest dependencies",
                "ec_file_mount": args.ec_file_mount, "mount_started": False}
    manifest.update(transport)
    (record / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"services": len(services), "ec_example": bool(args.ec_example),
                      "payload_files": len(copies), "manifest": str(record / "manifest.json")}))


if __name__ == "__main__":
    main()
