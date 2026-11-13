#!/usr/bin/env python3
"""Build and test the real chunk_engine crate in a fresh Linux work directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import urllib.request


TOOLCHAIN = "1.99.1"
EXPECTED = {
    "ec_codec::tests::" + name
    for name in (
        "malformed_bridge_requests_return_errors_without_partial_output",
        "codec_bridge_verifies_padding_and_returns_owned_bytes",
        "raw_bridge_rejects_malformed_sources_without_cpp_validation",
        "cached_plans_preserve_order_and_actual_helper_identity",
        "cache_capacity_is_bounded_and_evicted_borrows_remain_valid",
        "concurrent_same_key_misses_share_one_plan",
        "warmed_bridge_cache_does_not_bypass_request_validation",
        "poisoned_cache_is_an_explicit_internal_error",
        "unexpected_unwind_is_contained_at_bridge_boundary",
        "configured_backend_matches_scalar_across_bridge_operations",
    )
}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--backend", choices=("scalar", "isal"), default="scalar")
    parser.add_argument("--cxx-probe", action="store_true")
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "This validation entry point requires Linux x86_64")
    require(os.getuid() != 0, "Run as an ordinary build user")
    root = Path(__file__).resolve().parents[3]
    work = args.work.absolute()
    require(not work.exists() and not work.is_symlink(), "Work directory must be new")
    require(work.parent.is_dir() and not work.parent.is_symlink(), "Work parent must exist")
    work = work.parent.resolve() / work.name
    require(not work.is_relative_to(root), "Keep build outputs outside the source tree")
    require(re.fullmatch(r"[0-9a-f]{40}", args.revision), "Specify an exact Git revision")
    git = lambda *argv: subprocess.check_output(["git", "-C", str(root), *argv], text=True).strip()
    require(git("rev-parse", "HEAD") == args.revision, "Unexpected source revision")
    require(not git("status", "--porcelain", "--untracked-files=normal"), "Source must be clean")
    source_target = root / "target"
    require(not source_target.exists() and not source_target.is_symlink(),
            "Source target must be absent; do not share a checkout between concurrent backends")
    work.mkdir(mode=0o700)
    # Drop inherited compiler flags, preload settings and RocksDB/system-library
    # overrides. Cargo and its target directory are private; Rustup's fixed
    # toolchain can be reused. No test executable or Cargo build cache is reused.
    env = {key: os.environ[key] for key in (
        "PATH", "HOME", "TMPDIR", "RUSTUP_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR"
    ) if key in os.environ}
    env.update({
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "CARGO_HOME": str(work / "cargo-home"),
        "CARGO_TARGET_DIR": str(work / "cargo-target"),
        "CARGO_BUILD_JOBS": "1", "CMAKE_BUILD_PARALLEL_LEVEL": "1", "MAKEFLAGS": "-j1",
        "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
        "CARGO_PROFILE_DEV_OPT_LEVEL": "0", "CARGO_PROFILE_TEST_OPT_LEVEL": "0",
        "CC": "/usr/bin/gcc-12", "CXX": "/usr/bin/g++-12",
        "LIBCLANG_PATH": "/usr/lib/llvm-18/lib", "RUST_BACKTRACE": "1",
        "CARGO_TERM_COLOR": "never",
        "RUSTUP_TOOLCHAIN": TOOLCHAIN,
    })
    commands = []

    def run(label, argv, show=False):
        stdout, stderr = work / (label + ".stdout"), work / (label + ".stderr")
        print(json.dumps({"phase": label, "argv": argv}), flush=True)
        with stdout.open("xb") as out, stderr.open("xb") as err:
            result = subprocess.run(argv, cwd=root, env=env, stdout=out, stderr=err)
        record = {"phase": label, "exit_code": result.returncode,
                  "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
        commands.append(record)
        print(json.dumps(record), flush=True)
        if show or result.returncode:
            print(stdout.read_text(encoding="utf-8", errors="replace")[-24000:], flush=True)
            print(stderr.read_text(encoding="utf-8", errors="replace")[-16000:], flush=True)
        require(result.returncode == 0, "Command failed: " + label)
        return stdout.read_text(encoding="utf-8")

    inputs = (
        "Cargo.toml", "Cargo.lock", "src/storage/ec/Cargo.toml", "src/storage/ec/Cargo.lock",
        "src/storage/chunk_engine/Cargo.toml", "src/storage/chunk_engine/build.rs",
        "src/storage/chunk_engine/src/lib.rs", "src/storage/chunk_engine/src/cxx.rs",
        "src/storage/chunk_engine/src/ec_codec.rs", "scripts/ec/ci/run-codec-tests.py",
        "cmake/AddCrate.cmake", "cmake/EcCodecBackend.cmake",
        "scripts/ec/reference/downloads.json", "src/storage/ec_codec/EcCodec.h",
        "src/storage/ec_codec/EcCodec.cc", "scripts/ec/ci/codec-probe/main.cc",
        "scripts/ec/ci/codec-probe/CMakeLists.txt", "scripts/ec/ci/codec-probe/crate/CMakeLists.txt",
    )
    before = {path: digest(root / path) for path in inputs}
    receipt = {"schema": 1, "revision": args.revision, "inputs_sha256": before,
               "profile": "test, opt-level=0, debug=0", "backend": args.backend,
               "commands": commands, "status": "incomplete"}
    owned_target = False
    try:
        rust = ["rustup", "run", TOOLCHAIN]
        rustc = run("rustc", rust + ["rustc", "--version", "--verbose"], show=True)
        cargo_version = run("cargo", rust + ["cargo", "--version", "--verbose"], show=True)
        require(rustc.startswith("rustc " + TOOLCHAIN + " "), "Unexpected rustc")
        require(cargo_version.startswith("cargo " + TOOLCHAIN + " "), "Unexpected cargo")
        run("packages", ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        provider = None
        if args.backend == "isal":
            # Reuse the fixed official dependency lock, without installing
            # packages system-wide or executing package maintainer scripts.
            lock = json.loads((root / "scripts/ec/reference/downloads.json").read_text(encoding="utf-8"))
            packages = [p for p in lock["packages"] if p["package"] in ("libisal-dev", "libisal2")]
            require(len(packages) == 2 and {p["package"] for p in packages} == {"libisal-dev", "libisal2"},
                    "Expected the two locked ISA-L packages")
            prefix = work / "isal-prefix"
            prefix.mkdir(mode=0o700)
            receipt["isal_packages"] = []
            for item in packages:
                require(item["url"].startswith("https://archive.ubuntu.com/ubuntu/pool/universe/libi/libisal/"),
                        "ISA-L URL is not an official locked Ubuntu source")
                archive = work / (item["package"] + ".deb")
                request = urllib.request.Request(item["url"], headers={"User-Agent": "ec-native-fixed-input/1"})
                with urllib.request.urlopen(request, timeout=60) as response, archive.open("xb") as out:
                    require(response.status == 200 and response.url == item["url"], "Unexpected download redirect")
                    length = 0
                    while True:
                        block = response.read(65536)
                        if not block:
                            break
                        length += len(block)
                        require(length <= item["size"], "Locked ISA-L download is oversized")
                        out.write(block)
                require(length == item["size"] and digest(archive) == item["sha256"], "ISA-L download mismatch")
                metadata = run("metadata-" + item["package"], ["dpkg-deb", "-f", str(archive),
                                                               "Package", "Version", "Architecture"])
                expected_metadata = {"Package": item["package"], "Version": item["version"],
                                     "Architecture": item["architecture"]}
                require(dict(line.split(": ", 1) for line in metadata.splitlines()) == expected_metadata,
                        "Locked ISA-L package metadata mismatch")
                run("extract-" + item["package"], ["dpkg-deb", "-x", str(archive), str(prefix)])
                receipt["isal_packages"].append(item)
            libdir = prefix / "usr/lib/x86_64-linux-gnu"
            provider = (libdir / "libisal.so").resolve(strict=True)
            require(provider.is_relative_to(prefix), "ISA-L provider escaped private prefix")
            env["HF3FS_EC_ISAL_LIBDIR"] = str(libdir)
            env["LD_LIBRARY_PATH"] = str(libdir)
            receipt["isal_provider"] = {"path": str(provider), "sha256": digest(provider)}
        cargo = rust + ["cargo"]
        run("fetch", cargo + ["fetch", "--locked", "--manifest-path", str(root / "Cargo.toml")])
        require(before == {path: digest(root / path) for path in inputs}, "Fetch changed source or lock")
        env["CARGO_NET_OFFLINE"] = "true"
        feature = ["--features", "chunk_engine/isal-backend"] if args.backend == "isal" else []
        output = run("build", cargo + ["test", "--locked", "--offline", "-p", "chunk_engine",
                                      "--lib", "--no-run", "--message-format=json", *feature])
        executables = set()
        for line in output.splitlines():
            event = json.loads(line)
            if (event.get("reason") == "compiler-artifact" and event.get("executable")
                    and event.get("profile", {}).get("test")
                    and event.get("target", {}).get("name") == "chunk_engine"
                    and Path(event["target"]["src_path"]).resolve()
                    == root / "src/storage/chunk_engine/src/lib.rs"):
                executables.add(event["executable"])
        require(len(executables) == 1, "Expected one real chunk_engine library test executable")
        executable = Path(executables.pop()).resolve(strict=True)
        require(executable.is_relative_to(work / "cargo-target"), "Executable escaped fresh target")
        receipt["executable_sha256"] = digest(executable)
        listing = run("list", [str(executable), "ec_codec::tests::", "--list", "--format", "terse"], show=True)
        names = re.findall(r"^(ec_codec::tests::\S+): test$", listing, re.MULTILINE)
        require(len(names) == len(EXPECTED) and set(names) == EXPECTED,
                "Actual test inventory differs from the required bridge tests")
        result = run("test", [str(executable), "ec_codec::tests::", "--test-threads=1", "--show-output"], show=True)
        passed = re.findall(r"^test (ec_codec::tests::\S+) \.\.\. ok$", result, re.MULTILINE)
        require(len(passed) == len(EXPECTED) and set(passed) == EXPECTED, "Missing or non-passing test")
        # Captured successful output follows the intact per-test result lines.
        # Check the same metadata through the generated CXX bridge below.
        marker = "EC_CODEC_BACKEND=" + args.backend
        require(marker in result, "Actual Rust backend marker differs from the requested backend")
        require(re.search(r"^test result: ok\. 10 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;",
                          result, re.MULTILINE), "Unexpected test summary")
        if args.cxx_probe:
            (work / "cargo-target").mkdir(exist_ok=True)
            source_target.symlink_to(work / "cargo-target", target_is_directory=True)
            owned_target = True
            cmake_args = ["cmake", "-S", str(root / "scripts/ec/ci/codec-probe"), "-B", str(work / "cmake"),
                          "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_C_COMPILER=/usr/bin/gcc-12",
                          "-DCMAKE_CXX_COMPILER=/usr/bin/g++-12", "-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g0",
                          "-DHF3FS_EC_BACKEND=" + args.backend]
            if provider is not None:
                cmake_args.append("-DHF3FS_EC_ISAL_ROOT=" + str(prefix))
            run("cmake-configure", cmake_args, show=True)
            run("cmake-build", ["cmake", "--build", str(work / "cmake"), "--target", "ec_codec_bridge_probe", "-j", "1"], show=True)
            probe = work / "cmake/ec_codec_bridge_probe"
            receipt["cxx_probe_sha256"] = digest(probe)
            receipt["rust_staticlib_sha256"] = digest(source_target / "debug/libchunk_engine.a")
            receipt["generated_cxx_sha256"] = {
                suffix: digest(source_target / ("cxxbridge/chunk_engine/src/cxx.rs." + suffix))
                for suffix in ("h", "cc")
            }
            # Prove that CMake's build-time runtime path works; the earlier
            # standalone Rust test required this private loader path explicitly.
            env.pop("LD_LIBRARY_PATH", None)
            run("cxx-ldd", ["ldd", str(probe)], show=True)
            probe_result = json.loads(run("cxx-probe", [str(probe), args.backend] + ([str(provider)] if provider else []), show=True))
            require(probe_result.get("ec_cxx_probe") == "passed" and probe_result.get("backend") == args.backend,
                    "Generated CXX bridge probe did not pass")
            require(probe_result.get("provider") == (str(provider) if provider else ""), "Unexpected CXX provider")
            receipt["cxx_probe"] = probe_result
        if provider is not None:
            require(digest(provider) == receipt["isal_provider"]["sha256"], "ISA-L provider changed")
        require(digest(executable) == receipt["executable_sha256"], "Rust test executable changed")
        require(before == {path: digest(root / path) for path in inputs}, "Build or tests changed source or lock")
        require(not git("status", "--porcelain", "--untracked-files=normal"), "Source tree changed")
        receipt.update(status="passed", passed=sorted(passed), source_and_locks_unchanged=True)
    finally:
        try:
            if owned_target:
                require(source_target.is_symlink() and source_target.resolve() == (work / "cargo-target").resolve(),
                        "Owned Cargo target link was replaced; refusing cleanup")
                source_target.unlink()
        except Exception as error:
            receipt["status"] = "incomplete"
            receipt["target_cleanup_error"] = str(error)
            raise
        finally:
            path = work / "receipt.json"
            path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"codec_bridge_acceptance": receipt, "receipt_sha256": digest(path)}), flush=True)


if __name__ == "__main__":
    main()
