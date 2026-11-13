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
    )
    before = {path: digest(root / path) for path in inputs}
    receipt = {"schema": 1, "revision": args.revision, "inputs_sha256": before,
               "profile": "test, opt-level=0, debug=0", "backend": "Scalar",
               "commands": commands, "status": "incomplete"}
    try:
        rust = ["rustup", "run", TOOLCHAIN]
        rustc = run("rustc", rust + ["rustc", "--version", "--verbose"], show=True)
        cargo_version = run("cargo", rust + ["cargo", "--version", "--verbose"], show=True)
        require(rustc.startswith("rustc " + TOOLCHAIN + " "), "Unexpected rustc")
        require(cargo_version.startswith("cargo " + TOOLCHAIN + " "), "Unexpected cargo")
        run("packages", ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        cargo = rust + ["cargo"]
        run("fetch", cargo + ["fetch", "--locked", "--manifest-path", str(root / "Cargo.toml")])
        require(before == {path: digest(root / path) for path in inputs}, "Fetch changed source or lock")
        env["CARGO_NET_OFFLINE"] = "true"
        output = run("build", cargo + ["test", "--locked", "--offline", "-p", "chunk_engine",
                                      "--lib", "--no-run", "--message-format=json"])
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
                "Actual test inventory differs from the nine required bridge tests")
        result = run("test", [str(executable), "ec_codec::tests::", "--test-threads=1", "--nocapture"], show=True)
        passed = re.findall(r"^test (ec_codec::tests::\S+) \.\.\. ok$", result, re.MULTILINE)
        require(len(passed) == len(EXPECTED) and set(passed) == EXPECTED, "Missing or non-passing test")
        require(re.search(r"^test result: ok\. 9 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;",
                          result, re.MULTILINE), "Unexpected test summary")
        require(before == {path: digest(root / path) for path in inputs}, "Build or tests changed source or lock")
        require(not git("status", "--porcelain", "--untracked-files=normal"), "Source tree changed")
        receipt.update(status="passed", passed=sorted(passed), source_and_locks_unchanged=True)
    finally:
        path = work / "receipt.json"
        path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"codec_bridge_acceptance": receipt, "receipt_sha256": digest(path)}), flush=True)


if __name__ == "__main__":
    main()
