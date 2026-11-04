#!/usr/bin/env python3
"""Exercise the real AddCrate.cmake build graph with a deterministic fake Cargo.

The fixture uses real CMake, Ninja, C/C++ compilation and ar. It does not compile
Rust or test an EC protocol. Output directories must be new; no existing build,
Cargo configuration, compiler configuration or repository source is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time


FAKE_CARGO = r'''#!/usr/bin/env python3
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

root = Path(__file__).resolve().parents[1]
tools = json.loads((root / ".fake-cargo-tools.json").read_text())
profile = "release" if "--release" in sys.argv[1:] else "debug"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def update(path, content):
    if path.exists() and path.read_bytes() == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return True

def number(path, name):
    match = re.search(r"const " + name + r": u32 = ([0-9]+);", path.read_text())
    if not match:
        raise RuntimeError("missing fixture input " + name)
    return int(match.group(1))

def run(command, events):
    completed = subprocess.run(command, text=True, capture_output=True, timeout=30)
    events.append({"argv": command, "returncode": completed.returncode,
                   "stdout": completed.stdout, "stderr": completed.stderr})
    if completed.returncode:
        raise RuntimeError("tool failed: " + repr(events[-1]))

if not sys.argv[1:] or sys.argv[1] != "build":
    raise SystemExit("fixture fake Cargo only supports cargo build [--release]")

event = {"argv": sys.argv, "cwd": os.getcwd(), "profile": profile,
         "start_ns": time.time_ns(), "commands": []}
try:
    with (root / ".fake-cargo.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        api = number(root / "demo/src/cxx.rs", "BRIDGE_API")
        value = number(root / "demo/src/lib.rs", "IMPL_VALUE")
        symbol = "demo_bridge_v" + str(api)
        rust_symbol = "demo_rust_v" + str(api)
        bridge = root / "target/cxxbridge/demo/src"
        header = ("#pragma once\nint " + symbol + "();\n").encode()
        source = ("#include \"demo/src/cxx.rs.h\"\nextern \"C\" int " + rust_symbol
                  + "(void);\nint " + symbol + "() { return " + rust_symbol + "(); }\n").encode()
        changed_header = update(bridge / "cxx.rs.h", header)
        changed_source = update(bridge / "cxx.rs.cc", source)
        target = root / "target" / profile
        target.mkdir(parents=True, exist_ok=True)
        workspace_call = Path.cwd().resolve() == root
        workspace_tool_changed = False
        if workspace_call:
            tool_value = number(root / "trash/src/main.rs", "TOOL_VALUE")
            workspace_tool_changed = update(target / "fake-trash.marker", str(tool_value).encode() + b"\n")
        archive = target / "libdemo.a"
        state = target / ".fake-cargo-input.json"
        current_input = {"api": api, "value": value,
                         "cxx_rs_sha256": digest((root / "demo/src/cxx.rs").read_bytes()),
                         "lib_rs_sha256": digest((root / "demo/src/lib.rs").read_bytes())}
        previous_input = json.loads(state.read_text()) if state.exists() else None
        changed_archive = not archive.exists() or current_input != previous_input
        if changed_archive:
            with tempfile.TemporaryDirectory(prefix="fake-cargo-", dir=target) as temp_name:
                temp = Path(temp_name)
                c_source = temp / "demo_rust.c"
                c_source.write_text("int " + rust_symbol + "(void) { return " + str(value) + "; }\n")
                run([tools["cc"], "-c", str(c_source), "-o", str(temp / "demo_rust.o")], event["commands"])
                run([tools["ar"], "rcs", str(temp / "libdemo.a"), str(temp / "demo_rust.o")], event["commands"])
                os.replace(temp / "libdemo.a", archive)
            update(state, (json.dumps(current_input, sort_keys=True) + "\n").encode())
        event.update({"inputs": current_input, "header_changed": changed_header,
                      "source_changed": changed_source, "archive_changed": changed_archive,
                      "workspace_call": workspace_call, "workspace_tool_changed": workspace_tool_changed})
        event["success"] = True
except BaseException as error:
    event["success"] = False
    event["error"] = repr(error)
    raise
finally:
    event["end_ns"] = time.time_ns()
    with (root / "fake-cargo-events.jsonl").open("a") as log:
        log.write(json.dumps(event, sort_keys=True) + "\n")
'''


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def file_state(path: Path) -> dict:
    if not path.exists():
        return {"path": str(path), "exists": False}
    stat = path.stat()
    return {"path": str(path), "exists": True, "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns, "sha256": sha256(path)}


def snapshot(source: Path, build: Path) -> dict:
    fixed = [source / "demo/src/cxx.rs", source / "demo/src/lib.rs", source / "main.cc",
             source / "target/cxxbridge/demo/src/cxx.rs.h",
             source / "target/cxxbridge/demo/src/cxx.rs.cc",
             source / "target/debug/libdemo.a", build / "app", build / "libdemo.a"]
    files = fixed + sorted(build.rglob("*.o"))
    return {str(path.relative_to(source.parent)): file_state(path) for path in files}


def same_artifact(before: dict, after: dict) -> bool:
    return (before.get("exists") and after.get("exists")
            and before["sha256"] == after["sha256"]
            and before["mtime_ns"] == after["mtime_ns"])


def wait_for_distinct_mtime() -> None:
    # Cover filesystems whose timestamps have only one-second granularity. This
    # is fixture setup, never a production benchmark or part of a timed result.
    time.sleep(1.1)


class Runner:
    def __init__(self, args: argparse.Namespace, tools: dict[str, str]):
        self.args = args
        self.tools = tools
        self.root = args.output_root
        self.command_index = 0
        self.results = {"schema_version": 1, "scope": "CMake generated-source/link dependencies only",
                        "module": file_state(args.cmake_module),
                        "runner": file_state(Path(__file__).resolve()), "tools": tools,
                        "commands": [], "cases": [], "status": "running"}
        self.flush()

    def flush(self) -> None:
        save_json(self.root / "results.json", self.results)

    def command(self, label: str, argv: list[str], cwd: Path, env: dict) -> dict:
        self.command_index += 1
        prefix = f"{self.command_index:02d}-{label}"
        started = time.time_ns()
        try:
            completed = subprocess.run(argv, cwd=cwd, env=env, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=self.args.command_timeout)
            returncode, output = completed.returncode, completed.stdout
            timed_out = False
        except subprocess.TimeoutExpired as error:
            returncode, timed_out = None, True
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
        log_path = self.root / "logs" / (prefix + ".log")
        log_path.write_text(output, encoding="utf-8")
        item = {"label": label, "argv": argv, "shell_display_only": shlex.join(argv),
                "cwd": str(cwd), "path": env.get("PATH"), "returncode": returncode,
                "timed_out": timed_out, "start_ns": started, "end_ns": time.time_ns(),
                "log": str(log_path), "log_sha256": sha256(log_path), "stdout": output}
        self.results["commands"].append(item)
        self.flush()
        return item

    def fixture(self, name: str) -> tuple[Path, Path, dict]:
        case = self.root / name
        source, build = case / "source", case / "build"
        (source / "demo/src").mkdir(parents=True)
        (source / "trash/src").mkdir(parents=True)
        (source / ".fake-bin").mkdir()
        (source / "Cargo.toml").write_text('[workspace]\nmembers = ["demo", "trash"]\ndefault-members = ["demo", "trash"]\nresolver = "2"\n')
        (source / "Cargo.lock").write_text('version = 3\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n')
        (source / "demo/Cargo.toml").write_text('[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n[lib]\ncrate-type = ["staticlib"]\n')
        (source / "demo/build.rs").write_text('fn main() {}\n')
        (source / "trash/Cargo.toml").write_text('[package]\nname = "trash"\nversion = "0.1.0"\nedition = "2021"\n')
        (source / "trash/src/main.rs").write_text('pub const TOOL_VALUE: u32 = 701;\nfn main() {}\n')
        (source / "demo/src/cxx.rs").write_text('pub const BRIDGE_API: u32 = 1;\n')
        (source / "demo/src/lib.rs").write_text('pub const IMPL_VALUE: u32 = 101;\n')
        self.write_main(source, 1)
        # Include the supplied repository module itself; its implementation is
        # deliberately neither copied nor approximated in this fixture.
        (source / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.20)
project(AddCrateDependencyFixture LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
include("${ADD_CRATE_MODULE}")
add_crate(demo)
add_executable(app main.cc)
target_link_libraries(app PRIVATE demo)
''')
        fake = source / ".fake-bin/cargo"
        fake.write_text(FAKE_CARGO, encoding="utf-8")
        fake.chmod(0o755)
        save_json(source / ".fake-cargo-tools.json", self.tools)
        env = os.environ.copy()
        env["PATH"] = str(fake.parent) + os.pathsep + env.get("PATH", "")
        # A caller's Cargo target override must not redirect this isolated fixture.
        env.pop("CARGO_TARGET_DIR", None)
        return source, build, env

    @staticmethod
    def write_main(source: Path, api: int) -> None:
        (source / "main.cc").write_text('#include "demo/src/cxx.rs.h"\n#include <cstdio>\n'
                                      f'int main() {{ std::printf("%d\\n", demo_bridge_v{api}()); }}\n')

    def build(self, name: str, build: Path, env: dict) -> dict:
        return self.command(name, [self.tools["cmake"], "--build", str(build),
                                  "--parallel", "1", "--verbose"], build.parent, env)

    def run_app(self, name: str, build: Path, env: dict) -> dict:
        return self.command(name, [str(build / "app")], build.parent, env)

    def run_case(self, name: str) -> None:
        source, build, env = self.fixture(name)
        case = {"name": name, "checks": [], "status": "running"}
        self.results["cases"].append(case)

        def check(description: str, passed: bool, details: object = None) -> None:
            case["checks"].append({"description": description, "passed": bool(passed), "details": details})

        config = self.command(name + "-configure", [self.tools["cmake"], "-S", str(source), "-B", str(build),
                              "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Debug",
                              "-DCMAKE_C_COMPILER=" + self.tools["cc"],
                              "-DCMAKE_CXX_COMPILER=" + self.tools["cxx"],
                              "-DCMAKE_MAKE_PROGRAM=" + self.tools["ninja"],
                              "-DADD_CRATE_MODULE=" + str(self.args.cmake_module)], source, env)
        check("configure succeeds", config["returncode"] == 0)
        if config["returncode"] != 0:
            case["status"] = "failed"
            self.flush()
            return
        initial = self.build(name + "-initial-build", build, env)
        check("clean build succeeds", initial["returncode"] == 0)
        if initial["returncode"] != 0:
            case["status"] = "failed"
            self.flush()
            return
        result = self.run_app(name + "-initial-app", build, env)
        check("clean application prints 101", result["returncode"] == 0 and result["stdout"].strip() == "101")
        marker = source / "target/debug/fake-trash.marker"
        check("workspace default-member marker was generated", marker.exists() and marker.read_text().strip() == "701")
        prior_events = len((source / "fake-cargo-events.jsonl").read_text().splitlines())
        before = snapshot(source, build)
        save_json(source.parent / "before.json", before)
        wait_for_distinct_mtime()
        if name == "api-change":
            (source / "demo/src/cxx.rs").write_text('pub const BRIDGE_API: u32 = 2;\n')
            self.write_main(source, 2)
        elif name == "implementation-only":
            (source / "demo/src/lib.rs").write_text('pub const IMPL_VALUE: u32 = 202;\n')
        changed = self.build(name + "-single-rebuild", build, env)
        check("exactly one rebuild succeeds", changed["returncode"] == 0)
        new_events = [json.loads(line) for line in (source / "fake-cargo-events.jsonl").read_text().splitlines()[prior_events:]]
        check("rebuild actually invoked Cargo, including workspace defaults",
              bool(new_events) and any(event.get("workspace_call") for event in new_events), new_events)
        after = snapshot(source, build)
        save_json(source.parent / "after.json", after)
        if changed["returncode"] == 0:
            result = self.run_app(name + "-rebuilt-app", build, env)
            expected = "202" if name == "implementation-only" else "101"
            check("application observes expected result after one build",
                  result["returncode"] == 0 and result["stdout"].strip() == expected,
                  {"expected": expected, "actual": result["stdout"].strip()})
        objects = [key for key in before if key.endswith(".o")]
        check("real main and bridge objects exist", len(objects) >= 2, objects)
        if name == "clean-noop":
            retained = objects + ["build/app", "build/libdemo.a", "source/target/debug/libdemo.a",
                                  "source/target/cxxbridge/demo/src/cxx.rs.h",
                                  "source/target/cxxbridge/demo/src/cxx.rs.cc"]
            check("no-op preserves object/application/library/bridge mtimes and content",
                  all(same_artifact(before[key], after[key]) for key in retained), retained)
            wait_for_distinct_mtime()
            (source / "trash/src/main.rs").write_text('pub const TOOL_VALUE: u32 = 702;\nfn main() {}\n')
            tool_rebuild = self.build(name + "-workspace-tool-rebuild", build, env)
            tool_after = snapshot(source, build)
            save_json(source.parent / "workspace-tool-after.json", tool_after)
            check("workspace default-member change is built without crate/bridge changes",
                  tool_rebuild["returncode"] == 0 and marker.exists() and marker.read_text().strip() == "702")
            check("workspace-only change preserves bridge/main objects and application",
                  all(same_artifact(after[key], tool_after[key]) for key in retained), retained)
        elif name == "api-change":
            check("fixture changed both main and generated bridge API",
                  before["source/main.cc"]["sha256"] != after["source/main.cc"]["sha256"]
                  and before["source/target/cxxbridge/demo/src/cxx.rs.h"]["sha256"]
                  != after["source/target/cxxbridge/demo/src/cxx.rs.h"]["sha256"])
        else:
            fixed = objects + ["source/main.cc", "source/target/cxxbridge/demo/src/cxx.rs.h",
                               "source/target/cxxbridge/demo/src/cxx.rs.cc"]
            check("implementation-only leaves main/bridge/object content and mtimes unchanged",
                  all(same_artifact(before[key], after[key]) for key in fixed), fixed)
            check("implementation-only really changed the Cargo archive",
                  before["source/target/debug/libdemo.a"]["sha256"]
                  != after["source/target/debug/libdemo.a"]["sha256"])
            check("implementation-only relinks the application",
                  before["build/app"]["mtime_ns"] != after["build/app"]["mtime_ns"]
                  and before["build/app"]["sha256"] != after["build/app"]["sha256"])
        case["status"] = "passed" if all(item["passed"] for item in case["checks"]) else "failed"
        self.flush()

    def run(self) -> int:
        for name, command in (("cmake", [self.tools["cmake"], "--version"]),
                              ("ninja", [self.tools["ninja"], "--version"]),
                              ("cc", [self.tools["cc"], "--version"]),
                              ("cxx", [self.tools["cxx"], "--version"]),
                              ("ar", [self.tools["ar"], "--version"])):
            self.command("tool-" + name, command, self.root, os.environ.copy())
        for name in ("clean-noop", "api-change", "implementation-only"):
            self.run_case(name)
        check_module = sha256(self.args.cmake_module) == self.results["module"]["sha256"]
        self.results["module_unchanged_during_run"] = check_module
        self.results["status"] = "passed" if check_module and all(
            case["status"] == "passed" for case in self.results["cases"]) else "failed"
        self.results["artifact_hashes"] = {
            str(path.relative_to(self.root)): sha256(path)
            for path in sorted(self.root.rglob("*"))
            if path.is_file() and path.name != "results.json"
        }
        self.flush()
        print(json.dumps({"status": self.results["status"], "results": str(self.root / "results.json"),
                          "cases": [{"name": case["name"], "status": case["status"]}
                                    for case in self.results["cases"]]}, indent=2))
        return 0 if self.results["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmake-module", type=Path, required=True,
                        help="absolute or relative path to the actual before/candidate AddCrate.cmake")
    parser.add_argument("--output-root", type=Path, required=True, help="new, nonexistent result/fixture directory")
    parser.add_argument("--command-timeout", type=float, default=120, help="seconds per real command (default 120)")
    args = parser.parse_args()
    args.cmake_module = args.cmake_module.resolve(strict=True)
    args.output_root = args.output_root.resolve()
    if os.name != "posix":
        parser.error("execution requires a POSIX host with real CMake, Ninja, C/C++ compilers and ar")
    if not args.cmake_module.is_file() or args.command_timeout <= 0:
        parser.error("module must be a regular file and command timeout must be positive")
    tools = {}
    for name, executable in (("cmake", "cmake"), ("ninja", "ninja"), ("cc", "cc"), ("cxx", "c++"), ("ar", "ar")):
        path = shutil.which(executable)
        if path is None:
            parser.error("required real tool is unavailable: " + executable)
        tools[name] = str(Path(path).resolve())
    try:
        args.output_root.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error("output-root already exists; choose a new directory, existing evidence is never overwritten")
    (args.output_root / "logs").mkdir()
    runner = Runner(args, tools)
    try:
        return runner.run()
    except BaseException as error:
        runner.results["status"] = "harness-error"
        runner.results["error"] = repr(error)
        runner.flush()
        raise


if __name__ == "__main__":
    raise SystemExit(main())
