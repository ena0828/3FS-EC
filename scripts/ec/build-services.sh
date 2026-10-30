#!/usr/bin/env bash
# Build the original services in a separate Linux source mirror.
set -euo pipefail

source_root="${THREEFS_SOURCE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}"
native_root="${THREEFS_NATIVE_ROOT:-/mnt/3fsec-build/3FS-EC}"
build_dir="${THREEFS_CPP_BUILD_DIR:-/mnt/3fsec-build/artifacts/cpp-build}"
cargo_target="${CARGO_TARGET_DIR:-/mnt/3fsec-build/artifacts/cargo-target}"
gcc_toolchain="${THREEFS_GCC_TOOLCHAIN:-}"
jobs="${THREEFS_BUILD_JOBS:-2}"
configure_only=false
targets=()

usage() {
    cat <<'EOF'
Usage: build-services.sh [options] [-- target ...]
  --source DIR          Authoritative checkout (default: this script's checkout)
  --native-root DIR     Separate Linux source mirror
  --build-dir DIR       CMake build directory
  --cargo-target DIR    Shared native Cargo output directory
  --gcc-toolchain DIR   Private GCC 12 layout used by Clang 14
  --jobs N              Build concurrency, default 2
  --configure-only      Synchronize and configure, without building services
  --help                Show this message
Default targets: storage_main mgmtd_main meta_main admin_cli
                 hf3fs_fuse_main monitor_collector_main

Existing mirror files replaced by synchronization are backed up. No --delete
is used; unexpected source files in the mirror are rejected. A nonmatching
source/target path is never overwritten. Do not run during another build in
the mirror. CARGO_HOME and RUSTUP_HOME may select an existing Linux toolchain.
EOF
}

while (($#)); do
    case "$1" in
        --source|--native-root|--build-dir|--cargo-target|--gcc-toolchain|--jobs)
            (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
            case "$1" in
                --source) source_root=$2 ;;
                --native-root) native_root=$2 ;;
                --build-dir) build_dir=$2 ;;
                --cargo-target) cargo_target=$2 ;;
                --gcc-toolchain) gcc_toolchain=$2 ;;
                --jobs) jobs=$2 ;;
            esac
            shift 2 ;;
        --configure-only) configure_only=true; shift ;;
        --help) usage; exit 0 ;;
        --) shift; targets=("$@"); break ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] && ((jobs <= 16)) || { echo "--jobs must be 1..16" >&2; exit 2; }
if ((${#targets[@]} == 0)); then
    targets=(storage_main mgmtd_main meta_main admin_cli hf3fs_fuse_main monitor_collector_main)
fi

source_root=$(realpath -e -- "$source_root")
native_root=$(realpath -m -- "$native_root")
native_git_root=$(git -C "$native_root" rev-parse --show-toplevel 2>/dev/null || true)
[[ "$native_git_root" == "$native_root" ]] || {
    echo "--native-root must already be an independent Git clone; see docs/ec/reproduction-manual.md" >&2
    exit 2
}
build_dir=$(realpath -m -- "$build_dir")
cargo_target=$(realpath -m -- "$cargo_target")
gcc_toolchain=$(realpath -m -- "${gcc_toolchain:-$(dirname -- "$native_root")/toolchains/gcc12}")
[[ -f "$source_root/CMakeLists.txt" && -f "$source_root/.gitmodules" ]] || {
    echo "--source must identify a 3FS checkout" >&2; exit 2;
}
export CARGO_HOME="${CARGO_HOME:-$(dirname -- "$native_root")/toolchains/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$(dirname -- "$native_root")/toolchains/rustup}"
# Avoid costly probes of Windows PATH directories through WSL's 9P mount.
export PATH="$CARGO_HOME/bin:/usr/lib/llvm-14/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_TARGET_DIR="$cargo_target"
export CARGO_BUILD_JOBS="$jobs"
export CMAKE_BUILD_PARALLEL_LEVEL="$jobs"
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-18/lib}"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

for command in python3 rsync git cmake ninja clang-14 clang++-14 g++-12 cargo flock; do
    command -v "$command" >/dev/null || { echo "Required command not found: $command" >&2; exit 2; }
done
[[ -x /usr/bin/clang-format-14 ]] || { echo "Install clang-format-14 before configuring" >&2; exit 2; }

python3 - "$source_root" "$native_root" "$build_dir" "$cargo_target" "$gcc_toolchain" <<'PY'
import os, pathlib, sys
source, native, build, cargo, gcc = map(pathlib.Path, sys.argv[1:])
if source == native or native.is_relative_to(source) or source.is_relative_to(native):
    raise SystemExit("Authoritative checkout and mirror must be disjoint directories")
for output in (build, cargo):
    if output == native or native.is_relative_to(output) or output.is_relative_to(native) or output.is_relative_to(source) or source.is_relative_to(output):
        raise SystemExit("Source checkouts and output directories must be disjoint")
if build == cargo or build.is_relative_to(cargo) or cargo.is_relative_to(build):
    raise SystemExit("CMake and Cargo output directories must be disjoint")
for protected in (source, native, build, cargo):
    if gcc == protected or gcc.is_relative_to(protected) or protected.is_relative_to(gcc):
        raise SystemExit("Private GCC layout must be separate from sources and build outputs")
target = native / "target"
if target.exists() or target.is_symlink():
    if not target.is_symlink() or target.resolve() != cargo:
        raise SystemExit(f"Refusing to replace existing nonmatching path: {target}")
for process in pathlib.Path("/proc").iterdir():
    if not process.name.isdigit():
        continue
    try:
        name = (process / "comm").read_text().strip()
        cwd = (process / "cwd").resolve(strict=True)
        args = (process / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except (OSError, ProcessLookupError):
        continue
    if name in {"cargo", "rustc", "cmake", "ninja", "make", "cc1plus", "clang", "clang++"}:
        if cwd.is_relative_to(native) or str(build) in args or str(cargo) in args:
            raise SystemExit(f"Refusing source synchronization during active build {process.name}: {name}")
# Stale extra translation units can enter CMake's recursive source globs.
suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".cmake"}
extras = []
for directory in ("src", "tests", "benchmarks", "cmake"):
    base = native / directory
    if not base.exists():
        continue
    for root, directories, files in os.walk(base):
        directories[:] = [name for name in directories if name not in {"target", "build", "__pycache__", ".cache", ".git"}]
        for name in files:
            file = pathlib.Path(root) / name
            if file.suffix in suffixes or file.name == "CMakeLists.txt":
                relative = file.relative_to(native)
                if not (source / relative).exists():
                    extras.append(str(relative))
if extras:
    raise SystemExit("Mirror has extra source files; preserve and reconcile them explicitly:\n" + "\n".join(extras[:30]))
PY

mkdir -p -- "$native_root" "$build_dir" "$cargo_target"
exec 9>"$build_dir/ec-services.lock"
flock -n 9 || { echo "Another build-services.sh owns this build directory" >&2; exit 2; }
run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
run_dir="$build_dir/ec-runs/$run_id"
backup_dir="$build_dir/ec-source-backups/$run_id"
mkdir -p -- "$run_dir" "$backup_dir"
exec > >(tee -a "$run_dir/build.log") 2>&1
trap 'result=$?; if ((result)); then echo "build-services failed: exit=$result line=$LINENO log=$run_dir/build.log"; fi' EXIT

printf 'Authoritative source: %s\nNative mirror: %s\nBuild directory: %s\nJobs: %s\n' \
    "$source_root" "$native_root" "$build_dir" "$jobs"
git -C "$source_root" rev-parse HEAD > "$run_dir/source-head.txt"
git -C "$source_root" status --porcelain --ignore-submodules=all > "$run_dir/source-status.txt"
git -C "$source_root" submodule status --recursive > "$run_dir/submodules.txt"
git -C "$source_root" diff HEAD --binary --ignore-submodules=all > "$run_dir/source-tracked.patch"

rsync -a --checksum --no-perms --no-owner --no-group --safe-links \
    --backup --backup-dir="$backup_dir" \
    --exclude='.git' --exclude='target/' --exclude='__pycache__/' --exclude='/build/' \
    --exclude='/artifacts/' --exclude='/.cache/' \
    "$source_root/" "$native_root/"

# Windows archives lose Unix mode bits. Recover tracked modes from Git, not
# from DrvFS's synthetic permissions. Preserve submodule revision contents.
python3 - "$source_root" "$native_root" "$run_dir" <<'PY'
import json, pathlib, subprocess, sys
source, native, run = map(pathlib.Path, sys.argv[1:])
modules = [pathlib.Path(".")]
listed = subprocess.run(["git", "-C", str(source), "config", "-f", ".gitmodules", "--get-regexp", "path"], capture_output=True, text=True, check=True)
modules += [pathlib.Path(line.split(None, 1)[1]) for line in listed.stdout.splitlines()]
count = 0
for module in modules:
    raw = subprocess.check_output(["git", "-C", str(source / module), "ls-files", "--stage", "-z"])
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, relative = entry.split(b"\t", 1)
        mode = metadata.split()[0]
        if mode not in {b"100644", b"100755"}:
            continue
        file = native / module / relative.decode()
        if file.is_file() and not file.is_symlink():
            file.chmod(0o755 if mode == b"100755" else 0o644)
            count += 1
native_head = subprocess.run(["git", "-C", str(native), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
snapshot = {"source": str(source), "native": str(native), "source_head": (run / "source-head.txt").read_text().strip(), "native_git_head": native_head, "restored_modes": count, "method": "rsync-checksum-with-backups-no-delete"}
(run / "source-snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
print(json.dumps(snapshot))
if snapshot["source_head"] != native_head:
    print("Native Git metadata was preserved; binary Git strings may describe the older mirror HEAD. Use source-snapshot.json and source-status.txt for this build's provenance.")
PY

# Clang 14 cannot compile GCC 13's <chrono>. Keep the system compiler intact
# and select GCC 12 headers/start files using a separate, explicit layout.
python3 - "$gcc_toolchain" <<'PY'
import pathlib, subprocess, sys
base = pathlib.Path(sys.argv[1])
triple = subprocess.check_output(["g++-12", "-dumpmachine"], text=True).strip()
links = {
    f"lib/gcc/{triple}/12": f"/usr/lib/gcc/{triple}/12",
    "include/c++/12": "/usr/include/c++/12",
    f"include/{triple}/c++/12": f"/usr/include/{triple}/c++/12",
    f"lib/{triple}": f"/usr/lib/{triple}",
}
for relative, destination in links.items():
    target, link = pathlib.Path(destination), base / relative
    if not target.is_dir():
        raise SystemExit(f"Missing GCC 12 development directory: {target}")
    if link.exists() or link.is_symlink():
        if not link.is_symlink() or link.resolve() != target.resolve():
            raise SystemExit(f"Refusing to replace GCC layout path: {link}")
    else:
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target, target_is_directory=True)
print(f"Clang GCC toolchain: {base}")
PY

if [[ ! -L "$native_root/target" ]]; then
    ln -s -- "$cargo_target" "$native_root/target"
fi
[[ "$(realpath -e -- "$native_root/target")" == "$cargo_target" ]] || {
    echo "Native target path does not resolve to requested Cargo output" >&2; exit 2;
}
ulimit -n 65536
cmake_command=(cmake -S "$native_root" -B "$build_dir" -G Ninja
    -DCMAKE_CXX_COMPILER=clang++-14 -DCMAKE_C_COMPILER=clang-14
    "-DCMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN=$gcc_toolchain"
    "-DCMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN=$gcc_toolchain"
    -DCMAKE_BUILD_TYPE=Debug -DDEBUG_INFO_FLAGS=-g0
    '-DCMAKE_C_FLAGS_DEBUG=-O0 -g0' '-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g0'
    -DFOLLY_CXX_FLAGS=-g0
    -DSHUFFLE_METHOD=g++11 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    "-DHF3FS_EXTERNAL_BUILD_JOBS=$jobs")
printf '%q ' "${cmake_command[@]}"; printf '\n'
"${cmake_command[@]}"
if "$configure_only"; then
    printf 'Configuration completed; no service build requested. Log: %s\n' "$run_dir/build.log"
    exit 0
fi
build_command=(cmake --build "$build_dir" --parallel "$jobs" --target "${targets[@]}")
printf '%q ' "${build_command[@]}"; printf '\n'
"${build_command[@]}"
printf 'Service build completed. Binaries: %s/bin\nLog: %s\n' "$build_dir" "$run_dir/build.log"
