#!/usr/bin/env bash
# One fresh, disposable GitHub-hosted runner; no cache, service or mount here.
set -euo pipefail
umask 077
with_lab=false
if [[ "${1:-}" == --with-lab-targets && "$#" == 1 ]]; then
    with_lab=true
elif (($#)); then
    echo 'Usage: build-native.sh [--with-lab-targets]' >&2; exit 2
fi

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]] || {
    echo "This entry point requires a fresh Linux GitHub-hosted job" >&2; exit 2;
}
[[ "$(id -u)" != 0 && "$(uname -m)" == x86_64 ]] || {
    echo "Use the ordinary x86_64 runner user" >&2; exit 2;
}
source_root=$(realpath -e -- "${GITHUB_WORKSPACE:?}")
runner_temp=$(realpath -e -- "${RUNNER_TEMP:?}")
work="$runner_temp/ec-native"
[[ "$(git -C "$source_root" rev-parse --show-toplevel)" == "$source_root" ]]
[[ "$(git -C "$source_root" rev-parse HEAD)" == "${GITHUB_SHA:?}" ]]
git -C "$source_root" diff --quiet HEAD --ignore-submodules=all
git -C "$source_root" submodule foreach --recursive 'git diff --quiet HEAD && test -z "$(git ls-files --others --exclude-standard)"'
[[ ! -e "$work" && ! -L "$work" && ! -e "$source_root/target" && ! -L "$source_root/target" ]] || {
    echo "Refusing to reuse an existing build or Cargo target directory" >&2; exit 2;
}
mkdir -m 700 -- "$work"
mkdir -- "$work/provenance" "$work/cargo-target" "$work/bin"
cd -- "$source_root"
trap 'rc=$?; printf "native build exit=%s at %s\n" "$rc" "$(date -u +%FT%TZ)"; df -h -- "$work"; exit "$rc"' EXIT

printf 'source=%s revision=%s work=%s\n' "$source_root" "$GITHUB_SHA" "$work"
uname -a
id
getconf _NPROCESSORS_ONLN
head -n 5 /proc/meminfo
df -B1 -- "$source_root" "$work"
findmnt -n -o FSTYPE,OPTIONS -T "$work"
git rev-parse HEAD > "$work/provenance/source-head.txt"
git submodule status --recursive | tee "$work/provenance/submodules.txt"
sha256sum Cargo.lock src/storage/ec/Cargo.lock > "$work/provenance/cargo-locks.sha256"
sha256sum scripts/ec/install-build-deps.sh scripts/ec/cluster/fetch-fdb.sh \
    patches/apply.sh patches/folly.patch patches/rocksdb.patch patches/rocksdb.patch.2 \
    cmake/AddCrate.cmake cmake/ApacheArrow.cmake cmake/Jemalloc.cmake \
    scripts/ec/ci/build-native.sh scripts/ec/ci/run-core-tests.py \
    .github/workflows/ec-hosted-native.yml | tee "$work/provenance/build-inputs.sha256"

# Reuse the repository's dependency set, including Arrow's transitive closure.
# No system FoundationDB package hooks or services are installed.
sudo -n bash "$source_root/scripts/ec/install-build-deps.sh"
dpkg-query -W -f='${Package}\t${Version}\n' > "$work/provenance/dpkg-packages.txt"
sha256sum "$work/provenance/dpkg-packages.txt"
for tool in clang-14 clang++-14 g++-12 gcc-12 cmake ninja meson rustup cargo python3; do
    command -v "$tool"
    "$tool" --version
done
python3 - <<'PY'
import re
import subprocess
version = subprocess.check_output(["cmake", "--version"], text=True).splitlines()[0]
match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
if not match or tuple(map(int, match.groups())) < (3, 28, 0):
    raise SystemExit("CMake >= 3.28 is required to avoid Arrow's legacy explicit -j8 path")
PY

# Child ExternalProjects do not inherit the top-level Clang toolchain flags.
# Give them an explicit GCC 12 compiler instead of Clang with GCC 13+ headers.
export CC=/usr/bin/gcc-12
export CXX=/usr/bin/g++-12
export CMAKE_BUILD_PARALLEL_LEVEL=1
export CARGO_BUILD_JOBS=1
export MAKEFLAGS=-j1
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
export LD_LIBRARY_PATH=/usr/local/lib

bash "$source_root/scripts/ec/cluster/fetch-fdb.sh" "$work/fdb"
sudo -n install -d /usr/local/include/foundationdb
sudo -n cp -a "$work/fdb/fdb-package/usr/include/foundationdb/." /usr/local/include/foundationdb/
sudo -n install -m 755 "$work/fdb/lib/libfdb_c.so" /usr/local/lib/libfdb_c.so
cat "$work/fdb/fdb-binaries.sha256"

gcc_toolchain="$work/gcc12"
python3 - "$gcc_toolchain" <<'PY'
from pathlib import Path
import subprocess
import sys
base = Path(sys.argv[1])
triple = subprocess.check_output(["g++-12", "-dumpmachine"], text=True).strip()
links = {
    f"lib/gcc/{triple}/12": f"/usr/lib/gcc/{triple}/12",
    "include/c++/12": "/usr/include/c++/12",
    f"include/{triple}/c++/12": f"/usr/include/{triple}/c++/12",
    f"lib/{triple}": f"/usr/lib/{triple}",
}
for relative, destination in links.items():
    target = Path(destination)
    if not target.is_dir():
        raise SystemExit(f"Missing GCC 12 layout input: {target}")
    link = base / relative
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target, target_is_directory=True)
print("Explicit top-level Clang GCC layout:", base)
PY

# Clang/lld does not use LD_LIBRARY_PATH as a link-time -L search path.
# Fail before libfuse, Cargo and Arrow builds if the actual compiler/layout/linker
# cannot link and load the exact installed FDB client. This starts no FDB network.
cmp -- "$work/fdb/lib/libfdb_c.so" /usr/local/lib/libfdb_c.so
cat > "$work/provenance/fdb-link-probe.cc" <<'CPP'
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define FDB_API_VERSION 710
#include <foundationdb/fdb_c.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstring>

int main() {
    const int maximum = fdb_get_max_api_version();
    const char* version = fdb_get_client_version();
    // dlsym avoids dladdr mistaking an executable PLT trampoline for the DSO.
    void* symbol = dlsym(RTLD_DEFAULT, "fdb_get_max_api_version");
    Dl_info provider{};
    if (maximum != FDB_LATEST_API_VERSION || maximum < FDB_API_VERSION || !version ||
        std::strlen(version) > 256 || !symbol || !dladdr(symbol, &provider) ||
        !provider.dli_fname || std::strlen(provider.dli_fname) > 4096) {
        return 1;
    }
    std::printf("%d\n%s\n%s\n", maximum, version, provider.dli_fname);
    return 0;
}
CPP
fdb_probe_argv=(/usr/bin/clang++-14 "--gcc-toolchain=$gcc_toolchain"
    -std=c++20 -O0 -g0 -fcoroutines-ts -fuse-ld=lld -I/usr/local/include
    -L/usr/local/lib "$work/provenance/fdb-link-probe.cc" -lfdb_c -ldl -latomic
    -o "$work/provenance/fdb-link-probe")
printf '%q ' "${fdb_probe_argv[@]}" > "$work/provenance/fdb-link-probe.argv"
printf '\n' >> "$work/provenance/fdb-link-probe.argv"
"${fdb_probe_argv[@]}"
"$work/provenance/fdb-link-probe" > "$work/provenance/fdb-link-probe.out"
python3 - "$work" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

work = Path(sys.argv[1])
provenance = work / 'provenance'
rows = (provenance / 'fdb-link-probe.out').read_text().splitlines()
if len(rows) != 3 or rows[0] != '730':
    raise SystemExit('FDB probe returned an unexpected 7.3.63 API/record shape')
provider = Path(rows[2]).resolve(strict=True)
installed = Path('/usr/local/lib/libfdb_c.so').resolve(strict=True)
expected = work / 'fdb/lib/libfdb_c.so'
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
if provider != installed or sha(provider) != sha(expected):
    raise SystemExit('FDB probe loaded a different client library')
record = {'schema': 1, 'status': 'linked-and-loaded-fixed-client',
          'maximum_api_version': int(rows[0]), 'requested_header_api': 710,
          'client_version': rows[1], 'provider': str(provider), 'provider_sha256': sha(provider),
          'expected_package_library_sha256': sha(expected),
          'gcc_toolchain': str(work / 'gcc12'), 'linker': 'lld',
          'link_search_directory': '/usr/local/lib', 'fdb_network_started': False,
          'probe_sha256': sha(provenance / 'fdb-link-probe'),
          'probe_source_sha256': sha(provenance / 'fdb-link-probe.cc'),
          'argv_sha256': sha(provenance / 'fdb-link-probe.argv')}
with (provenance / 'fdb-link-probe.json').open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps(record))
PY

# Ubuntu 24.04's libfuse 3.14 is below this tree's required >= 3.16.1.
fuse_revision=7a92727d97c10290b3501d86a194738973edb61d
git init -q "$work/libfuse"
git -C "$work/libfuse" remote add origin https://github.com/libfuse/libfuse.git
git -C "$work/libfuse" fetch --depth 1 origin "$fuse_revision"
git -C "$work/libfuse" checkout --detach FETCH_HEAD
[[ "$(git -C "$work/libfuse" rev-parse HEAD)" == "$fuse_revision" ]]
meson setup "$work/libfuse-build" "$work/libfuse" --prefix=/usr/local --libdir=lib \
    --buildtype=release -Dtests=false -Dexamples=false -Dinitscriptdir=
ninja -C "$work/libfuse-build" -j1
sudo -n ninja -C "$work/libfuse-build" -j1 install
sudo -n ldconfig
[[ "$(pkg-config --modversion fuse3)" == 3.16.2 ]]
printf 'libfuse_revision=%s libfuse_version=%s\n' "$fuse_revision" "$(pkg-config --modversion fuse3)"
sha256sum /usr/local/lib/libfuse3.so.3 /usr/local/lib/libfdb_c.so

# Preserve both checked-in locks. The local wrapper also adds --locked to
# CMake's existing cargo build commands; no production CMake edit is needed.
export RUSTUP_TOOLCHAIN=1.99.1
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
export EC_REAL_CARGO
EC_REAL_CARGO=$(command -v cargo)
export CARGO_HOME="$work/cargo-home"
export CARGO_TARGET_DIR="$work/cargo-target"
rustc --version --verbose
"$EC_REAL_CARGO" --version --verbose
[[ "$(rustc --version)" == 'rustc 1.99.1 '* ]]
[[ "$("$EC_REAL_CARGO" --version)" == 'cargo 1.99.1 '* ]]
cat > "$work/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == build ]]; then
    shift
    exec "${EC_REAL_CARGO:?}" build --locked "$@"
fi
exec "${EC_REAL_CARGO:?}" "$@"
SH
chmod 700 "$work/bin/cargo"
export PATH="$work/bin:$PATH"
cargo fetch --locked --manifest-path "$source_root/Cargo.toml"
cargo fetch --locked --manifest-path "$source_root/src/storage/ec/Cargo.toml"
export CARGO_NET_OFFLINE=true
sha256sum --check "$work/provenance/cargo-locks.sha256"

# Fresh submodules plus these tracked patches reproduce the C++ input edits.
bash "$source_root/patches/apply.sh"
git -C third_party/rocksdb apply --reverse --check ../../patches/rocksdb.patch.2
git -C third_party/folly apply --reverse --check ../../patches/folly.patch
git -C third_party/folly diff --binary | sha256sum
git -C third_party/rocksdb diff --binary | sha256sum

ln -s -- "$work/cargo-target" "$source_root/target"
ulimit -n 65536
cmake -S "$source_root" -B "$work/build" -G Ninja \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 -DCMAKE_C_COMPILER=/usr/bin/clang-14 \
    "-DCMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN=$gcc_toolchain" \
    "-DCMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN=$gcc_toolchain" \
    -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASSERTIONS=ON -DDEBUG_INFO_FLAGS=-g0 \
    '-DCMAKE_C_FLAGS_DEBUG=-O0 -g0' '-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g0' \
    -DFOLLY_CXX_FLAGS=-g0 -DSHUFFLE_METHOD=g++11 -DENABLE_FUSE_APPLICATION=ON \
    '-DCMAKE_EXE_LINKER_FLAGS=-L/usr/local/lib' \
    '-DCMAKE_SHARED_LINKER_FLAGS=-L/usr/local/lib' \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DHF3FS_EXTERNAL_BUILD_JOBS=1
cmake --build "$work/build" --parallel 1 --target test_meta test_fuse_ec
if "$with_lab"; then
    cmake --build "$work/build" --parallel 1 --target storage_main mgmtd_main meta_main admin_cli \
        ec_stripe_cli ec_file_cli hf3fs_fuse_main ec_mount_read_probe
fi
[[ "$(git -C "$work/build/src/apache-arrow-cpp" rev-parse HEAD)" == b7d2f7ffca66c868bd2fce5b3749c6caa002a7f0 ]]
printf 'Arrow actual checkout: '
git -C "$work/build/src/apache-arrow-cpp" rev-parse HEAD
sha256sum --check "$work/provenance/cargo-locks.sha256"
git diff --exit-code HEAD --ignore-submodules=all
sha256sum "$work/build/CMakeCache.txt" "$work/build/compile_commands.json" \
    "$work/build/tests/test_meta" "$work/build/tests/test_fuse_ec"
du -sh -- "$work/build" "$work/cargo-target" "$work/cargo-home" "$work/fdb"
if "$with_lab"; then
    python3 - "$source_root" "$work" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import sys
source, work = map(Path, sys.argv[1:])
names = ('storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli',
         'ec_file_cli', 'hf3fs_fuse_main', 'ec_mount_read_probe')
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
record = {'schema': 1, 'source': str(source), 'revision': os.environ['GITHUB_SHA'],
          'build': str(work / 'build'), 'targets': list(names),
          'binaries': {name: sha(work / 'build/bin' / name) for name in names},
          'build_script_sha256': sha(source / 'scripts/ec/ci/build-native.sh'),
          'acceptance_executed': False}
with (work / 'provenance/lab-build.json').open('x') as out:
    json.dump(record, out, indent=2)
    out.write('\n')
print('lab-build receipt sha256=' + sha(work / 'provenance/lab-build.json'))
PY
fi
printf 'Requested build targets completed; acceptance and actual mounts are separate.\n'
