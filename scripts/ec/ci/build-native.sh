#!/usr/bin/env bash
# One fresh hosted job or explicit dedicated local checkout; no service or mount here.
set -euo pipefail
umask 077
with_lab=false
with_regression=false
backend=scalar
backend_seen=false
build_jobs=1
build_jobs_seen=false
local_source=
local_work=
local_revision=
local_container=false
container_fdb_cache=
container_arrow_cache=
container_arrow_source_pack=
container_arrow_source_pack_sha256=
container_libfuse_bundle=
container_libfuse_bundle_sha256=
usage() {
    echo 'Usage: build-native.sh [--backend scalar|isal] [--build-jobs N] [--with-lab-targets] [--with-ec-regression-targets] [--local-source ABS --local-work ABS --local-revision FULL_SHA [--local-container-build-only [--container-fdb-cache ABS] [--container-arrow-cache ABS] [--container-arrow-source-pack ABS --container-arrow-source-pack-sha256 SHA256] [--container-libfuse-bundle ABS --container-libfuse-bundle-sha256 SHA256]]]; N=1|2|4 except explicit container builds' >&2
}
while (($#)); do
    case "$1" in
        --container-arrow-source-pack)
            if [[ -n "$container_arrow_source_pack" ]] || (($# < 2)) || [[ "$2" != /* ]]; then usage; exit 2; fi
            container_arrow_source_pack="$2"
            shift 2
            ;;
        --container-arrow-source-pack-sha256)
            if [[ -n "$container_arrow_source_pack_sha256" ]] || (($# < 2)) || [[ ! "$2" =~ ^[a-f0-9]{64}$ ]]; then usage; exit 2; fi
            container_arrow_source_pack_sha256="$2"
            shift 2
            ;;
        --container-arrow-cache)
            if [[ -n "$container_arrow_cache" ]] || (($# < 2)) || [[ "$2" != /* ]]; then usage; exit 2; fi
            container_arrow_cache="$2"
            shift 2
            ;;
        --container-libfuse-bundle)
            if [[ -n "$container_libfuse_bundle" ]] || (($# < 2)) || [[ "$2" != /* ]]; then usage; exit 2; fi
            container_libfuse_bundle="$2"
            shift 2
            ;;
        --container-libfuse-bundle-sha256)
            if [[ -n "$container_libfuse_bundle_sha256" ]] || (($# < 2)) || [[ ! "$2" =~ ^[a-f0-9]{64}$ ]]; then usage; exit 2; fi
            container_libfuse_bundle_sha256="$2"
            shift 2
            ;;
        --container-fdb-cache)
            if [[ -n "$container_fdb_cache" ]] || (($# < 2)) || [[ "$2" != /* ]]; then usage; exit 2; fi
            container_fdb_cache="$2"
            shift 2
            ;;
        --local-container-build-only)
            if "$local_container"; then usage; exit 2; fi
            local_container=true
            shift
            ;;
        --local-source|--local-work|--local-revision)
            if (($# < 2)) || [[ -z "$2" ]]; then usage; exit 2; fi
            case "$1" in
                --local-source) [[ -z "$local_source" && "$2" == /* ]] || { usage; exit 2; }; local_source="$2" ;;
                --local-work) [[ -z "$local_work" && "$2" == /* ]] || { usage; exit 2; }; local_work="$2" ;;
                --local-revision) [[ -z "$local_revision" && "$2" =~ ^[0-9a-f]{40}$ ]] || { usage; exit 2; }; local_revision="$2" ;;
            esac
            shift 2
            ;;
        --backend)
            if "$backend_seen" || (($# < 2)) || [[ "$2" != scalar && "$2" != isal ]]; then
                usage; exit 2
            fi
            backend="$2"
            backend_seen=true
            shift 2
            ;;
        --build-jobs)
            if "$build_jobs_seen" || (($# < 2)) || [[ ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                usage; exit 2
            fi
            build_jobs="$2"
            build_jobs_seen=true
            shift 2
            ;;
        --with-lab-targets)
            if "$with_lab"; then usage; exit 2; fi
            with_lab=true
            shift
            ;;
        --with-ec-regression-targets)
            if "$with_regression"; then usage; exit 2; fi
            with_regression=true
            shift
            ;;
        *) usage; exit 2 ;;
    esac
done

local_mode=false
if [[ -n "$local_source$local_work$local_revision" ]]; then
    [[ -n "$local_source" && -n "$local_work" && -n "$local_revision" ]] || { usage; exit 2; }
    local_mode=true
fi
if "$local_container"; then
    "$local_mode" || { usage; exit 2; }
elif [[ "$build_jobs" != 1 && "$build_jobs" != 2 && "$build_jobs" != 4 ]]; then
    usage; exit 2
fi
if [[ -n "$container_fdb_cache$container_arrow_cache" ]] && ! "$local_container"; then usage; exit 2; fi
if [[ -n "$container_libfuse_bundle$container_libfuse_bundle_sha256" ]]; then
    "$local_container" && [[ -n "$container_libfuse_bundle" && -n "$container_libfuse_bundle_sha256" ]] || { usage; exit 2; }
fi
if [[ -n "$container_arrow_source_pack$container_arrow_source_pack_sha256" ]]; then
    "$local_container" && [[ -n "$container_arrow_source_pack" && -n "$container_arrow_source_pack_sha256" ]] || { usage; exit 2; }
fi
# END ARGUMENT PARSER
if "$local_mode"; then
    # No environment impersonation: the requested revision is checked against Git.
    source_root="$local_source"
    work="$local_work"
    source_revision="$local_revision"
    [[ "$(realpath -e -- "${BASH_SOURCE[0]}")" == "$source_root/scripts/ec/ci/build-native.sh" ]]
    local_profile_args=()
    if "$local_container"; then local_profile_args=(--container-build-only); fi
    local_preflight=$(/usr/bin/python3 -I "$source_root/scripts/ec/ci/prepare-local-build.py" \
        --source "$source_root" --work "$work" --revision "$source_revision" --backend "$backend" "${local_profile_args[@]}")
    dependency_prefix="$work/deps"
else
    [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]] || {
        echo "Use a fresh hosted job or the explicit --local-source/work/revision mode" >&2; exit 2;
    }
    [[ "$(id -u)" != 0 && "$(uname -m)" == x86_64 ]] || {
        echo "Use the ordinary x86_64 runner user" >&2; exit 2;
    }
    source_root=$(realpath -e -- "${GITHUB_WORKSPACE:?}")
    runner_temp=$(realpath -e -- "${RUNNER_TEMP:?}")
    work="$runner_temp/ec-native"
    source_revision="${GITHUB_SHA:?}"
    dependency_prefix=/usr/local
fi
[[ "$(git -C "$source_root" rev-parse --show-toplevel)" == "$source_root" ]]
[[ "$(git -C "$source_root" rev-parse HEAD)" == "$source_revision" ]]
git -C "$source_root" diff --quiet HEAD --ignore-submodules=all
git -C "$source_root" submodule foreach --recursive 'git diff --quiet HEAD && test -z "$(git ls-files --others --exclude-standard)"'
[[ ! -e "$work" && ! -L "$work" && ! -e "$source_root/target" && ! -L "$source_root/target" ]] || {
    echo "Refusing to reuse an existing build or Cargo target directory" >&2; exit 2;
}
mkdir -m 700 -- "$work"
mkdir -- "$work/provenance" "$work/cargo-target" "$work/bin"
if "$local_mode"; then
    printf '%s\n' "$local_preflight" > "$work/provenance/local-preflight.json"
    unset local_preflight
    # Set before any rustup/cargo/rustc command. Never change the user's defaults.
    export RUSTUP_HOME="$work/rustup-home" CARGO_HOME="$work/cargo-home"
    export RUSTUP_TOOLCHAIN=1.99.1
fi
cd -- "$source_root"
trap 'rc=$?; printf "native build exit=%s at %s\n" "$rc" "$(date -u +%FT%TZ)"; df -h -- "$work"; exit "$rc"' EXIT

printf 'source=%s revision=%s work=%s\n' "$source_root" "$source_revision" "$work"
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
    scripts/ec/cluster/prepare-fdb-cache.py \
    patches/apply.sh patches/folly.patch patches/rocksdb.patch patches/rocksdb.patch.2 \
    cmake/AddCrate.cmake cmake/ApacheArrow.cmake cmake/Jemalloc.cmake \
    scripts/ec/ci/build-native.sh scripts/ec/ci/prepare-local-build.py scripts/ec/ci/run-core-tests.py \
    scripts/ec/ci/container-build-resources.py \
    scripts/ec/ci/prepare-libfuse-cache.py scripts/ec/ci/prepare-arrow-cache.py \
    scripts/ec/ci/prepare-arrow-source-cache.py \
    scripts/ec/ci/prepare-isal.py scripts/ec/reference/downloads.json cmake/EcCodecBackend.cmake \
    .github/workflows/ec-hosted-native.yml .github/workflows/ec-hosted-system.yml \
    .github/workflows/ec-hosted-target-control.yml \
    .github/workflows/ec-hosted-target-meta.yml \
    | tee "$work/provenance/build-inputs.sha256"

# Only top-level Ninja concurrency changes. Nested Cargo, Make and Arrow remain
# at one job. This admission policy is not a proof of peak RSS or completion time.
python3 - "$work" "$build_jobs" "$local_mode" "$local_container" "$source_root" <<'PY'
from pathlib import Path
import json
import os
import sys

GIB = 1024 ** 3

def require(value, message):
    if not value:
        raise ValueError(message)

def cgroup_rows(root, membership, mountinfo):
    # Map only a verified full-root cgroup v2 mount. A namespaced root is fine;
    # hidden host ancestors are not observable and are not claimed as verified.
    matches = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == str(root) and ' - cgroup2 ' in line:
            matches.append(fields)
    require(len(matches) == 1 and matches[0][3] == '/', 'unverified cgroup v2 mount mapping')
    entries = [line.split(':', 2) for line in membership.splitlines() if line.startswith('0::')]
    require(len(entries) == 1 and len(entries[0]) == 3, 'missing unified cgroup membership')
    relative = entries[0][2]
    require(relative.startswith('/') and '..' not in Path(relative).parts, 'invalid cgroup namespace path')
    base = root.resolve(strict=True)
    current = (base / relative.lstrip('/')).resolve(strict=True)
    require(current == base or base in current.parents, 'cgroup membership outside mounted root')
    result = []
    while True:
        require(len(result) < 32, 'cgroup ancestor bound exceeded')
        row = {'path': str(current), 'cpu_max': None, 'memory_max': None, 'memory_current': None}
        for controller, filename in [('cpu', 'cpu.max'), ('memory', 'memory.max')]:
            path = current / filename
            if not path.exists():
                # Root cgroups have no parent-imposed max file. On a child, a
                # disabled parent controller must be explicitly observable.
                enabled = set() if current == base else set((current.parent / 'cgroup.subtree_control').read_text().split())
                require(current == base or controller not in enabled, 'enabled cgroup controller limit missing')
                row[controller + '_scope'] = 'root-no-max' if current == base else 'parent-controller-disabled'
                continue
            raw = path.read_text().strip()
            if controller == 'cpu':
                parts = raw.split()
                require(len(parts) == 2 and parts[1].isdigit() and int(parts[1]) > 0,
                        'invalid cgroup CPU period')
                require(parts[0] == 'max' or (parts[0].isdigit() and int(parts[0]) > 0),
                        'invalid cgroup CPU quota')
                row['cpu_max'] = raw
            else:
                require(raw == 'max' or raw.isdigit(), 'invalid cgroup memory limit')
                used = (current / 'memory.current').read_text().strip()
                require(used.isdigit(), 'invalid cgroup memory usage')
                row.update(memory_max=raw, memory_current=int(used))
        result.append(row)
        if current == base:
            return result
        current = current.parent

def resource_plan(jobs, memory, affinity, groups):
    require(type(jobs) is int and jobs in (1, 2, 4), 'unknown build concurrency')
    require(type(affinity) is int and affinity > 0, 'CPU affinity unavailable')
    total, available = memory['MemTotal'], memory['MemAvailable']
    require(type(total) is int and type(available) is int and 0 <= available <= total,
            'invalid host memory observation')
    cpus, headroom = affinity, available
    for row in groups:
        if row['cpu_max'] is not None:
            quota, period = row['cpu_max'].split()
            if quota != 'max':
                cpus = min(cpus, int(quota) // int(period))
        if row['memory_max'] not in (None, 'max'):
            headroom = min(headroom, max(0, int(row['memory_max']) - row['memory_current']))
    # Explicit four-way builds retain the same visible admission floor. Neither
    # this floor nor prior two-way results prove four-way peak RSS or duration.
    admitted = jobs == 1 or (total >= 15 * GIB and headroom >= 12 * GIB and cpus >= 4)
    return {'schema': 1, 'status': 'admitted' if admitted else 'insufficient-resources',
            'requested_jobs': jobs, 'effective_jobs': jobs if admitted else None,
            'affinity_cpus': affinity, 'visible_effective_cpu_floor': cpus,
            'host_memory_bytes': memory, 'visible_memory_headroom_bytes': headroom,
            'cgroup_ancestors': groups,
            'j2_thresholds': {'memtotal_bytes': 15 * GIB, 'headroom_bytes': 12 * GIB, 'cpu_floor': 4},
            'j4_thresholds': {'memtotal_bytes': 15 * GIB, 'headroom_bytes': 12 * GIB, 'cpu_floor': 4},
            'pools': {'compile': jobs, 'link': 1},
            'nested_jobs': {'cmake_environment': 1, 'cargo': 1, 'make': 1, 'jemalloc': 1},
            'scope': 'visible host/cgroup admission only; hidden ancestors, peak RSS and elapsed time unproven'}

work, jobs = Path(sys.argv[1]), int(sys.argv[2])
memory = {}
for line in Path('/proc/meminfo').read_text().splitlines():
    key, _, value = line.partition(':')
    if key in ('MemTotal', 'MemAvailable'):
        amount, unit = value.split()
        require(unit == 'kB', 'unexpected memory unit')
        memory[key] = int(amount) * 1024
try:
    if sys.argv[4] == 'true':
        import importlib.util
        helper = Path(sys.argv[5]) / 'scripts/ec/ci/container-build-resources.py'
        spec = importlib.util.spec_from_file_location('container_build_resources', helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        record = module.observe(jobs, memory)
    else:
        groups = cgroup_rows(Path('/sys/fs/cgroup'), Path('/proc/self/cgroup').read_text(),
                             Path('/proc/self/mountinfo').read_text())
        record = resource_plan(jobs, memory, len(os.sched_getaffinity(0)), groups)
    if sys.argv[3] == 'true' and sys.argv[4] == 'false':
        floor = resource_plan(2, memory, len(os.sched_getaffinity(0)), groups)
        record['local_conservative_floor'] = floor['j2_thresholds']
        if floor['effective_jobs'] is None:
            record.update(status='insufficient-local-resources', effective_jobs=None)
except (OSError, ValueError) as error:
    # Keep the original serial build path usable without inventing a verified
    # cgroup budget. Parallel opt-in always fails closed on unknown observations.
    record = {'schema': 1, 'status': 'unverified-serial' if jobs == 1 and sys.argv[3] == 'false' else 'unverified-refused',
              'requested_jobs': jobs, 'effective_jobs': 1 if jobs == 1 and sys.argv[3] == 'false' else None,
              'error_type': type(error).__name__, 'pools': {'compile': jobs, 'link': 1}}
with (work / 'provenance/build-resources.json').open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps({'build_resources': record}), flush=True)
require(record['effective_jobs'] == jobs, 'build resource admission refused')
PY

# Reuse the repository's dependency set, including Arrow's transitive closure.
# No system FoundationDB package hooks or services are installed.
if ! "$local_mode"; then
    sudo -n bash "$source_root/scripts/ec/install-build-deps.sh"
fi
dpkg-query -W -f='${Package}\t${Version}\n' > "$work/provenance/dpkg-packages.txt"
sha256sum "$work/provenance/dpkg-packages.txt"
for tool in clang-14 clang++-14 g++-12 gcc-12 cmake ninja meson rustup cargo python3; do
    command -v "$tool"
    if "$local_mode" && [[ "$tool" == cargo || "$tool" == rustup ]]; then continue; fi
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
export PKG_CONFIG_PATH="$dependency_prefix/lib/pkgconfig"
export LD_LIBRARY_PATH="$dependency_prefix/lib"
# END BUILD ENVIRONMENT

# BEGIN ARROW SOURCE CACHE
arrow_source_cmake_args=()
if [[ -n "$container_arrow_source_pack" ]]; then
    /usr/bin/python3 -I "$source_root/scripts/ec/ci/prepare-arrow-source-cache.py" \
        --source "$source_root" --work "$work" --pack "$container_arrow_source_pack" \
        --pack-sha256 "$container_arrow_source_pack_sha256"
    sha256sum "$work/provenance/arrow-source-cache.json" > "$work/provenance/arrow-source-cache-proof.sha256"
    arrow_source_cmake_args=("-DHF3FS_ARROW_SOURCE_DIR=$work/build/src/apache-arrow-cpp")
fi
# END ARROW SOURCE CACHE

# BEGIN ARROW CACHE
if [[ -n "$container_arrow_cache" ]]; then
    /usr/bin/python3 -I "$source_root/scripts/ec/ci/prepare-arrow-cache.py" \
        --source "$source_root" --work "$work" --cache "$container_arrow_cache"
    mapfile -d '' -t arrow_urls < "$work/arrow-cache/urls.nul"
    [[ "${#arrow_urls[@]}" -eq 7 ]]
    export ARROW_BOOST_URL="${arrow_urls[0]}"
    export ARROW_JEMALLOC_URL="${arrow_urls[1]}"
    export ARROW_LZ4_URL="${arrow_urls[2]}"
    export ARROW_THRIFT_URL="${arrow_urls[3]}"
    export ARROW_XSIMD_URL="${arrow_urls[4]}"
    export ARROW_ZLIB_URL="${arrow_urls[5]}"
    export ARROW_ZSTD_URL="${arrow_urls[6]}"
    sha256sum "$work/provenance/arrow-cache.json" > "$work/provenance/arrow-cache-proof.sha256"
    unset arrow_urls
fi
# END ARROW CACHE

# BEGIN FDB FETCH
fdb_cache_args=()
if [[ -n "$container_fdb_cache" ]]; then
    fdb_cache_args=(--container-fdb-cache "$container_fdb_cache" --source "$source_root" --work "$work")
fi
bash "$source_root/scripts/ec/cluster/fetch-fdb.sh" "$work/fdb" "${fdb_cache_args[@]}"
# END FDB FETCH
# BEGIN FDB INSTALL
if "$local_mode"; then
    install -d "$dependency_prefix/include/foundationdb" "$dependency_prefix/lib"
    cp -a "$work/fdb/fdb-package/usr/include/foundationdb/." "$dependency_prefix/include/foundationdb/"
    install -m 755 "$work/fdb/lib/libfdb_c.so" "$dependency_prefix/lib/libfdb_c.so"
else
    sudo -n install -d "$dependency_prefix/include/foundationdb"
    sudo -n cp -a "$work/fdb/fdb-package/usr/include/foundationdb/." "$dependency_prefix/include/foundationdb/"
    sudo -n install -m 755 "$work/fdb/lib/libfdb_c.so" "$dependency_prefix/lib/libfdb_c.so"
fi
# END FDB INSTALL
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
cmp -- "$work/fdb/lib/libfdb_c.so" "$dependency_prefix/lib/libfdb_c.so"
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
    if (maximum != FDB_LATEST_API_VERSION || maximum < FDB_API_VERSION) {
        std::fprintf(stderr, "unexpected FDB maximum API: %d\n", maximum);
        return 1;
    }
    // FDB 7.3.63 initializes its local client in selectApiVersion. Calling
    // getClientVersion first dereferences an uninitialized localClient.
    const fdb_error_t selected = fdb_select_api_version(FDB_API_VERSION);
    if (selected != 0) {
        std::fprintf(stderr, "FDB API selection failed: %d\n", selected);
        return 1;
    }
    const char* version = fdb_get_client_version();
    // dlsym avoids dladdr mistaking an executable PLT trampoline for the DSO.
    void* symbol = dlsym(RTLD_DEFAULT, "fdb_get_max_api_version");
    Dl_info provider{};
    if (!version || std::strlen(version) > 256 || !symbol || !dladdr(symbol, &provider) ||
        !provider.dli_fname || std::strlen(provider.dli_fname) > 4096) {
        return 1;
    }
    std::printf("%d\n%s\n%s\n", maximum, version, provider.dli_fname);
    return 0;
}
CPP
fdb_probe_argv=(/usr/bin/clang++-14 "--gcc-toolchain=$gcc_toolchain"
    -std=c++20 -O0 -g0 -fcoroutines-ts -fuse-ld=lld "-I$dependency_prefix/include"
    "-L$dependency_prefix/lib" "$work/provenance/fdb-link-probe.cc" -lfdb_c -ldl -latomic
    -o "$work/provenance/fdb-link-probe")
printf '%q ' "${fdb_probe_argv[@]}" > "$work/provenance/fdb-link-probe.argv"
printf '\n' >> "$work/provenance/fdb-link-probe.argv"
"${fdb_probe_argv[@]}"
"$work/provenance/fdb-link-probe" > "$work/provenance/fdb-link-probe.out"
python3 - "$work" "$dependency_prefix" <<'PY'
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
installed = (Path(sys.argv[2]) / 'lib/libfdb_c.so').resolve(strict=True)
expected = work / 'fdb/lib/libfdb_c.so'
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
if provider != installed or sha(provider) != sha(expected):
    raise SystemExit('FDB probe loaded a different client library')
record = {'schema': 1, 'status': 'linked-and-loaded-fixed-client',
          'maximum_api_version': int(rows[0]), 'requested_header_api': 710,
          'selected_api_version': 710, 'api_selection_result': 0,
          'client_version': rows[1], 'provider': str(provider), 'provider_sha256': sha(provider),
          'expected_package_library_sha256': sha(expected),
          'gcc_toolchain': str(work / 'gcc12'), 'linker': 'lld',
          'link_search_directory': str(Path(sys.argv[2]) / 'lib'), 'fdb_network_started': False,
          'probe_sha256': sha(provenance / 'fdb-link-probe'),
          'probe_source_sha256': sha(provenance / 'fdb-link-probe.cc'),
          'argv_sha256': sha(provenance / 'fdb-link-probe.argv')}
with (provenance / 'fdb-link-probe.json').open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps(record))
PY

# Prepare the same official private provider validated by run-codec-tests.py.
# The codec runner's preparation is inside main; keep that passed entry unchanged.
backend_cmake_args=("-DHF3FS_EC_BACKEND=$backend")
if [[ "$backend" == isal ]]; then
    python3 -B "$source_root/scripts/ec/ci/prepare-isal.py" --source "$source_root" --work "$work"
    backend_cmake_args+=("-DHF3FS_EC_ISAL_ROOT=$work/isal-prefix")
else
    backend_cmake_args+=("-DHF3FS_EC_ISAL_ROOT=")
fi

# Ubuntu 24.04's libfuse 3.14 is below this tree's required >= 3.16.1.
fuse_revision=7a92727d97c10290b3501d86a194738973edb61d
# BEGIN LIBFUSE SOURCE
if [[ -n "$container_libfuse_bundle" ]]; then
    /usr/bin/python3 -I "$source_root/scripts/ec/ci/prepare-libfuse-cache.py" \
        --source "$source_root" --work "$work" --bundle "$container_libfuse_bundle" \
        --bundle-sha256 "$container_libfuse_bundle_sha256"
else
git init -q "$work/libfuse"
git -C "$work/libfuse" remote add origin https://github.com/libfuse/libfuse.git
git -C "$work/libfuse" fetch --depth 1 origin "$fuse_revision"
git -C "$work/libfuse" checkout --detach FETCH_HEAD
[[ "$(git -C "$work/libfuse" rev-parse HEAD)" == "$fuse_revision" ]]
fi
# END LIBFUSE SOURCE
# BEGIN FUSE INSTALL
fuse_options=()
if "$local_mode"; then
    # util/install_helper.sh can create system/setuid files even with a prefix.
    # Only the library and headers are needed here. Mounting is a later contract.
    fuse_options=(-Dutils=false -Duseroot=false)
fi
meson setup "$work/libfuse-build" "$work/libfuse" "--prefix=$dependency_prefix" --libdir=lib \
    --buildtype=release -Dtests=false -Dexamples=false -Dinitscriptdir= "${fuse_options[@]}"
ninja -C "$work/libfuse-build" -j1
if "$local_mode"; then
    ninja -C "$work/libfuse-build" -j1 install
else
    sudo -n ninja -C "$work/libfuse-build" -j1 install
    sudo -n ldconfig
fi
# END FUSE INSTALL
[[ "$(pkg-config --modversion fuse3)" == 3.16.2 ]]
[[ "$(pkg-config --variable=prefix fuse3)" == "$dependency_prefix" ]]
pkg-config --cflags --libs fuse3 | tee "$work/provenance/fuse-pkg-config.txt"
printf 'libfuse_revision=%s libfuse_version=%s\n' "$fuse_revision" "$(pkg-config --modversion fuse3)"
sha256sum "$dependency_prefix/lib/libfuse3.so.3" "$dependency_prefix/lib/libfdb_c.so" > "$work/provenance/private-libraries.sha256"
cat "$work/provenance/private-libraries.sha256"

# Preserve both checked-in locks. AddCrate already passes --locked; the wrapper
# adds it only when absent from another build caller, without duplicating it.
export RUSTUP_TOOLCHAIN=1.99.1
# BEGIN RUST TOOLCHAIN INSTALL
rustup_install_options=()
if "$local_mode"; then rustup_install_options=(--no-self-update); fi
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal "${rustup_install_options[@]}"
# END RUST TOOLCHAIN INSTALL
if "$local_mode"; then rustup --version; fi
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
    for argument in "$@"; do
        if [[ "$argument" == --locked ]]; then
            exec "${EC_REAL_CARGO:?}" build "$@"
        fi
    done
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
# BEGIN REQUESTED BUILD
local_cmake_args=()
if "$local_mode"; then
    # Raw fdb_c linkage needs explicit headers, -L and a persistent runtime path.
    # Keep this prefix in place for core tests and ldd-based package collection.
    local_cmake_args=("-DCMAKE_C_FLAGS=-I$dependency_prefix/include"
        "-DCMAKE_CXX_FLAGS=-I$dependency_prefix/include"
        "-DCMAKE_PREFIX_PATH=$dependency_prefix" "-DCMAKE_BUILD_RPATH=$dependency_prefix/lib")
fi
cmake -S "$source_root" -B "$work/build" -G Ninja \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 -DCMAKE_C_COMPILER=/usr/bin/clang-14 \
    "-DCMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN=$gcc_toolchain" \
    "-DCMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN=$gcc_toolchain" \
    -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASSERTIONS=ON -DDEBUG_INFO_FLAGS=-g0 \
    '-DCMAKE_C_FLAGS_DEBUG=-O0 -g0' '-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g0' \
    -DFOLLY_CXX_FLAGS=-g0 -DSHUFFLE_METHOD=g++11 -DENABLE_FUSE_APPLICATION=ON \
    "-DCMAKE_EXE_LINKER_FLAGS=-L$dependency_prefix/lib" \
    "-DCMAKE_SHARED_LINKER_FLAGS=-L$dependency_prefix/lib" "${local_cmake_args[@]}" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DHF3FS_EXTERNAL_BUILD_JOBS=1 "${backend_cmake_args[@]}" \
    "-DCMAKE_JOB_POOLS=ec_compile=$build_jobs;ec_link=1" \
    -DCMAKE_JOB_POOL_COMPILE=ec_compile -DCMAKE_JOB_POOL_LINK=ec_link "${arrow_source_cmake_args[@]}"
build_targets=(test_meta test_fuse_ec)
if "$with_regression"; then
    build_targets+=(test_storage_store test_storage_service test_client)
fi
if "$with_lab"; then
    build_targets+=(storage_main mgmtd_main meta_main admin_cli ec_stripe_cli ec_file_cli hf3fs_fuse_main ec_mount_read_probe)
fi
build_argv=(cmake --build "$work/build" --parallel "$build_jobs" --target "${build_targets[@]}")
python3 - "$work/provenance/build-command.json" "${build_argv[@]}" <<'PY'
from pathlib import Path
import json
import sys
with Path(sys.argv[1]).open('x') as stream:
    json.dump({'schema': 1, 'argv': sys.argv[2:]}, stream, indent=2)
    stream.write('\n')
PY
printf 'Requested build: '; printf '%q ' "${build_argv[@]}"; printf '\n'
"${build_argv[@]}"
# END REQUESTED BUILD
[[ "$(git -C "$work/build/src/apache-arrow-cpp" rev-parse HEAD)" == b7d2f7ffca66c868bd2fce5b3749c6caa002a7f0 ]]
printf 'Arrow actual checkout: '
git -C "$work/build/src/apache-arrow-cpp" rev-parse HEAD
sha256sum --check "$work/provenance/cargo-locks.sha256"
git diff --exit-code HEAD --ignore-submodules=all
[[ "$(git rev-parse HEAD)" == "$source_revision" ]]
sha256sum --check "$work/provenance/build-inputs.sha256"
sha256sum --check "$work/provenance/private-libraries.sha256"
if [[ -n "$container_arrow_cache" ]]; then
    sha256sum --check "$work/provenance/arrow-cache-proof.sha256"
fi
if [[ -n "$container_arrow_source_pack" ]]; then
    sha256sum --check "$work/provenance/arrow-source-cache-proof.sha256"
fi
sha256sum "$work/build/CMakeCache.txt" "$work/build/compile_commands.json" \
    "$work/build/tests/test_meta" "$work/build/tests/test_fuse_ec"
du -sh -- "$work/build" "$work/cargo-target" "$work/cargo-home" "$work/fdb"
# Keep the existing eight-binary lab receipt contract; additionally bind every
# requested test target and the selected backend in an always-written receipt.
python3 - "$source_root" "$work" "$backend" "$with_lab" "$with_regression" "$source_revision" "$local_mode" "$dependency_prefix" "$local_container" "$container_arrow_cache" "$container_arrow_source_pack" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import sys
source, work = map(Path, sys.argv[1:3])
backend, with_lab, with_regression, revision, local_mode, dependency_prefix, local_container, container_arrow_cache, container_arrow_source_pack = sys.argv[3:]
lab_names = ('storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli',
             'ec_file_cli', 'hf3fs_fuse_main', 'ec_mount_read_probe')
tests = ['test_meta', 'test_fuse_ec']
if with_regression == 'true':
    tests += ['test_storage_store', 'test_storage_service', 'test_client']
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
cache = (work / 'build/CMakeCache.txt').read_text()
if ('HF3FS_EC_BACKEND:STRING=' + backend + '\n') not in cache:
    raise SystemExit('Configured CMake backend differs from request')
isal = None
if backend == 'isal':
    receipt = work / 'provenance/isal-prepare.json'
    isal = json.loads(receipt.read_text())
    provider = Path(isal['provider']['path'])
    prefix = work / 'isal-prefix'
    if (isal['status'] != 'private-packages-prepared-not-executed' or isal['backend'] != 'isal'
            or isal['prefix'] != str(prefix) or provider.resolve(strict=True) != provider
            or provider != prefix / 'usr/lib/x86_64-linux-gnu/libisal.so.2.0.31'
            or (prefix / 'usr/lib/x86_64-linux-gnu/libisal.so').resolve(strict=True) != provider
            or sha(provider) != isal['provider']['sha256']
            or sha(provider) != '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c'
            or sha(source / 'scripts/ec/reference/downloads.json') != isal['source_lock_sha256']
            or sha(source / 'scripts/ec/ci/prepare-isal.py') != isal['helper_sha256']
            or ('HF3FS_EC_ISAL_ROOT:PATH=' + str(prefix) + '\n') not in cache):
        raise SystemExit('Private ISA-L build input/provider changed')
    isal = {'prefix': str(prefix), 'provider': isal['provider'], 'prepare_receipt_sha256': sha(receipt),
            'source_lock_sha256': isal['source_lock_sha256']}
paths = {name: work / 'build/tests' / name for name in tests}
if with_lab == 'true':
    paths.update({name: work / 'build/bin' / name for name in lab_names})
if not all(path.is_file() and os.access(path, os.X_OK) for path in paths.values()):
    raise SystemExit('A requested build target is not an executable file')
# Verify local executable loading with no LD override: later consumers are new
# processes and package-services resolves actual ldd providers, not this shell.
runtime_providers = {}
if local_mode == 'true':
    import subprocess
    expected = {name: (Path(dependency_prefix) / 'lib' / name).resolve(strict=True)
                for name in ('libfdb_c.so', 'libfuse3.so.3')}
    if isal is not None:
        expected['libisal.so.2'] = Path(isal['provider']['path'])
    preflight = json.loads((work / 'provenance/local-preflight.json').read_text())
    for tool in preflight['tools'].values():
        if sha(Path(tool['path'])) != tool['sha256']:
            raise SystemExit('A prepared local tool changed during the build')
    for name, executable in paths.items():
        observations = []
        for search_path in (None, '/usr/local/lib'):
            env = dict(os.environ)
            env.pop('LD_LIBRARY_PATH', None)
            if search_path is not None:
                env['LD_LIBRARY_PATH'] = search_path  # Existing package-services environment.
            output = subprocess.check_output(['ldd', str(executable)], text=True, env=env)
            if 'not found' in output:
                raise SystemExit('A requested binary has unresolved runtime libraries: ' + name)
            observed = {}
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[0] in expected:
                    actual = Path(fields[2]).resolve(strict=True)
                    if fields[1] != '=>' or actual != expected[fields[0]]:
                        raise SystemExit('A requested binary resolves a different local provider: ' + name)
                    observed[fields[0]] = {'path': str(actual), 'sha256': sha(actual)}
            observations.append(observed)
        if observations[0] != observations[1]:
            raise SystemExit('Package and direct runtime library observations differ')
        runtime_providers[name] = observations[0]
    if 'libfdb_c.so' not in runtime_providers['test_meta'] or 'libfuse3.so.3' not in runtime_providers['test_fuse_ec']:
        raise SystemExit('Required FDB/FUSE executable provider evidence is absent')
    if isal is not None and not any('libisal.so.2' in row for row in runtime_providers.values()):
        raise SystemExit('Required ISA-L executable provider evidence is absent')
common = {'schema': 1, 'source': str(source), 'revision': revision,
          'execution_environment': ('local-linux-container-build-only' if local_container == 'true' else
                                    'ordinary-linux-local' if local_mode == 'true' else 'github-hosted'),
          'dependency_prefix': dependency_prefix, 'runtime_providers_without_ld_override': runtime_providers,
          'local_preflight_sha256': sha(work / 'provenance/local-preflight.json') if local_mode == 'true' else None,
          'local_package_ld_library_path_checked': '/usr/local/lib' if local_mode == 'true' else None,
          'build': str(work / 'build'), 'backend': backend, 'isal': isal,
          'build_script_sha256': sha(source / 'scripts/ec/ci/build-native.sh'),
          'cmake_cache_sha256': sha(work / 'build/CMakeCache.txt'),
          'acceptance_executed': False,
          'build_resources': json.loads((work / 'provenance/build-resources.json').read_text()),
          'build_resources_sha256': sha(work / 'provenance/build-resources.json'),
          'build_command': json.loads((work / 'provenance/build-command.json').read_text()),
          'build_command_sha256': sha(work / 'provenance/build-command.json')}
if local_container == 'true':
    common.update(build_only=True, filesystems=preflight['filesystems'],
                  container_resource_helper_sha256=sha(source / 'scripts/ec/ci/container-build-resources.py'))
    fdb_cache = work / 'fdb/fdb-cache-provenance.json'
    if fdb_cache.exists():
        common['fdb_cache_provenance'] = {'path': str(fdb_cache), 'sha256': sha(fdb_cache)}
    libfuse_cache = work / 'provenance/libfuse-cache.json'
    if libfuse_cache.exists():
        common['libfuse_cache_provenance'] = {'path': str(libfuse_cache), 'sha256': sha(libfuse_cache)}
if container_arrow_cache:
    if local_container != 'true':
        raise SystemExit('Arrow archive cache is container-build-only')
    import importlib.util
    spec = importlib.util.spec_from_file_location('arrow_cache', source / 'scripts/ec/ci/prepare-arrow-cache.py')
    arrow_cache = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(arrow_cache)
    common['arrow_cache_provenance'] = arrow_cache.verify_preparation(
        source, work, Path(container_arrow_cache), verify_upstream=True)
if container_arrow_source_pack:
    if local_container != 'true':
        raise SystemExit('Arrow source pack is container-build-only')
    if ('HF3FS_ARROW_SOURCE_DIR:PATH=' + str(work / 'build/src/apache-arrow-cpp') + '\n') not in cache:
        raise SystemExit('Configured Arrow source differs from the prepared snapshot')
    import importlib.util
    spec = importlib.util.spec_from_file_location('arrow_source_cache', source / 'scripts/ec/ci/prepare-arrow-source-cache.py')
    arrow_source_cache = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(arrow_source_cache)
    common['arrow_source_cache_provenance'] = arrow_source_cache.verify_preparation(source, work)
record = dict(common, targets=list(paths), binaries={name: sha(path) for name, path in paths.items()},
              ec_regression_targets_requested=with_regression == 'true', lab_targets_requested=with_lab == 'true')
path = work / 'provenance/native-build.json'
with path.open('x') as out:
    json.dump(record, out, indent=2)
    out.write('\n')
print(json.dumps({'native_build': record, 'receipt_sha256': sha(path)}))
if with_lab == 'true':
    lab = dict(common, targets=list(lab_names),
               binaries={name: record['binaries'][name] for name in lab_names},
               native_build_receipt_sha256=sha(path))
    path = work / 'provenance/lab-build.json'
    with path.open('x') as out:
        json.dump(lab, out, indent=2)
        out.write('\n')
    print('lab-build receipt sha256=' + sha(path))
PY
printf 'Requested build targets completed; acceptance and actual mounts are separate.\n'
