#!/usr/bin/env bash
set -euo pipefail

# Run from Linux; the data directory must support the native ChunkEngine I/O path.
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_root=${EC_ARTIFACT_ROOT:-"$(dirname -- "$repo_root")/artifacts"}
export CARGO_HOME=${CARGO_HOME:-"$(dirname -- "$repo_root")/toolchains/cargo"}
export RUSTUP_HOME=${RUSTUP_HOME:-"$(dirname -- "$repo_root")/toolchains/rustup"}
export PATH="$CARGO_HOME/bin:/usr/lib/llvm-14/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$artifact_root/cargo-target"}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export LIBCLANG_PATH=${LIBCLANG_PATH:-/usr/lib/llvm-18/lib}
export TMPDIR=${EC_TEST_TMPDIR:-/tmp/3fs-ec-tests}
mkdir -p -- "$artifact_root/logs" "$TMPDIR" "$CARGO_TARGET_DIR"
fs_type=$(stat -f -c %T -- "$TMPDIR")
case "$fs_type" in
    ext2/ext3|xfs) ;;
    *) echo "Unsupported test filesystem: $fs_type ($TMPDIR)" >&2; exit 2 ;;
esac
ulimit -n 65536
cd -- "$repo_root"
{
    date --iso-8601=seconds
    git rev-parse HEAD
    git status --short --ignore-submodules=all
    uname -a
    rustc --version --verbose
    cargo --version
    printf 'data_fs=%s\nfd_limit=%s\nbuild_jobs=%s\n' "$fs_type" "$(ulimit -n)" "$CARGO_BUILD_JOBS"
    free -b
    df -B1 -- "$TMPDIR" "$CARGO_TARGET_DIR/.."
} > "$artifact_root/logs/environment.txt"
case "${1:-baseline}" in
    baseline)
        cargo test --locked -p chunk_engine --lib test_engine_checksum -- --test-threads=1
        cargo test --locked -p chunk_engine --lib test_engine_normal -- --test-threads=1
        cargo test --locked -p chunk_engine --lib test_engine_load -- --test-threads=1
        ;;
    native)
        cargo test --locked -p chunk_engine --example ec_pipeline -- --test-threads=1
        cargo run --locked -p chunk_engine --example ec_pipeline -- --root "$TMPDIR" --verify-abort
        ;;
    boundaries)
        cargo build --locked -p chunk_engine --example ec_pipeline
        for object_bytes in 0 1 9 10 11 40959 40960 40961 655360; do
            "$CARGO_TARGET_DIR/debug/examples/ec_pipeline" --root "$TMPDIR" \
                --bytes "$object_bytes" --slice-bytes 4096 --queue-depth 1 --verify-abort
        done
        ;;
    *) echo 'Usage: test-local.sh {baseline|native|boundaries}' >&2; exit 2 ;;
esac
