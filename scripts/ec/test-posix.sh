#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/src/storage/ec/Cargo.toml"
export CARGO_BUILD_JOBS=1
cargo_options=()
if [[ -n "${EC_POSIX_FEATURES:-}" ]]; then
    cargo_options+=(--features "$EC_POSIX_FEATURES")
fi

case "${1:-check}" in
    check)
        cargo test --locked --offline --manifest-path "$manifest" "${cargo_options[@]}" --example posix_pipeline -- --test-threads=1
        cargo clippy --locked --offline --manifest-path "$manifest" "${cargo_options[@]}" --example posix_pipeline --tests -- -D warnings
        ;;
    run)
        shift
        cargo run --locked --offline --manifest-path "$manifest" "${cargo_options[@]}" --example posix_pipeline -- "$@"
        ;;
    verify)
        shift
        executable=${EC_POSIX_EXECUTABLE:-"${CARGO_TARGET_DIR:-$repo_root/src/storage/ec/target}/debug/examples/posix_pipeline"}
        exec "$executable" --verify-existing "$@"
        ;;
    *) echo 'Usage: test-posix.sh check | run --root NEW_DIRECTORY | verify --root EXISTING_DIRECTORY [example options]' >&2; exit 2 ;;
esac
