#!/usr/bin/env bash
set -euo pipefail

# Ubuntu 24.04 development packages; inspect before running as root.
if [[ $(id -u) != 0 ]]; then
    echo 'Run as root inside the chosen Linux development environment.' >&2
    exit 2
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential g++-12 cmake ninja-build meson pkg-config curl ca-certificates git rsync util-linux \
    clang-14 clang-format-14 clang-tidy-14 lld-14 libclang-18-dev libssl-dev \
    libuv1-dev liblz4-dev liblzma-dev zlib1g-dev libdouble-conversion-dev \
    libdwarf-dev libunwind-dev libaio-dev libgflags-dev \
    libgoogle-glog-dev libgtest-dev libgmock-dev libgoogle-perftools-dev \
    libboost-all-dev libibverbs-dev libnuma-dev libevent-dev \
    libisal-dev libfuse3-dev libbz2-dev libsnappy-dev python3-dev autoconf automake libtool

# FoundationDB and libfuse >= 3.16 must be installed separately using pinned releases.
