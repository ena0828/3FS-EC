#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 && "$(hostname)" == 3fs-ec-lab ]] || {
  echo "Run as root inside the task guest" >&2; exit 1;
}
[[ "$(uname -r)" != *microsoft* ]] || { echo "Refusing to configure WSL host" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update
apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends \
  fuse3 libaio1t64 libnuma1 libunwind8
modprobe fuse
test -c /dev/fuse
command -v fusermount3
echo "Guest FUSE/runtime packages prepared; no 3FS service started."
