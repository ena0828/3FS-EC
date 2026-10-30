#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo "Run inside the task guest as root" >&2; exit 1; }
[[ "$(hostname)" == 3fs-ec-lab ]] || { echo "Refusing to configure a different host" >&2; exit 1; }
LOG_DIR=/home/ec/rdma-preflight
mkdir -p "$LOG_DIR"
exec > >(tee "$LOG_DIR/setup.log") 2>&1
date --iso-8601=seconds
uname -a
cat /etc/os-release
free -m
df -h /
cloud-init status --wait
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update
apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends \
  "linux-modules-extra-$(uname -r)" rdma-core ibverbs-utils perftest \
  libibverbs-dev build-essential iproute2
dpkg-query -W rdma-core ibverbs-utils perftest libibverbs-dev \
  "linux-modules-extra-$(uname -r)"
modprobe rdma_rxe
NETDEV="$(ip -o route show default | awk 'NR == 1 { print $5 }')"
[[ -n "$NETDEV" ]] || { echo "No guest default-route network interface" >&2; exit 1; }
ip -details address show dev "$NETDEV"
if ! rdma link show rxe0/1 >/dev/null 2>&1; then
  rdma link add rxe0 type rxe netdev "$NETDEV"
fi
rdma link show
ibv_devices
ibv_devinfo -d rxe0 -v
for gid_file in /sys/class/infiniband/rxe0/ports/1/gids/*; do
  gid_value="$(cat "$gid_file")"
  [[ "$gid_value" != 0000:0000:0000:0000:0000:0000:0000:0000 ]] || continue
  printf 'GID[%s] = %s; type = %s\n' "${gid_file##*/}" "$gid_value" \
    "$(cat "/sys/class/infiniband/rxe0/ports/1/gid_attrs/types/${gid_file##*/}")"
done
free -m
echo "Device setup complete. RDMA data-path tests have not run yet."
