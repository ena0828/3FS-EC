#!/usr/bin/env bash
set -euo pipefail
# Run in WSL Ubuntu. This prepares artifacts only; it never starts the guest.
VM_DIR="${HF3FS_VM_DIR:-/mnt/e/3fsec/artifacts/vm}"
IMAGE_BUILD=20261017
IMAGE_NAME=noble-server-cloudimg-amd64.img
IMAGE_URL="https://cloud-images.ubuntu.com/noble/${IMAGE_BUILD}"
KEYRING=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
for tool in curl gpgv qemu-img cloud-localds ssh-keygen sha256sum flock python3; do
  command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }
done
[[ "$VM_DIR" = /* && "$VM_DIR" != / ]] || { echo "VM directory must be absolute and non-root" >&2; exit 1; }
mkdir -p "$VM_DIR"/{downloads,keys,logs}
VM_DIR="$(realpath "$VM_DIR")"
exec 9>"$VM_DIR/prepare.lock"
flock -n 9 || { echo "Preparation already running" >&2; exit 1; }
exec 8>"$VM_DIR/run.lock"
flock -n 8 || { echo "Stop the guest before preparing artifacts" >&2; exit 1; }
[[ -r "$KEYRING" ]] || { echo "Ubuntu cloud-image keyring required" >&2; exit 1; }
available="$(df --output=avail -B1 "$VM_DIR" | tail -n 1 | tr -d ' ')"
(( available >= 21474836480 )) || { echo "Keep at least 20 GiB free before preparation" >&2; exit 1; }
cd "$VM_DIR/downloads"
for file in SHA256SUMS SHA256SUMS.gpg; do
  curl --fail --location --retry 3 --connect-timeout 20 --output "$file.part" "$IMAGE_URL/$file"
  mv -- "$file.part" "$file"
done
gpgv --keyring "$KEYRING" SHA256SUMS.gpg SHA256SUMS 2>"$VM_DIR/logs/checksum-signature.log"
expected="$(awk -v name="$IMAGE_NAME" '$2 == "*" name || $2 == name { print $1 }' SHA256SUMS)"
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || { echo "Image checksum not found or ambiguous" >&2; exit 1; }
if [[ ! -f "$IMAGE_NAME" ]]; then
  curl --fail --location --retry 3 --connect-timeout 20 --continue-at - --output "$IMAGE_NAME.part" "$IMAGE_URL/$IMAGE_NAME"
  printf '%s  %s\n' "$expected" "$IMAGE_NAME.part" | sha256sum --check -
  mv -- "$IMAGE_NAME.part" "$IMAGE_NAME"
fi
printf '%s  %s\n' "$expected" "$IMAGE_NAME" | sha256sum --check - | tee "$VM_DIR/logs/image-sha256.log"
qemu-img info --output=json "$IMAGE_NAME" > "$VM_DIR/base-image-info.json"
if [[ ! -f "$VM_DIR/guest.qcow2" ]]; then
  qemu-img create -f qcow2 -F qcow2 -b "$VM_DIR/downloads/$IMAGE_NAME" "$VM_DIR/guest.qcow2" 40G
fi
qemu-img info --output=json "$VM_DIR/guest.qcow2" > "$VM_DIR/guest-image-info.json"
python3 - "$VM_DIR/guest-image-info.json" <<'PY'
import json, sys
info = json.load(open(sys.argv[1], encoding="utf-8"))
if info["format"] != "qcow2" or info["virtual-size"] != 40 * 1024**3:
    raise SystemExit("Existing overlay is not a 40 GiB qcow2 image")
PY
if [[ ! -f "$VM_DIR/keys/id_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$VM_DIR/keys/id_ed25519"
fi
if [[ ! -f "$VM_DIR/keys/id_ed25519.pub" ]]; then
  ssh-keygen -y -f "$VM_DIR/keys/id_ed25519" > "$VM_DIR/keys/id_ed25519.pub"
fi
chmod 600 "$VM_DIR/keys/id_ed25519"
public_key="$(cat "$VM_DIR/keys/id_ed25519.pub")"
cat > "$VM_DIR/user-data" <<EOF
#cloud-config
hostname: 3fs-ec-lab
manage_etc_hosts: true
users:
  - name: ec
    shell: /bin/bash
    lock_passwd: true
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - ${public_key}
ssh_pwauth: false
disable_root: true
package_update: false
package_upgrade: false
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
EOF
cat > "$VM_DIR/meta-data" <<'EOF'
instance-id: 3fs-ec-noble-20261017
local-hostname: 3fs-ec-lab
EOF
cat > "$VM_DIR/network-config" <<'EOF'
version: 2
ethernets:
  vmnet:
    match:
      driver: virtio_net
    dhcp4: true
    dhcp6: false
EOF
if [[ ! -f "$VM_DIR/seed.img" ]]; then
  cloud-localds --network-config="$VM_DIR/network-config" "$VM_DIR/seed.img" "$VM_DIR/user-data" "$VM_DIR/meta-data"
fi
python3 - "$VM_DIR" "$IMAGE_URL/$IMAGE_NAME" "$expected" <<'PY'
import datetime, json, pathlib, sys
root, url, checksum = sys.argv[1:]
manifest = {
    "prepared_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "image_url": url, "image_sha256": checksum,
    "checksum_signature": "verified with installed Ubuntu cloud-image keyring",
    "memory_mib": 4096, "vcpus": 2, "virtual_disk_bytes": 40 * 1024**3,
    "accelerator": "kvm", "ssh_bind": "127.0.0.1:2222",
    "qmp_bind": "127.0.0.1:24444", "guest_started": False,
}
pathlib.Path(root, "preparation.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
printf 'Prepared %s; guest has NOT been started.\n' "$VM_DIR"
