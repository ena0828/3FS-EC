#!/usr/bin/env bash
set -euo pipefail
VM_DIR="${HF3FS_VM_DIR:-/mnt/e/3fsec/artifacts/vm}"
VM_DIR="$(realpath "$VM_DIR")"
[[ -f "$VM_DIR/keys/id_ed25519" ]] || { echo "Run prepare-vm.sh first" >&2; exit 1; }
# DrvFs may ignore chmod. Use a private transient Linux copy for OpenSSH.
key_dir="$(mktemp -d /dev/shm/3fs-ec-ssh.XXXXXXXX)"
trap 'rm -f -- "$key_dir/key"; rmdir -- "$key_dir"' EXIT
chmod 700 "$key_dir"
cp -- "$VM_DIR/keys/id_ed25519" "$key_dir/key"
chmod 600 "$key_dir/key"
ssh -i "$key_dir/key" -p 2222 \
  -o IdentitiesOnly=yes -o PasswordAuthentication=no \
  -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=accept-new \
  -o "UserKnownHostsFile=$VM_DIR/known_hosts" \
  ec@127.0.0.1 "$@"
