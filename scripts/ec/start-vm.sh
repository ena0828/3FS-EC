#!/usr/bin/env bash
set -euo pipefail
# Foreground execution lets the caller retain a process handle and all logs.
VM_DIR="${HF3FS_VM_DIR:-/mnt/e/3fsec/artifacts/vm}"
VM_ACCEL="${HF3FS_VM_ACCEL:-kvm}"
VM_MEMORY_MIB="${HF3FS_VM_MEMORY_MIB:-4096}"
[[ "$VM_MEMORY_MIB" =~ ^[1-9][0-9]{3}$ ]] &&
  (( VM_MEMORY_MIB >= 1024 && VM_MEMORY_MIB <= 8192 )) || {
    echo "HF3FS_VM_MEMORY_MIB must be an integer between 1024 and 8192" >&2
    exit 1
  }
VM_DIR="$(realpath "$VM_DIR")"
[[ -f "$VM_DIR/guest.qcow2" && -f "$VM_DIR/seed.img" ]] || { echo "Run prepare-vm.sh first" >&2; exit 1; }
case "$VM_ACCEL" in
  kvm) [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "KVM is not accessible" >&2; exit 1; }; cpu=host ;;
  tcg) cpu=max ;;
  *) echo "Use kvm or tcg" >&2; exit 1 ;;
esac
exec 9>"$VM_DIR/run.lock"
flock -n 9 || { echo "Guest is already running" >&2; exit 1; }
mkdir -p "$VM_DIR/logs"
exec qemu-system-x86_64 \
  -name 3fs-ec-lab \
  -machine q35 -accel "$VM_ACCEL" -cpu "$cpu" -m "$VM_MEMORY_MIB" -smp 2 \
  -drive "file=$VM_DIR/guest.qcow2,format=qcow2,if=virtio,cache=writethrough" \
  -drive "file=$VM_DIR/seed.img,format=raw,if=virtio,readonly=on" \
  -device virtio-net-pci,netdev=mgmt \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:2222-:22 \
  -display none -serial "file:$VM_DIR/logs/serial.log" \
  -qmp tcp:127.0.0.1:24444,server=on,wait=off \
  -pidfile "$VM_DIR/guest.pid"
