#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 && "$(hostname)" == 3fs-ec-lab ]] || {
  echo "Run as root inside the task guest" >&2; exit 1;
}
SOURCE="${1:-/home/ec/verbs-data-check.c}"
LOG_DIR="/home/ec/rdma-preflight/run-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$LOG_DIR"
exec > >(tee "$LOG_DIR/smoke.log") 2>&1
date --iso-8601=seconds
ulimit -l
NETDEV="$(ip -o route show default | awk 'NR == 1 { print $5 }')"
GID_INDEX="$(python3 - "$NETDEV" <<'PY'
import ipaddress, json, pathlib, subprocess, sys
addresses = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", sys.argv[1]]))
local_ips = {ipaddress.IPv4Address(a["local"]) for link in addresses for a in link["addr_info"]}
base = pathlib.Path("/sys/class/infiniband/rxe0/ports/1")
for path in sorted((base / "gids").iterdir(), key=lambda p: int(p.name)):
    gid = ipaddress.IPv6Address(path.read_text().strip())
    if gid.ipv4_mapped in local_ips and (base / "gid_attrs/types" / path.name).read_text().strip() == "RoCE v2":
        print(path.name)
        break
else:
    raise SystemExit("No IPv4 RoCE v2 GID matches the guest network interface")
PY
)"
printf 'netdev=%s gid_index=%s\n' "$NETDEV" "$GID_INDEX"
rdma link show
gcc -std=c11 -O2 -Wall -Wextra -Werror "$SOURCE" -o /home/ec/verbs-data-check -libverbs
sha256sum "$SOURCE" /home/ec/verbs-data-check
timeout 30 /home/ec/verbs-data-check rxe0 "$GID_INDEX" | tee "$LOG_DIR/content-check.log"

run_pair() {
  local label="$1" program="$2" port="$3"
  shift 3
  local server_status=0 client_status=0 server_pid
  timeout 45 "$program" "$@" -p "$port" >"$LOG_DIR/$label-server.log" 2>&1 &
  server_pid=$!
  for attempt in $(seq 1 50); do
    if ss -ltn "sport = :$port" | grep -q ":$port"; then break; fi
    sleep 0.1
  done
  timeout 40 "$program" "$@" -p "$port" 127.0.0.1 >"$LOG_DIR/$label-client.log" 2>&1 || client_status=$?
  wait "$server_pid" || server_status=$?
  printf '%s: client_exit=%s server_exit=%s\n' "$label" "$client_status" "$server_status"
  cat "$LOG_DIR/$label-client.log"
  [[ "$client_status" == 0 && "$server_status" == 0 ]]
}

result=0
run_pair pingpong ibv_rc_pingpong 18515 -d rxe0 -g "$GID_INDEX" -c -n 100 -s 4096 -r 32 || result=1
run_pair write ib_write_bw 18516 -d rxe0 -x "$GID_INDEX" -n 100 -s 114688 -t 8 -I 0 --use_old_post_send || result=1
run_pair read ib_read_bw 18517 -d rxe0 -x "$GID_INDEX" -n 100 -s 114688 -t 8 --use_old_post_send || result=1
free -m
printf 'smoke_exit=%s; reported timings are functional-run diagnostics only\n' "$result"
exit "$result"
