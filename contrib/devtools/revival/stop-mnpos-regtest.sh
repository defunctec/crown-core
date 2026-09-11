#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-/tmp/crown-phase1d}"
BIN_DIR="${BIN_DIR:-$(cd "$(dirname "$0")/../../.." && pwd)/src}"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1d}"
NODES=(ctl mn1 sn1 obs)

for n in "${NODES[@]}"; do
  "$BIN_DIR/crown-cli" -datadir="$ROOT/$n" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" stop >/dev/null 2>&1 || true
done
sleep 3

match_exact_cmd() {
  local pid="$1" n="$2" cmd
  cmd="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  [ -n "$cmd" ] || return 1
  [ "$cmd" = "$BIN_DIR/crownd -datadir=$ROOT/$n" ]
}

collect_tracked_pids() {
  local n pid
  for n in "${NODES[@]}"; do
    if [ -f "$ROOT/$n/crownd.pid" ]; then
      pid="$(cat "$ROOT/$n/crownd.pid" 2>/dev/null || true)"
      if [[ "$pid" =~ ^[0-9]+$ ]] && match_exact_cmd "$pid" "$n"; then
        echo "$pid"
      fi
    fi
  done
}

mapfile -t pids < <(collect_tracked_pids)
if [ "${#pids[@]}" -gt 0 ]; then
  kill "${pids[@]}" >/dev/null 2>&1 || true
  sleep 2
fi
mapfile -t pids2 < <(collect_tracked_pids)
if [ "${#pids2[@]}" -gt 0 ]; then
  kill -9 "${pids2[@]}" >/dev/null 2>&1 || true
fi

for n in "${NODES[@]}"; do
  rm -f "$ROOT/$n/crownd.pid"
done

echo "Stopped nodes in $ROOT"
