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

match_datadir() {
  local args="$1"
  for n in "${NODES[@]}"; do
    if [[ "$args" == *"crownd -datadir=$ROOT/$n"* ]]; then
      return 0
    fi
  done
  return 1
}

mapfile -t pids < <(while read -r pid args; do
  if match_datadir "$args"; then
    echo "$pid"
  fi
done < <(ps -eo pid=,args=))
if [ "${#pids[@]}" -gt 0 ]; then
  kill "${pids[@]}" >/dev/null 2>&1 || true
  sleep 2
fi
mapfile -t pids2 < <(while read -r pid args; do
  if match_datadir "$args"; then
    echo "$pid"
  fi
done < <(ps -eo pid=,args=))
if [ "${#pids2[@]}" -gt 0 ]; then
  kill -9 "${pids2[@]}" >/dev/null 2>&1 || true
fi

echo "Stopped nodes in $ROOT"
