#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "" ]; then
  echo "Usage: $0 <private_datadir_root>" >&2
  exit 1
fi
ROOT="$1"
BIN_DIR="${BIN_DIR:-$(cd "$(dirname "$0")/../../.." && pwd)/src}"
NODES=(ctl mn1 sn1 obs)

for n in "${NODES[@]}"; do
  "$BIN_DIR/crown-cli" -datadir="$ROOT/$n" stop >/dev/null 2>&1 || true
done
sleep 3

match_exact_cmd() {
  local pid="$1" n="$2" cmd needle
  cmd="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  [ -n "$cmd" ] || return 1
  [[ "$cmd" == *"crownd"* ]] || return 1
  needle="-datadir=$ROOT/$n"
  case "$cmd" in
    *"$needle"*) return 0 ;;
    *) return 1 ;;
  esac
}

collect_tracked_pids() {
  local n pid
  for n in "${NODES[@]}"; do
    for pidfile in "$ROOT/$n/crownd.pid" "$ROOT/$n/regtest/crownd.pid"; do
      if [ -f "$pidfile" ]; then
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [[ "$pid" =~ ^[0-9]+$ ]] && match_exact_cmd "$pid" "$n"; then
          echo "$pid"
        fi
      fi
    done
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
  rm -f "$ROOT/$n/regtest/crownd.pid"
done

echo "Stopped nodes in $ROOT"
