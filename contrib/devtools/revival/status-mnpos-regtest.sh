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
  echo "=== $n ==="
  if "$BIN_DIR/crown-cli" -datadir="$ROOT/$n" getblockcount >/dev/null 2>&1; then
    h=$("$BIN_DIR/crown-cli" -datadir="$ROOT/$n" getblockcount)
    c=$("$BIN_DIR/crown-cli" -datadir="$ROOT/$n" getconnectioncount)
    bh=$("$BIN_DIR/crown-cli" -datadir="$ROOT/$n" getbestblockhash)
    mn=$("$BIN_DIR/crown-cli" -datadir="$ROOT/$n" masternode count 2>/dev/null || echo n/a)
    sn=$("$BIN_DIR/crown-cli" -datadir="$ROOT/$n" systemnode count 2>/dev/null || echo n/a)
    echo "height=$h conn=$c mn=$mn sn=$sn best=${bh:0:16}..."
  else
    echo "offline"
  fi
done
