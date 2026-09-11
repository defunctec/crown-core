#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/mnpos-repro-common.sh"

ROOT="${1:-$(mktemp -d /tmp/crown-phase1e-regdiv.XXXXXX)}"
trap 'cleanup_root "$ROOT"' EXIT

echo "root=$ROOT"
start_network "$ROOT"
prepare_collateral "$ROOT"
COLLATERAL_TXID="$(cat "$ROOT/collateral.txid")"
write_systemnode_config "$ROOT" "$COLLATERAL_TXID"
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"
wait_height "$ROOT" 720

echo "systemnode outputs:"
rpc "$ROOT" sn1 systemnode outputs
echo "spork active:"
rpc "$ROOT" ctl spork active

echo "starting alias immediately after collateral maturity"
rpc "$ROOT" sn1 systemnode start-alias sn1
sleep 3

echo "post-start counts:"
COUNTS="$(render_counts "$ROOT")"
printf '%s\n' "$COUNTS"

SN1_COUNT="$(rpc "$ROOT" sn1 systemnode count)"
CTL_COUNT="$(rpc "$ROOT" ctl systemnode count)"
MN1_COUNT="$(rpc "$ROOT" mn1 systemnode count)"
OBS_COUNT="$(rpc "$ROOT" obs systemnode count)"

if [ "$SN1_COUNT" != "1" ] || [ "$CTL_COUNT" != "0" ] || [ "$MN1_COUNT" != "0" ] || [ "$OBS_COUNT" != "0" ]; then
  echo "registration divergence not reproduced" >&2
  exit 41
fi

if ! grep -q "Bad sigTime .*15 conf block is at" "$ROOT/ctl/regtest/debug.log"; then
  echo "expected remote sigTime rejection was not logged on ctl" >&2
  exit 42
fi
if ! grep -q "Rejected Systemnode entry 8.8.8.8:24003" "$ROOT/ctl/regtest/debug.log"; then
  echo "expected remote rejection was not logged on ctl" >&2
  exit 43
fi

echo "divergence reproduced"
echo "first divergent event=remote CheckInputsAndAdd sigTime check"
grep -n "Bad sigTime .*15 conf block is at" "$ROOT/ctl/regtest/debug.log" | tail -n 1
