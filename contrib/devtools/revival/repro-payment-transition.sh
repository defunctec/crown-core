#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/mnpos-repro-common.sh"

ROOT="${1:-$(mktemp -d /tmp/crown-phase1e-pay.XXXXXX)}"
trap 'cleanup_root "$ROOT"' EXIT

echo "root=$ROOT"
start_network "$ROOT"
prepare_collateral "$ROOT"
COLLATERAL_TXID="$(cat "$ROOT/collateral.txid")"
CONF15_TIME="$(find_conf15_time "$ROOT" "$COLLATERAL_TXID")"
NOW="$(date +%s)"
WAIT_SECS=$((CONF15_TIME - NOW + 2))
if [ "$WAIT_SECS" -gt 0 ]; then
  echo "waiting $WAIT_SECS seconds for wall clock to pass the collateral 15-confirmation block time"
  sleep "$WAIT_SECS"
fi

write_systemnode_config "$ROOT" "$COLLATERAL_TXID"
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"
wait_height "$ROOT" 720

echo "systemnode outputs:"
rpc "$ROOT" sn1 systemnode outputs
echo "starting alias after wait"
rpc "$ROOT" sn1 systemnode start-alias sn1
sleep 3

echo "post-start counts:"
COUNTS="$(render_counts "$ROOT")"
printf '%s\n' "$COUNTS"

for node in "${NODES[@]}"; do
  if [ "$(rpc "$ROOT" "$node" systemnode count)" != "1" ]; then
    echo "systemnode registration did not converge on $node" >&2
    exit 51
  fi
done

set +e
SN1_GBT_OUTPUT="$(rpc "$ROOT" sn1 getblocktemplate '{}' 2>&1)"
SN1_GBT_RC=$?
CTL_GBT_OUTPUT="$(rpc "$ROOT" ctl getblocktemplate '{}' 2>&1)"
CTL_GBT_RC=$?
set -e

printf 'sn1 getblocktemplate rc=%s\n%s\n' "$SN1_GBT_RC" "$SN1_GBT_OUTPUT"
printf 'ctl getblocktemplate rc=%s\n%s\n' "$CTL_GBT_RC" "$CTL_GBT_OUTPUT"

if [ "$SN1_GBT_RC" -eq 0 ] || [[ "$SN1_GBT_OUTPUT" != *"CTransaction::GetValueOut() : value out of range"* ]]; then
  echo "expected local payment-transition failure missing on sn1" >&2
  exit 52
fi
if [ "$CTL_GBT_RC" -eq 0 ] || [[ "$CTL_GBT_OUTPUT" != *"CTransaction::GetValueOut() : value out of range"* ]]; then
  echo "expected converged payment-transition failure missing on ctl" >&2
  exit 53
fi
if ! grep -q "CreateNewBlock: Failed to detect masternode to pay" "$ROOT/sn1/regtest/debug.log"; then
  echo "expected masternode-missing log missing on sn1" >&2
  exit 54
fi
if ! grep -q "Systemnode payment to " "$ROOT/sn1/regtest/debug.log"; then
  echo "expected systemnode payment log missing on sn1" >&2
  exit 55
fi

echo "payment-transition failure reproduced"
echo "root cause condition=no masternode payee but enabled systemnode payee"
