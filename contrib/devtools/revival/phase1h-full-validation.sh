#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
ROOT="${1:-$(mktemp -d /tmp/crown-phase1h.XXXXXX)}"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1d}"
KEEP_WORKDIR="${KEEP_WORKDIR:-1}"
SYSTEMNODE_SERVICE_ADDR="${SYSTEMNODE_SERVICE_ADDR:-}"
if [ -z "$SYSTEMNODE_SERVICE_ADDR" ]; then
  echo "Set SYSTEMNODE_SERVICE_ADDR to the service-address string to write in systemnode.conf (example: 8.8.8.8:24003)." >&2
  exit 1
fi

export BIN_DIR RPC_USER RPC_PASS KEEP_WORKDIR
source "$REPO_ROOT/contrib/devtools/revival/mnpos-repro-common.sh"

record_node_state() {
  local tag="$1"
  for n in "${NODES[@]}"; do
    rpc "$ROOT" "$n" getnetworkinfo > "$ROOT/$n.networkinfo.$tag.json"
    rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.$tag.json"
    rpc "$ROOT" "$n" getpeerinfo > "$ROOT/$n.peerinfo.$tag.json"
    rpc "$ROOT" "$n" spork active > "$ROOT/$n.spork.active.$tag.json"
    rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.$tag.txt" || true
    rpc "$ROOT" "$n" masternode count > "$ROOT/$n.masternode.count.$tag.txt" || true
  done
}

decode_address_to_keyhash() {
  python3 - "$1" <<'PY'
import sys, hashlib
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = sys.argv[1]
num = 0
for c in s:
    if c not in alphabet:
        raise SystemExit("invalid base58 character in address")
    num = num * 58 + alphabet.index(c)
b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
pad = 0
for c in s:
    if c == '1':
        pad += 1
    else:
        break
b = b'\x00' * pad + b
if len(b) < 5:
    raise SystemExit("address too short")
payload, checksum = b[:-4], b[-4:]
calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
if checksum != calc:
    raise SystemExit("base58 checksum mismatch")
if len(payload) < 21:
    raise SystemExit("unexpected payload length")
payload = b[:-4]
print(payload[-20:].hex())
PY
}

build_raw_payment_tx() {
  local utxos_json="$1"
  local dest_keyhash="$2"
  local change_keyhash="$3"
  local amount="$4"
  local fee="$5"
  python3 - "$utxos_json" "$dest_keyhash" "$change_keyhash" "$amount" "$fee" <<'PY'
import sys, json, decimal, struct
utxos = json.load(open(sys.argv[1]))
dest = sys.argv[2]
change_dest = sys.argv[3]
amount = decimal.Decimal(sys.argv[4])
fee = decimal.Decimal(sys.argv[5])
need = amount + fee

selected = []
total = decimal.Decimal('0')
for u in utxos:
    selected.append(u)
    total += decimal.Decimal(str(u['amount']))
    if total >= need:
        break
if total < need:
    raise SystemExit('insufficient funds')

change = total - amount - fee

def vi(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def p2pkh(keyhash):
    return bytes.fromhex('76a914' + keyhash + '88ac')

payload = bytearray(struct.pack('<I', 1))
payload += vi(len(selected))
for u in selected:
    payload += bytes.fromhex(u['txid'])[::-1]
    payload += struct.pack('<I', int(u['vout']))
    payload += b'\x00'
    payload += struct.pack('<I', 0xffffffff)

outputs = [(amount, p2pkh(dest))]
if change > 0:
    outputs.append((change, p2pkh(change_dest)))

payload += vi(len(outputs))
for out_amount, script in outputs:
    sats = int((out_amount * decimal.Decimal(100000000)).to_integral_value())
    payload += struct.pack('<q', sats)
    payload += vi(len(script))
    payload += script

payload += struct.pack('<I', 0)
print(payload.hex())
PY
}

wait_all_equal_height() {
  local min_height="$1"
  for _ in $(seq 1 120); do
    local ok=1
    local ref=-1
    for n in "${NODES[@]}"; do
      local h
      h="$(rpc "$ROOT" "$n" getblockcount)"
      if [ "$ref" = "-1" ]; then
        ref="$h"
      fi
      if [ "$h" != "$ref" ] || [ "$h" -lt "$min_height" ]; then
        ok=0
      fi
    done
    if [ "$ok" -eq 1 ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

stop_network() {
  "$REPO_ROOT/contrib/devtools/revival/stop-mnpos-regtest.sh" "$ROOT" >/dev/null 2>&1 || true
}

stop_network
start_network "$ROOT"
record_node_state "initial"

# Baseline chain + tx propagation
rpc "$ROOT" ctl setgenerate true 130 >/dev/null
wait_height "$ROOT" 130
wait_all_equal_height 130 || { echo "initial chain convergence failed before tx propagation test" >&2; exit 1; }
rpc "$ROOT" mn1 getnewaddress > "$ROOT/mn1.addr"
rpc "$ROOT" ctl getnewaddress > "$ROOT/ctl.addr"
MN_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/mn1.addr")")"
CTL_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/ctl.addr")")"
rpc "$ROOT" ctl listunspent > "$ROOT/utxos.base.json"
RAW_TX="$(build_raw_payment_tx "$ROOT/utxos.base.json" "$MN_KEYHASH" "$CTL_KEYHASH" "0.2" "0.01")"
rpc "$ROOT" ctl signrawtransaction "$RAW_TX" > "$ROOT/base.signed.json"
TX_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hex"])' "$ROOT/base.signed.json")"
BASE_TXID="$(rpc "$ROOT" ctl sendrawtransaction "$TX_HEX")"
printf '%s\n' "$BASE_TXID" > "$ROOT/base.txid"
PROPAGATED=0
for _ in $(seq 1 20); do
  all_seen=1
  for n in "${NODES[@]}"; do
    rpc "$ROOT" "$n" getrawmempool > "$ROOT/$n.mempool.base.preconfirm.json"
    if ! grep -q "$BASE_TXID" "$ROOT/$n.mempool.base.preconfirm.json"; then
      all_seen=0
    fi
  done
  if [ "$all_seen" -eq 1 ]; then
    PROPAGATED=1
    break
  fi
  sleep 1
done
if [ "$PROPAGATED" -ne 1 ]; then
  echo "mempool propagation did not converge across all nodes" >&2
  exit 1
fi
rpc "$ROOT" ctl setgenerate true 1 >/dev/null
wait_all_equal_height 131
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" getrawmempool > "$ROOT/$n.mempool.base.postconfirm.json"
done
record_node_state "after_base"

# Collateral + registration-divergence checks
rpc "$ROOT" sn1 getnewaddress > "$ROOT/sn1.tcrw"
rpc "$ROOT" ctl getnewaddress > "$ROOT/ctl2.tcrw"
SN_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/sn1.tcrw")")"
CTL2_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/ctl2.tcrw")")"
rpc "$ROOT" ctl setgenerate true 569 >/dev/null
wait_height "$ROOT" 700
SN_COLLATERAL_TXID="$(build_collateral_transaction "$ROOT" "$SN_KEYHASH" "$CTL2_KEYHASH")"
printf '%s\n' "$SN_COLLATERAL_TXID" > "$ROOT/sn.collateral.txid"
SN_KEY1="$(rpc "$ROOT" sn1 node genkey)"
cat > "$ROOT/sn1/regtest/systemnode.conf" <<CFG
sn1 $SYSTEMNODE_SERVICE_ADDR $SN_KEY1 $SN_COLLATERAL_TXID 0
CFG
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"

rpc "$ROOT" ctl setgenerate true 14 >/dev/null
wait_height "$ROOT" 714
rpc "$ROOT" sn1 systemnode start-alias sn1 > "$ROOT/sn.start.14.json" || true
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.after14.txt"
done

rpc "$ROOT" ctl setgenerate true 1 >/dev/null
wait_height "$ROOT" 715
CONF15_TIME="$(find_conf15_time "$ROOT" "$SN_COLLATERAL_TXID")"
NOW="$(date +%s)"
printf '%s\n' "$CONF15_TIME" > "$ROOT/sn.conf15.time"
printf '%s\n' "$NOW" > "$ROOT/sn.now.before_early"
rpc "$ROOT" sn1 systemnode start-alias sn1 > "$ROOT/sn.start.early.json" || true
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.after_early.txt"
done

MAX_WAIT_SECS="${MAX_WAIT_SECS:-600}"
# MAX_WAIT_SECS bounds the total wait from first maturity check through
# eventual successful local-registration retry.
WAIT_START="$(date +%s)"
DEADLINE=$((WAIT_START + MAX_WAIT_SECS))
NOW_FOR_WAIT="$(date +%s)"
if [ "$NOW_FOR_WAIT" -lt "$CONF15_TIME" ]; then
  SLEEP_UNTIL_MATURITY=$((CONF15_TIME - NOW_FOR_WAIT))
  REMAINING_WINDOW=$((DEADLINE - NOW_FOR_WAIT))
  if [ "$SLEEP_UNTIL_MATURITY" -gt "$REMAINING_WINDOW" ]; then
    echo "Maturity wait exceeds remaining timeout window ($SLEEP_UNTIL_MATURITY > $REMAINING_WINDOW)" >&2
    exit 1
  fi
  # Add one second so the first retry happens strictly after the maturity time.
  sleep "$((SLEEP_UNTIL_MATURITY + 1))"
fi
while true; do
  set +e
  START_RESULT="$(rpc "$ROOT" sn1 systemnode start-alias sn1 2>/dev/null)"
  START_RC=$?
  set -e
  if [ "$START_RC" -eq 0 ] && python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",""))' <<<"$START_RESULT" | grep -qx 'successful'; then
    printf '%s\n' "$START_RESULT" > "$ROOT/sn.start.valid.json"
    break
  fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    if [ -n "${START_RESULT:-}" ] && python3 -c 'import json,sys; json.load(sys.stdin)' <<<"$START_RESULT" >/dev/null 2>&1; then
      printf '%s\n' "$START_RESULT" > "$ROOT/sn.start.valid.json"
    else
      printf '%s\n' '{"result":"failed","errorMessage":"timed out waiting for valid registration"}' > "$ROOT/sn.start.valid.json"
    fi
    echo "Timed out waiting for valid systemnode registration after maturity window" >&2
    exit 1
  fi
  sleep 1
done
sleep 3
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.after_valid.txt"
  rpc "$ROOT" "$n" systemnode list status > "$ROOT/$n.systemnode.status.after_valid.json"
done
record_node_state "after_sn_valid"

# PR #10 duplicate-IP semantics
rpc "$ROOT" sn1 systemnode start-alias sn1 > "$ROOT/sn.start.samevin.json" || true
rpc "$ROOT" sn1 getnewaddress > "$ROOT/sn2.tcrw"
SN2_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/sn2.tcrw")")"
SN2_COLLATERAL_TXID="$(build_collateral_transaction "$ROOT" "$SN2_KEYHASH" "$CTL2_KEYHASH")"
printf '%s\n' "$SN2_COLLATERAL_TXID" > "$ROOT/sn2.collateral.txid"
rpc "$ROOT" ctl setgenerate true 20 >/dev/null
wait_all_equal_height 735 || { echo "pre-duplicate convergence failed" >&2; exit 1; }
SN2_CONF15_TIME="$(find_conf15_time "$ROOT" "$SN2_COLLATERAL_TXID")"
SN2_NOW="$(date +%s)"
if [ "$SN2_NOW" -lt "$SN2_CONF15_TIME" ]; then
  SN2_WAIT=$((SN2_CONF15_TIME - SN2_NOW + 1))
  if [ "$SN2_WAIT" -gt "$MAX_WAIT_SECS" ]; then
    echo "sn2 maturity wait exceeds MAX_WAIT_SECS ($SN2_WAIT > $MAX_WAIT_SECS)" >&2
    exit 1
  fi
  sleep "$SN2_WAIT"
fi
SN_KEY2="$(rpc "$ROOT" sn1 node genkey)"
printf '%s\n' "sn2 $SYSTEMNODE_SERVICE_ADDR $SN_KEY2 $SN2_COLLATERAL_TXID 0" >> "$ROOT/sn1/regtest/systemnode.conf"
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"
rpc "$ROOT" sn1 systemnode list-conf > "$ROOT/sn.listconf.after_sn2_restart.json"
rpc "$ROOT" sn1 systemnode start-alias sn2 > "$ROOT/sn.start.diffvin.json" || true

# Restart and persistence
restart_node "$ROOT" sn1
restart_node "$ROOT" obs
reconnect_topology "$ROOT"
wait_all_equal_height 735 || { echo "restart convergence failed" >&2; exit 1; }
record_node_state "after_restart"

# Service-node loss/rejoin
rpc "$ROOT" sn1 stop >/dev/null || true
sleep 3
rpc "$ROOT" ctl setgenerate true 3 >/dev/null
OFFLINE_CONVERGED=0
for _ in $(seq 1 120); do
  hc="$(rpc "$ROOT" ctl getblockcount)"
  hm="$(rpc "$ROOT" mn1 getblockcount)"
  ho="$(rpc "$ROOT" obs getblockcount)"
  if [ "$hc" = "$hm" ] && [ "$hc" = "$ho" ] && [ "$hc" -ge 738 ]; then
    OFFLINE_CONVERGED=1
    break
  fi
  sleep 1
done
if [ "$OFFLINE_CONVERGED" -ne 1 ]; then
  echo "offline-node convergence failed" >&2
  exit 1
fi
for n in ctl mn1 obs; do
  rpc "$ROOT" "$n" getnetworkinfo > "$ROOT/$n.networkinfo.sn1_offline.json"
  rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.sn1_offline.json"
  rpc "$ROOT" "$n" getpeerinfo > "$ROOT/$n.peerinfo.sn1_offline.json"
  rpc "$ROOT" "$n" spork active > "$ROOT/$n.spork.active.sn1_offline.json"
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.sn1_offline.txt" || true
  rpc "$ROOT" "$n" masternode count > "$ROOT/$n.masternode.count.sn1_offline.txt" || true
done

if ! restart_node "$ROOT" sn1; then
  echo "sn1 restart failed after offline test" >&2
  exit 1
fi
reconnect_topology "$ROOT"
wait_all_equal_height 738 || { echo "rejoin convergence failed" >&2; exit 1; }
record_node_state "after_rejoin"

# Controlled observer partition/reconnection
rpc "$ROOT" obs getblockcount > "$ROOT/obs.height.pre_partition.txt"
rpc "$ROOT" obs stop >/dev/null || true
sleep 3
if rpc "$ROOT" obs getblockcount >/dev/null 2>&1; then
  echo "observer did not stop for partition test" >&2
  exit 1
fi
rpc "$ROOT" ctl setgenerate true 2 >/dev/null
PARTITION_CORE_CONVERGED=0
for _ in $(seq 1 120); do
  hc="$(rpc "$ROOT" ctl getblockcount)"
  hm="$(rpc "$ROOT" mn1 getblockcount)"
  hs="$(rpc "$ROOT" sn1 getblockcount)"
  if [ "$hc" = "$hm" ] && [ "$hc" = "$hs" ] && [ "$hc" -ge 740 ]; then
    PARTITION_CORE_CONVERGED=1
    break
  fi
  sleep 1
done
if [ "$PARTITION_CORE_CONVERGED" -ne 1 ]; then
  echo "core-node convergence failed during observer partition" >&2
  exit 1
fi
if ! restart_node "$ROOT" obs; then
  echo "observer restart failed after partition test" >&2
  exit 1
fi
reconnect_topology "$ROOT"
wait_all_equal_height 740 || { echo "partition-reconnect convergence failed" >&2; exit 1; }
rpc "$ROOT" obs getblockcount > "$ROOT/obs.height.partition_rejoined.txt"
record_node_state "final"

# Regtest masternode-collateral feasibility snapshot
rpc "$ROOT" ctl listunspent > "$ROOT/utxos.for.mn.json"
python3 - "$ROOT/utxos.for.mn.json" > "$ROOT/mn.funds.json" <<'PY'
import json,sys,decimal
utxos=json.load(open(sys.argv[1]))
total=sum(decimal.Decimal(str(u['amount'])) for u in utxos)
print(json.dumps({"mature_spendable_total_crw": str(total), "required_masternode_collateral_crw": "10000"}, indent=2))
PY
python3 > "$ROOT/regtest_theoretical_max.json" <<'PY'
COIN=100000000
POS_START_HEIGHT=141000
HALVING_INTERVAL=150
total=0
last_positive_height = -1
for h in range(0, 20000):
    subsidy = 12 * COIN
    if h >= POS_START_HEIGHT:
        subsidy = 10 * COIN
    halvings = h // HALVING_INTERVAL
    if halvings >= 64:
        subsidy = 0
    else:
        subsidy >>= halvings
    if subsidy > 0:
        last_positive_height = h
        total += subsidy
first_zero_height = last_positive_height + 1
print('{\\n  "subsidy_halving_interval": %d,\\n  "pos_start_height_regtest_inherited": %d,\\n  "last_positive_subsidy_height": %d,\\n  "first_zero_subsidy_height": %d,\\n  "max_theoretical_subsidy_crw": "%.8f",\\n  "masternode_collateral_required_crw": "10000.00000000"\\n}' % (HALVING_INTERVAL, POS_START_HEIGHT, last_positive_height, first_zero_height, total/COIN))
PY

echo "Phase 1H capture complete."
echo "Artifacts: $ROOT"
