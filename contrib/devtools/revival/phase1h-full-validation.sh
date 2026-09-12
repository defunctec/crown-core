#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
ROOT="${1:-$(mktemp -d /tmp/crown-phase1h.XXXXXX)}"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1d}"
KEEP_WORKDIR="${KEEP_WORKDIR:-1}"

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
import sys
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = sys.argv[1]
num = 0
for c in s:
    num = num * 58 + alphabet.index(c)
b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
pad = 0
for c in s:
    if c == '1':
        pad += 1
    else:
        break
b = b'\x00' * pad + b
payload = b[:-4]
print(payload[4:24].hex())
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
for _ in $(seq 1 20); do
  all_seen=1
  for n in "${NODES[@]}"; do
    rpc "$ROOT" "$n" getrawmempool > "$ROOT/$n.mempool.base.preconfirm.json"
    if ! grep -q "$BASE_TXID" "$ROOT/$n.mempool.base.preconfirm.json"; then
      all_seen=0
    fi
  done
  if [ "$all_seen" -eq 1 ]; then
    break
  fi
  sleep 1
done
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
sn1 8.8.8.8:24003 $SN_KEY1 $SN_COLLATERAL_TXID 0
CFG
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"

rpc "$ROOT" ctl setgenerate true 14 >/dev/null
wait_height "$ROOT" 714
rpc "$ROOT" sn1 systemnode start-alias sn1 > "$ROOT/sn.start.14.json" || true
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.after14.txt"
done

rpc "$ROOT" ctl setgenerate true 6 >/dev/null
wait_height "$ROOT" 720
CONF15_TIME="$(find_conf15_time "$ROOT" "$SN_COLLATERAL_TXID")"
NOW="$(date +%s)"
printf '%s\n' "$CONF15_TIME" > "$ROOT/sn.conf15.time"
printf '%s\n' "$NOW" > "$ROOT/sn.now.before_early"
rpc "$ROOT" sn1 systemnode start-alias sn1 > "$ROOT/sn.start.early.json" || true
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.after_early.txt"
done

SLEEP_FOR=$((CONF15_TIME - NOW + 1))
if [ "$SLEEP_FOR" -gt 0 ]; then
  sleep "$SLEEP_FOR"
fi
rpc "$ROOT" sn1 systemnode start-alias sn1 > "$ROOT/sn.start.valid.json"
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
wait_all_equal_height 740
SN_KEY2="$(rpc "$ROOT" sn1 node genkey)"
printf '%s\n' "sn2 8.8.8.8:24003 $SN_KEY2 $SN2_COLLATERAL_TXID 0" >> "$ROOT/sn1/regtest/systemnode.conf"
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"
rpc "$ROOT" sn1 systemnode list-conf > "$ROOT/sn.listconf.after_sn2_restart.json"
rpc "$ROOT" sn1 systemnode start-alias sn2 > "$ROOT/sn.start.diffvin.json" || true

# Restart and persistence
restart_node "$ROOT" sn1
restart_node "$ROOT" obs
reconnect_topology "$ROOT"
wait_all_equal_height 740 || true
record_node_state "after_restart"

# Service-node loss/rejoin
rpc "$ROOT" sn1 stop >/dev/null || true
sleep 3
rpc "$ROOT" ctl setgenerate true 3 >/dev/null
for _ in $(seq 1 120); do
  hc="$(rpc "$ROOT" ctl getblockcount)"
  hm="$(rpc "$ROOT" mn1 getblockcount)"
  ho="$(rpc "$ROOT" obs getblockcount)"
  if [ "$hc" = "$hm" ] && [ "$hc" = "$ho" ] && [ "$hc" -ge 743 ]; then
    break
  fi
  sleep 1
done
for n in ctl mn1 obs; do
  rpc "$ROOT" "$n" getnetworkinfo > "$ROOT/$n.networkinfo.sn1_offline.json"
  rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.sn1_offline.json"
  rpc "$ROOT" "$n" getpeerinfo > "$ROOT/$n.peerinfo.sn1_offline.json"
  rpc "$ROOT" "$n" spork active > "$ROOT/$n.spork.active.sn1_offline.json"
  rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.sn1_offline.txt" || true
  rpc "$ROOT" "$n" masternode count > "$ROOT/$n.masternode.count.sn1_offline.txt" || true
done

"$BIN_DIR/crownd" -datadir="$ROOT/sn1" >/dev/null
for _ in $(seq 1 60); do
  if rpc "$ROOT" sn1 getblockcount >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
reconnect_topology "$ROOT"
wait_all_equal_height 743 || true
record_node_state "after_rejoin"

# Controlled observer partition/reconnection
rpc "$ROOT" obs stop >/dev/null || true
sleep 3
rpc "$ROOT" ctl setgenerate true 2 >/dev/null
for _ in $(seq 1 120); do
  hc="$(rpc "$ROOT" ctl getblockcount)"
  hm="$(rpc "$ROOT" mn1 getblockcount)"
  hs="$(rpc "$ROOT" sn1 getblockcount)"
  if [ "$hc" = "$hm" ] && [ "$hc" = "$hs" ] && [ "$hc" -ge 745 ]; then
    break
  fi
  sleep 1
done
"$BIN_DIR/crownd" -datadir="$ROOT/obs" >/dev/null
for _ in $(seq 1 60); do
  if rpc "$ROOT" obs getblockcount >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
rpc "$ROOT" obs addnode 127.0.0.1:24001 add >/dev/null 2>&1 || true
rpc "$ROOT" obs addnode 127.0.0.1:24001 onetry >/dev/null 2>&1 || true
wait_all_equal_height 745 || true
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
total=0
for h in range(1, 150*64+1):
    total += (12*COIN) >> (h//150)
print('{\\n  "subsidy_halving_interval": 150,\\n  "pos_start_height_regtest_inherited": 141000,\\n  "reward_zero_after_height": 9600,\\n  "max_theoretical_subsidy_crw": "%.8f",\\n  "masternode_collateral_required_crw": "10000.00000000"\\n}' % (total/COIN))
PY

echo "Phase 1H capture complete."
echo "Artifacts: $ROOT"
