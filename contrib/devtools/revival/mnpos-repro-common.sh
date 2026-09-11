#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
START_SCRIPT="$REPO_ROOT/contrib/devtools/revival/start-mnpos-regtest.sh"
STOP_SCRIPT="$REPO_ROOT/contrib/devtools/revival/stop-mnpos-regtest.sh"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1d}"
NODES=(ctl mn1 sn1 obs)

cleanup_root() {
  local root="$1"
  "$STOP_SCRIPT" "$root" >/dev/null 2>&1 || true
  if [ "${KEEP_WORKDIR:-0}" != "1" ]; then
    rm -rf "$root"
  fi
}

rpc() {
  local root="$1" node="$2"
  shift 2
  "$BIN_DIR/crown-cli" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -datadir="$root/$node" "$@"
}

start_network() {
  local root="$1"
  "$START_SCRIPT" "$root" >/dev/null
}

restart_node() {
  local root="$1" node="$2"
  rpc "$root" "$node" stop >/dev/null 2>&1 || true
  sleep 3
  "$BIN_DIR/crownd" -datadir="$root/$node" >/dev/null
  for _ in $(seq 1 60); do
    if rpc "$root" "$node" getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "failed to restart node '$node'" >&2
  return 1
}

reconnect_topology() {
  local root="$1"
  rpc "$root" ctl addnode 127.0.0.1:24002 add >/dev/null || true
  rpc "$root" ctl addnode 127.0.0.1:24003 add >/dev/null || true
  rpc "$root" ctl addnode 127.0.0.1:24004 add >/dev/null || true
  rpc "$root" mn1 addnode 127.0.0.1:24001 add >/dev/null || true
  rpc "$root" sn1 addnode 127.0.0.1:24001 add >/dev/null || true
  rpc "$root" obs addnode 127.0.0.1:24001 add >/dev/null || true

  rpc "$root" ctl addnode 127.0.0.1:24002 onetry >/dev/null || true
  rpc "$root" ctl addnode 127.0.0.1:24003 onetry >/dev/null || true
  rpc "$root" ctl addnode 127.0.0.1:24004 onetry >/dev/null || true
  rpc "$root" mn1 addnode 127.0.0.1:24001 onetry >/dev/null || true
  rpc "$root" sn1 addnode 127.0.0.1:24001 onetry >/dev/null || true
  rpc "$root" obs addnode 127.0.0.1:24001 onetry >/dev/null || true
}

wait_height() {
  local root="$1" target="$2"
  for node in "${NODES[@]}"; do
    for _ in $(seq 1 180); do
      if [ "$(rpc "$root" "$node" getblockcount)" = "$target" ]; then
        break
      fi
      sleep 1
    done
    if [ "$(rpc "$root" "$node" getblockcount)" != "$target" ]; then
      echo "node '$node' did not reach height $target" >&2
      return 1
    fi
  done
}

decode_keyhash() {
  python3 - "$1" <<'PY'
import sys
alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s=sys.argv[1]
num=0
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

build_collateral_transaction() {
  local root="$1"
  local sn_keyhash="$2"
  local ctl_keyhash="$3"

  rpc "$root" ctl listunspent > "$root/utxos.json"

  local raw signed_file tx_hex
  raw="$(python3 - "$root/utxos.json" "$sn_keyhash" "$ctl_keyhash" <<'PY'
import sys, json, decimal, struct
with open(sys.argv[1]) as f:
    utxos = json.load(f)
snkh = sys.argv[2]
ctlkh = sys.argv[3]
need = decimal.Decimal('500.01')
selected = []
total = decimal.Decimal('0')
for u in utxos:
    selected.append(u)
    total += decimal.Decimal(str(u['amount']))
    if total >= need:
        break
if total < need:
    raise SystemExit('insufficient mature funds for collateral transaction')
fee = decimal.Decimal('0.01')
change = total - decimal.Decimal('500') - fee

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
outputs = [(decimal.Decimal('500'), p2pkh(snkh))]
if change > 0:
    outputs.append((change, p2pkh(ctlkh)))
payload += vi(len(outputs))
for amount, script in outputs:
    sats = int((amount * decimal.Decimal(100000000)).to_integral_value())
    payload += struct.pack('<q', sats)
    payload += vi(len(script))
    payload += script
payload += struct.pack('<I', 0)
print(payload.hex())
PY
)"

  signed_file="$root/signed.json"
  rpc "$root" ctl signrawtransaction "$raw" > "$signed_file"
  tx_hex="$(python3 - "$signed_file" <<'PY'
import sys, json
with open(sys.argv[1]) as f:
    data = json.load(f)
assert data["complete"] is True, data
print(data["hex"])
PY
)"
  rpc "$root" ctl sendrawtransaction "$tx_hex"
}

prepare_collateral() {
  local root="$1"
  rpc "$root" sn1 getnewaddress > "$root/sn1.tcrw"
  rpc "$root" ctl getnewaddress > "$root/ctl.tcrw"
  local sn_tcrw ctl_tcrw sn_keyhash ctl_keyhash collateral_txid
  sn_tcrw="$(cat "$root/sn1.tcrw")"
  ctl_tcrw="$(cat "$root/ctl.tcrw")"
  sn_keyhash="$(decode_keyhash "$sn_tcrw")"
  ctl_keyhash="$(decode_keyhash "$ctl_tcrw")"

  rpc "$root" ctl setgenerate true 700 >/dev/null
  wait_height "$root" 700

  collateral_txid="$(build_collateral_transaction "$root" "$sn_keyhash" "$ctl_keyhash")"
  rpc "$root" ctl setgenerate true 20 >/dev/null
  wait_height "$root" 720

  printf '%s\n' "$collateral_txid" > "$root/collateral.txid"
  printf '%s\n' "$sn_tcrw" > "$root/sn1-payout-address.txt"
}

write_systemnode_config() {
  local root="$1"
  local collateral_txid="$2"
  local systemnode_key
  systemnode_key="$(rpc "$root" sn1 node genkey)"
  cat > "$root/sn1/regtest/systemnode.conf" <<EOF
sn1 8.8.8.8:24003 $systemnode_key $collateral_txid 0
EOF
}

render_counts() {
  local root="$1"
  for node in "${NODES[@]}"; do
    printf '=== %s ===\n' "$node"
    rpc "$root" "$node" systemnode count
    rpc "$root" "$node" systemnode list status
  done
}

find_conf15_time() {
  local root="$1"
  local txid="$2"
  local blockhash txheight conf15hash
  blockhash="$(rpc "$root" ctl getrawtransaction "$txid" 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')"
  txheight="$(rpc "$root" ctl getblock "$blockhash" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')"
  conf15hash="$(rpc "$root" ctl getblockhash "$((txheight + 14))")"
  rpc "$root" ctl getblock "$conf15hash" | python3 -c 'import json,sys; print(json.load(sys.stdin)["time"])'
}
