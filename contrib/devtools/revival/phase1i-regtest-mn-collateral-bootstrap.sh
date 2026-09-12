#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
ROOT="${1:-$(mktemp -d /tmp/crown-phase1i.XXXXXX)}"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1i}"
KEEP_WORKDIR="${KEEP_WORKDIR:-1}"
REGTEST_SUBSIDY_HALVING_INTERVAL="${REGTEST_SUBSIDY_HALVING_INTERVAL:-2100000}"
PHASE1I_DEEP_VALIDATION="${PHASE1I_DEEP_VALIDATION:-0}"
if [ "$PHASE1I_DEEP_VALIDATION" = "1" ]; then
  REGTEST_POS_START_HEIGHT="${REGTEST_POS_START_HEIGHT:-141000}"
  FUNDING_HEIGHT="${FUNDING_HEIGHT:-1000}"
  PRE_POS_CHUNK="${PRE_POS_CHUNK:-2000}"
  STAGE_WAIT_SECS="${STAGE_WAIT_SECS:-180}"
  START_ALIAS_WAIT_SECS="${START_ALIAS_WAIT_SECS:-600}"
  PRE_POS_WAIT_SECS="${PRE_POS_WAIT_SECS:-7200}"
  POS_WAIT_SECS="${POS_WAIT_SECS:-180}"
  POST_POS_WAIT_SECS="${POST_POS_WAIT_SECS:-600}"
else
  REGTEST_POS_START_HEIGHT="${REGTEST_POS_START_HEIGHT:-1200}"
  FUNDING_HEIGHT="${FUNDING_HEIGHT:-980}"
  PRE_POS_CHUNK="${PRE_POS_CHUNK:-100}"
  STAGE_WAIT_SECS="${STAGE_WAIT_SECS:-120}"
  START_ALIAS_WAIT_SECS="${START_ALIAS_WAIT_SECS:-120}"
  PRE_POS_WAIT_SECS="${PRE_POS_WAIT_SECS:-180}"
  POS_WAIT_SECS="${POS_WAIT_SECS:-120}"
  POST_POS_WAIT_SECS="${POST_POS_WAIT_SECS:-180}"
fi
  MAX_COLLATERAL_TX_INPUTS="${MAX_COLLATERAL_TX_INPUTS:-120}"
  COLLATERAL_TX_FEE="${COLLATERAL_TX_FEE:-0.01}"
  FINAL_CONVERGENCE_WAIT_SECS="${FINAL_CONVERGENCE_WAIT_SECS:-60}"
  FINAL_CONVERGENCE_POLL_SECS="${FINAL_CONVERGENCE_POLL_SECS:-2}"
  LIST_CONVERGENCE_WAIT_SECS="${LIST_CONVERGENCE_WAIT_SECS:-60}"
  SYSTEMNODE_SERVICE_ADDR="${SYSTEMNODE_SERVICE_ADDR:-}"
  MASTERNODE_SERVICE_ADDR="${MASTERNODE_SERVICE_ADDR:-}"

if [ -z "$SYSTEMNODE_SERVICE_ADDR" ]; then
  echo "Set SYSTEMNODE_SERVICE_ADDR (example: 8.8.8.8:24003)." >&2
  exit 1
fi
if [ -z "$MASTERNODE_SERVICE_ADDR" ]; then
  echo "Set MASTERNODE_SERVICE_ADDR (example: 8.8.4.4:24002)." >&2
  exit 1
fi
if [ "$FUNDING_HEIGHT" -le 130 ]; then
  echo "FUNDING_HEIGHT must be > 130 (current: $FUNDING_HEIGHT)." >&2
  exit 1
fi
if [ "$REGTEST_POS_START_HEIGHT" -le "$FUNDING_HEIGHT" ]; then
  echo "REGTEST_POS_START_HEIGHT must be greater than FUNDING_HEIGHT (current: $REGTEST_POS_START_HEIGHT, funding: $FUNDING_HEIGHT)." >&2
  exit 1
fi

export BIN_DIR RPC_USER RPC_PASS KEEP_WORKDIR REGTEST_SUBSIDY_HALVING_INTERVAL REGTEST_POS_START_HEIGHT
source "$REPO_ROOT/contrib/devtools/revival/mnpos-repro-common.sh"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
stage_begin() { echo "[$(ts)] BEGIN $1"; }
stage_end() { echo "[$(ts)] END $1"; }
VALIDATION_START_TS="$(date +%s)"
CHECKPOINT_DIR="$ROOT/checkpoints"
mkdir -p "$CHECKPOINT_DIR"

stage_fail() {
  local stage="$1"
  local reason="$2"
  echo "[$(ts)] FAIL $stage: $reason" >&2
  return 1
}

print_failure_diagnostics() {
  echo "[$(ts)] DIAGNOSTICS begin" >&2
  for n in "${NODES[@]}"; do
    local height hash peers mn_state sn_state
    height="$(rpc "$ROOT" "$n" getblockcount 2>/dev/null || echo "rpc-error")"
    hash="$(rpc "$ROOT" "$n" getbestblockhash 2>/dev/null || echo "rpc-error")"
    peers="$(rpc "$ROOT" "$n" getconnectioncount 2>/dev/null || echo "rpc-error")"
    mn_state="$(rpc "$ROOT" "$n" masternode count 2>/dev/null || echo "rpc-error")"
    sn_state="$(rpc "$ROOT" "$n" systemnode count 2>/dev/null || echo "rpc-error")"
    echo "[$(ts)] node=$n height=$height besthash=$hash peers=$peers masternode_count=$mn_state systemnode_count=$sn_state" >&2
    rpc "$ROOT" "$n" getpeerinfo > "$CHECKPOINT_DIR/$n.peerinfo.failure.json" 2>/dev/null || true
    rpc "$ROOT" "$n" getblockchaininfo > "$CHECKPOINT_DIR/$n.blockchaininfo.failure.json" 2>/dev/null || true
    rpc "$ROOT" "$n" systemnode list status > "$CHECKPOINT_DIR/$n.systemnode.status.failure.json" 2>/dev/null || true
    rpc "$ROOT" "$n" masternode list status > "$CHECKPOINT_DIR/$n.masternode.status.failure.json" 2>/dev/null || true
    tail -n 120 "$ROOT/$n/regtest/debug.log" > "$CHECKPOINT_DIR/$n.debug.failure.tail.log" 2>/dev/null || true
  done
  echo "[$(ts)] DIAGNOSTICS end" >&2
}

cleanup_on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    print_failure_diagnostics
    echo "[$(ts)] FAILED rc=$rc artifacts=$ROOT" >&2
  else
    local elapsed=$(( $(date +%s) - VALIDATION_START_TS ))
    echo "[$(ts)] COMPLETE artifacts=$ROOT runtime_seconds=$elapsed"
  fi
  "$REPO_ROOT/contrib/devtools/revival/stop-mnpos-regtest.sh" "$ROOT" >/dev/null 2>&1 || true
}
trap cleanup_on_exit EXIT INT TERM

rpc_or_placeholder() {
  local node="$1"
  shift
  rpc "$ROOT" "$node" "$@" 2>/dev/null || echo "RPC_ERROR"
}

capture_checkpoint() {
  local tag="$1"
  local safe_tag="${tag// /_}"
  for n in "${NODES[@]}"; do
    local height hash peers chainwork mn_count sn_count
    height="$(rpc_or_placeholder "$n" getblockcount)"
    hash="$(rpc_or_placeholder "$n" getbestblockhash)"
    peers="$(rpc_or_placeholder "$n" getconnectioncount)"
    chainwork="$(rpc_or_placeholder "$n" getblockchaininfo | python3 -c 'import json,sys; d=sys.stdin.read().strip(); print(json.loads(d).get("chainwork","RPC_ERROR") if d and d!="RPC_ERROR" else "RPC_ERROR")' 2>/dev/null || echo "RPC_ERROR")"
    mn_count="$(rpc_or_placeholder "$n" masternode count)"
    sn_count="$(rpc_or_placeholder "$n" systemnode count)"
    printf '%s\n' "$height" > "$CHECKPOINT_DIR/$safe_tag.$n.height.txt"
    printf '%s\n' "$hash" > "$CHECKPOINT_DIR/$safe_tag.$n.besthash.txt"
    printf '%s\n' "$peers" > "$CHECKPOINT_DIR/$safe_tag.$n.peers.txt"
    printf '%s\n' "$chainwork" > "$CHECKPOINT_DIR/$safe_tag.$n.chainwork.txt"
    printf '%s\n' "$mn_count" > "$CHECKPOINT_DIR/$safe_tag.$n.masternode.count.txt"
    printf '%s\n' "$sn_count" > "$CHECKPOINT_DIR/$safe_tag.$n.systemnode.count.txt"
    rpc "$ROOT" "$n" getpeerinfo > "$CHECKPOINT_DIR/$safe_tag.$n.peerinfo.json" 2>/dev/null || true
    rpc "$ROOT" "$n" masternode list status > "$CHECKPOINT_DIR/$safe_tag.$n.masternode.status.json" 2>/dev/null || true
    rpc "$ROOT" "$n" systemnode list status > "$CHECKPOINT_DIR/$safe_tag.$n.systemnode.status.json" 2>/dev/null || true
    echo "[$(ts)] checkpoint=$safe_tag node=$n height=$height hash=$hash peers=$peers chainwork=$chainwork mn_count=$mn_count sn_count=$sn_count"
  done
}

wait_tip_hash_convergence() {
  local timeout_secs="$1"
  local poll_secs="$2"
  local drive_staking="${3:-1}"
  local deadline=$(( $(date +%s) + timeout_secs ))
  local tick=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    tick=$((tick + 1))
    reconnect_topology "$ROOT"
    reinforce_observer_connectivity
    if [ "$drive_staking" = "1" ]; then
      sync_mocktime_to_tip
    fi
    local lines=()
    local first_height=""
    local first_hash=""
    local all_equal=1
    for n in "${NODES[@]}"; do
      local h bh
      h="$(rpc_or_placeholder "$n" getblockcount)"
      bh="$(rpc_or_placeholder "$n" getbestblockhash)"
      lines+=("$n=$h/$bh")
      if [ -z "$first_height" ]; then
        first_height="$h"
        first_hash="$bh"
      elif [ "$h" != "$first_height" ] || [ "$bh" != "$first_hash" ]; then
        all_equal=0
      fi
      if [ "$h" = "RPC_ERROR" ] || [ "$bh" = "RPC_ERROR" ]; then
        all_equal=0
      fi
    done
    echo "[$(ts)] convergence ${lines[*]}"
    rpc "$ROOT" obs getpeerinfo > "$CHECKPOINT_DIR/convergence.obs.peerinfo.$tick.json" 2>/dev/null || true
    if [ "$all_equal" -eq 1 ]; then
      return 0
    fi
    sleep "$poll_secs"
  done
  return 1
}

wait_service_list_convergence() {
  local timeout_secs="$1"
  local poll_secs="$2"
  local deadline=$(( $(date +%s) + timeout_secs ))
  local tick=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    tick=$((tick + 1))
    local ok=1
    for kind in masternode systemnode; do
      local base=""
      for n in "${NODES[@]}"; do
        local payload
        payload="$(rpc_or_placeholder "$n" "$kind" list status)"
        local canonical
        canonical="$(printf '%s' "$payload" | python3 -c 'import json,sys; d=sys.stdin.read().strip(); print("RPC_ERROR" if d=="RPC_ERROR" or not d else json.dumps(json.loads(d), sort_keys=True))' 2>/dev/null || echo "RPC_ERROR")"
        printf '%s\n' "$canonical" > "$CHECKPOINT_DIR/list_convergence.$tick.$kind.$n.json"
        if [ -z "$base" ]; then
          base="$canonical"
        elif [ "$canonical" != "$base" ]; then
          ok=0
        fi
      done
    done
    if [ "$ok" -eq 1 ]; then
      return 0
    fi
    sleep "$poll_secs"
  done
  return 1
}

reinforce_observer_connectivity() {
  rpc "$ROOT" obs addnode 127.0.0.1:24001 add >/dev/null 2>&1 || true
  rpc "$ROOT" obs addnode 127.0.0.1:24002 add >/dev/null 2>&1 || true
  rpc "$ROOT" obs addnode 127.0.0.1:24003 add >/dev/null 2>&1 || true
  rpc "$ROOT" obs addnode 127.0.0.1:24001 onetry >/dev/null 2>&1 || true
  rpc "$ROOT" obs addnode 127.0.0.1:24002 onetry >/dev/null 2>&1 || true
  rpc "$ROOT" obs addnode 127.0.0.1:24003 onetry >/dev/null 2>&1 || true
}

decode_address_to_keyhash() {
  python3 - "$1" <<'PY'
import sys, hashlib
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = sys.argv[1]
num = 0
for c in s:
    if c not in alphabet:
        raise SystemExit('invalid base58 character in address')
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
    raise SystemExit('address too short')
payload, checksum = b[:-4], b[-4:]
calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
if checksum != calc:
    raise SystemExit('base58 checksum mismatch')
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

select_largest_utxos() {
  local utxos_json="$1"
  local max_inputs="$2"
  local out_json="$3"
  python3 - "$utxos_json" "$max_inputs" "$out_json" <<'PY'
import json, decimal, sys
utxos = json.load(open(sys.argv[1]))
max_inputs = int(sys.argv[2])
out_json = sys.argv[3]
utxos = sorted(utxos, key=lambda u: decimal.Decimal(str(u['amount'])), reverse=True)
sel = utxos[:max_inputs]
total = sum(decimal.Decimal(str(u['amount'])) for u in sel)
json.dump(sel, open(out_json, 'w'))
print(total)
PY
}

max_utxo_amount() {
  local utxos_json="$1"
  python3 - "$utxos_json" <<'PY'
import json, decimal, sys
utxos = json.load(open(sys.argv[1]))
if not utxos:
    print("0")
else:
    print(max(decimal.Decimal(str(u['amount'])) for u in utxos))
PY
}

ensure_large_ctl_utxo() {
  local min_amount="$1"
  local payout_keyhash="$2"
  local label="$3"
  local rounds=0
  while true; do
    rpc "$ROOT" ctl listunspent > "$ROOT/utxos.$label.ensure.json"
    local largest
    largest="$(max_utxo_amount "$ROOT/utxos.$label.ensure.json")"
    if python3 - "$largest" "$min_amount" <<'PY'
import decimal, sys
largest = decimal.Decimal(sys.argv[1])
need = decimal.Decimal(sys.argv[2])
raise SystemExit(0 if largest >= need else 1)
PY
    then
      return 0
    fi

    rounds=$((rounds + 1))
    if [ "$rounds" -gt 40 ]; then
      stage_fail "collateral UTXO preparation" "unable to consolidate to target amount $min_amount in 40 rounds"
      return 1
    fi

    local selected_json total amount raw signed txhex
    selected_json="$ROOT/utxos.$label.ensure.selected.json"
    total="$(select_largest_utxos "$ROOT/utxos.$label.ensure.json" "$MAX_COLLATERAL_TX_INPUTS" "$selected_json")"
    amount="$(python3 - "$total" "$COLLATERAL_TX_FEE" <<'PY'
import decimal, sys
total = decimal.Decimal(sys.argv[1])
fee = decimal.Decimal(sys.argv[2])
value = total - fee
if value <= 0:
    raise SystemExit("consolidation output must be positive")
print(value)
PY
)"
    raw="$(build_raw_payment_tx "$selected_json" "$payout_keyhash" "$payout_keyhash" "$amount" "$COLLATERAL_TX_FEE")"
    rpc "$ROOT" ctl signrawtransaction "$raw" > "$ROOT/$label.ensure.signed.json"
    txhex="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["complete"] is True, d; print(d["hex"])' "$ROOT/$label.ensure.signed.json")"
    rpc "$ROOT" ctl sendrawtransaction "$txhex" >/dev/null
    rpc "$ROOT" ctl setgenerate true 1 >/dev/null
    wait_all_equal_height "$(rpc "$ROOT" ctl getblockcount)" || return 1
    echo "[$(ts)] consolidation round=$rounds largest_before=$largest target=$min_amount" >&2
  done
}

create_collateral_tx() {
  local node="$1"
  local keyhash="$2"
  local change_keyhash="$3"
  local amount="$4"
  local label="$5"
  ensure_large_ctl_utxo "$(python3 - "$amount" "$COLLATERAL_TX_FEE" <<'PY'
import decimal, sys
print(decimal.Decimal(sys.argv[1]) + decimal.Decimal(sys.argv[2]))
PY
)" "$change_keyhash" "$label"
  rpc "$ROOT" ctl listunspent > "$ROOT/utxos.$label.json"
  local raw signed txhex txid
  raw="$(build_raw_payment_tx "$ROOT/utxos.$label.json" "$keyhash" "$change_keyhash" "$amount" "$COLLATERAL_TX_FEE")"
  rpc "$ROOT" ctl signrawtransaction "$raw" > "$ROOT/$label.signed.json"
  txhex="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["complete"] is True, d; print(d["hex"])' "$ROOT/$label.signed.json")"
  txid="$(rpc "$ROOT" ctl sendrawtransaction "$txhex")"
  printf '%s\n' "$txid" > "$ROOT/$label.txid"
  rpc "$ROOT" ctl setgenerate true 1 >/dev/null
  wait_all_equal_height "$(rpc "$ROOT" ctl getblockcount)"
  echo "$txid"
}

wait_all_equal_height() {
  local min_height="$1"
  for i in $(seq 1 "$STAGE_WAIT_SECS"); do
    local ok=1
    local ref=-1
    local heights=""
    for n in "${NODES[@]}"; do
      local h
      h="$(rpc "$ROOT" "$n" getblockcount)"
      heights="$heights $n=$h"
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
    if [ $((i % 10)) -eq 0 ]; then
      echo "[$(ts)] waiting convergence min_height=$min_height$heights"
    fi
    sleep 1
  done
  return 1
}

wait_start_alias_success() {
  local node="$1" kind="$2" alias="$3" out_file="$4" deadline_secs="$5"
  local deadline=$(( $(date +%s) + deadline_secs ))
  while true; do
    set +e
    local result
    result="$(rpc "$ROOT" "$node" "$kind" start-alias "$alias" 2>/dev/null)"
    local rc=$?
    set -e
    if [ "$rc" -eq 0 ] && python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",""))' <<<"$result" | grep -qx 'successful'; then
      printf '%s\n' "$result" > "$out_file"
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      if [ -n "${result:-}" ] && python3 -c 'import json,sys; json.load(sys.stdin)' <<<"$result" >/dev/null 2>&1; then
        printf '%s\n' "$result" > "$out_file"
      else
        printf '%s\n' '{"result":"failed","errorMessage":"timed out"}' > "$out_file"
      fi
      return 1
    fi
    sleep 1
  done
}

set_all_mocktime() {
  local mocktime="$1"
  for n in "${NODES[@]}"; do
    rpc "$ROOT" "$n" setmocktime "$mocktime" >/dev/null
  done
}

set_staker_mocktime() {
  local mocktime="$1"
  for n in mn1 sn1; do
    rpc "$ROOT" "$n" setmocktime "$mocktime" >/dev/null
  done
}

sync_mocktime_to_tip() {
  local tip_hash tip_time
  tip_hash="$(rpc "$ROOT" ctl getbestblockhash)"
  tip_time="$(rpc "$ROOT" ctl getblock "$tip_hash" | python3 -c 'import json,sys; print(json.load(sys.stdin)["time"])')"
  set_staker_mocktime "$((tip_time + 2))"
}

record_counts() {
  local tag="$1"
  for n in "${NODES[@]}"; do
    rpc "$ROOT" "$n" systemnode count > "$ROOT/$n.systemnode.count.$tag.txt" || true
    rpc "$ROOT" "$n" masternode count > "$ROOT/$n.masternode.count.$tag.txt" || true
    rpc "$ROOT" "$n" systemnode list status > "$ROOT/$n.systemnode.status.$tag.json" || true
    rpc "$ROOT" "$n" masternode list status > "$ROOT/$n.masternode.status.$tag.json" || true
  done
}

stage_begin "STAGE 1 — fresh network startup"
python3 - "$REGTEST_SUBSIDY_HALVING_INTERVAL" "$REGTEST_POS_START_HEIGHT" "$FUNDING_HEIGHT" > "$ROOT/regtest_profile_plan.json" <<'PY'
COIN=100000000
import sys
HALVING_INTERVAL=int(sys.argv[1])
POS_START_HEIGHT=int(sys.argv[2])
FUNDING_HEIGHT=int(sys.argv[3])
COINBASE_MATURITY=100
MN_COLLATERAL=10000
SN_COLLATERAL=500
total=0
last_positive_height=-1
for h in range(0, 20000):
    subsidy=12*COIN
    if h >= POS_START_HEIGHT:
        subsidy=10*COIN
    halvings=h // HALVING_INTERVAL
    if halvings >= 64:
        subsidy=0
    else:
        subsidy >>= halvings
    if subsidy > 0:
        total += subsidy
        last_positive_height = h
if FUNDING_HEIGHT <= COINBASE_MATURITY:
    mature_rewards = 0
else:
    mature_rewards = (FUNDING_HEIGHT - COINBASE_MATURITY) * 12
required = MN_COLLATERAL + SN_COLLATERAL
print('{\n'
      '  "halving_interval": %d,\n'
      '  "pos_start_height": %d,\n'
      '  "funding_height": %d,\n'
      '  "coinbase_maturity_blocks": %d,\n'
      '  "estimated_mature_funding_crw": %d,\n'
      '  "required_collateral_total_crw": %d,\n'
      '  "funding_margin_crw": %d,\n'
      '  "last_positive_subsidy_height": %d,\n'
      '  "first_zero_subsidy_height": %d,\n'
      '  "max_theoretical_subsidy_crw": "%.8f"\n'
      '}' % (HALVING_INTERVAL, POS_START_HEIGHT, FUNDING_HEIGHT, COINBASE_MATURITY, mature_rewards, required, mature_rewards - required, last_positive_height, last_positive_height + 1, total / COIN))
PY

"$REPO_ROOT/contrib/devtools/revival/stop-mnpos-regtest.sh" "$ROOT" >/dev/null 2>&1 || true
start_network "$ROOT"
reinforce_observer_connectivity

for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" getnetworkinfo > "$ROOT/$n.networkinfo.initial.json"
  rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.initial.json"
  rpc "$ROOT" "$n" getpeerinfo > "$ROOT/$n.peerinfo.initial.json"
  rpc "$ROOT" "$n" spork active > "$ROOT/$n.spork.initial.json"
done
stage_end "STAGE 1 — fresh network startup"

stage_begin "STAGE 2 — funding/bootstrap"
rpc "$ROOT" ctl setgenerate true 130 >/dev/null
wait_all_equal_height 130 || { stage_fail "STAGE 2 — funding/bootstrap" "timeout waiting for initial chain convergence"; exit 1; }

rpc "$ROOT" ctl getnewaddress > "$ROOT/ctl.addr"
rpc "$ROOT" mn1 getnewaddress > "$ROOT/mn1.addr"
rpc "$ROOT" sn1 getnewaddress > "$ROOT/sn1.addr"
CTL_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/ctl.addr")")"
MN_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/mn1.addr")")"
SN_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/sn1.addr")")"

rpc "$ROOT" ctl setgenerate true "$((FUNDING_HEIGHT-130))" >/dev/null
wait_all_equal_height "$FUNDING_HEIGHT" || { stage_fail "STAGE 2 — funding/bootstrap" "timeout waiting for funding height convergence"; exit 1; }
rpc "$ROOT" ctl listunspent > "$ROOT/utxos.pre_collateral.json"
python3 - "$ROOT/utxos.pre_collateral.json" > "$ROOT/funding_balance.json" <<'PY'
import json, decimal, sys
utxos = json.load(open(sys.argv[1]))
total = sum(decimal.Decimal(str(u['amount'])) for u in utxos)
print('{"mature_spendable_total_crw":"%s"}' % total)
PY
stage_end "STAGE 2 — funding/bootstrap"

stage_begin "STAGE 3 — real 10,000 CRW MN collateral creation"
MN_COLLATERAL_TXID="$(create_collateral_tx mn1 "$MN_KEYHASH" "$CTL_KEYHASH" "10000" "mn.collateral")"
stage_end "STAGE 3 — real 10,000 CRW MN collateral creation"
stage_begin "STAGE 4 — collateral maturity"
SN_COLLATERAL_TXID="$(create_collateral_tx sn1 "$SN_KEYHASH" "$CTL_KEYHASH" "500" "sn.collateral")"

rpc "$ROOT" ctl setgenerate true 20 >/dev/null
wait_all_equal_height "$(rpc "$ROOT" ctl getblockcount)" || { stage_fail "STAGE 4 — collateral maturity" "timeout waiting for post-collateral maturity convergence"; exit 1; }

MN_KEY="$(rpc "$ROOT" mn1 node genkey)"
SN_KEY="$(rpc "$ROOT" sn1 node genkey)"
cat > "$ROOT/mn1/regtest/masternode.conf" <<CFG
mn1 $MASTERNODE_SERVICE_ADDR $MN_KEY $MN_COLLATERAL_TXID 0
CFG
cat > "$ROOT/sn1/regtest/systemnode.conf" <<CFG
sn1 $SYSTEMNODE_SERVICE_ADDR $SN_KEY $SN_COLLATERAL_TXID 0
CFG
echo "masternode=1" >> "$ROOT/mn1/crown.conf"
echo "masternodeprivkey=$MN_KEY" >> "$ROOT/mn1/crown.conf"
echo "masternodeaddr=$MASTERNODE_SERVICE_ADDR" >> "$ROOT/mn1/crown.conf"
echo "systemnode=1" >> "$ROOT/sn1/crown.conf"
echo "systemnodeprivkey=$SN_KEY" >> "$ROOT/sn1/crown.conf"
echo "systemnodeaddr=$SYSTEMNODE_SERVICE_ADDR" >> "$ROOT/sn1/crown.conf"

restart_node "$ROOT" mn1
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"
reinforce_observer_connectivity

record_counts "before_start"

MN_CONF15_TIME="$(find_conf15_time "$ROOT" "$MN_COLLATERAL_TXID")"
SN_CONF15_TIME="$(find_conf15_time "$ROOT" "$SN_COLLATERAL_TXID")"
printf '%s\n' "$MN_CONF15_TIME" > "$ROOT/mn.conf15.time"
printf '%s\n' "$SN_CONF15_TIME" > "$ROOT/sn.conf15.time"

NOW="$(date +%s)"
if [ "$NOW" -lt "$MN_CONF15_TIME" ] || [ "$NOW" -lt "$SN_CONF15_TIME" ]; then
  target="$MN_CONF15_TIME"
  if [ "$SN_CONF15_TIME" -gt "$target" ]; then
    target="$SN_CONF15_TIME"
  fi
  wait_secs=$((target - NOW + 1))
  if [ "$wait_secs" -gt "$START_ALIAS_WAIT_SECS" ]; then
    echo "[$(ts)] fast-forwarding node clocks by setmocktime to satisfy collateral confirmation-time gate"
    set_all_mocktime "$((target + 1))"
  else
    echo "[$(ts)] waiting ${wait_secs}s for collateral confirmation-time gate"
    sleep "$wait_secs"
  fi
fi
stage_end "STAGE 4 — collateral maturity"

stage_begin "STAGE 5 — Masternode registration"
wait_start_alias_success mn1 masternode mn1 "$ROOT/mn.start.valid.json" "$START_ALIAS_WAIT_SECS" || { stage_fail "STAGE 5 — Masternode registration" "masternode start-alias timed out"; exit 1; }
stage_end "STAGE 5 — Masternode registration"
stage_begin "STAGE 6 — Systemnode registration"
wait_start_alias_success sn1 systemnode sn1 "$ROOT/sn.start.valid.json" "$START_ALIAS_WAIT_SECS" || { stage_fail "STAGE 6 — Systemnode registration" "systemnode start-alias timed out"; exit 1; }
stage_end "STAGE 6 — Systemnode registration"
set_all_mocktime 0 || true
stage_begin "STAGE 7 — peer/list convergence"
sleep 3
record_counts "after_start"
capture_checkpoint "registration_complete"
stage_end "STAGE 7 — peer/list convergence"

stage_begin "STAGE 8 — MNPoS activation"
TARGET_PRE_POS=$((REGTEST_POS_START_HEIGHT - 1))
current_height="$(rpc "$ROOT" ctl getblockcount)"
pre_pos_deadline=$(( $(date +%s) + PRE_POS_WAIT_SECS ))
while [ "$current_height" -lt "$TARGET_PRE_POS" ]; do
  if [ "$(date +%s)" -ge "$pre_pos_deadline" ]; then
    stage_fail "STAGE 8 — MNPoS activation" "timeout before reaching pre-PoS height: current=$current_height target=$TARGET_PRE_POS"
    exit 1
  fi
  remain=$((TARGET_PRE_POS - current_height))
  chunk="$PRE_POS_CHUNK"
  if [ "$remain" -lt "$chunk" ]; then
    chunk="$remain"
  fi
  rpc "$ROOT" ctl setgenerate true "$chunk" >/dev/null
  current_height="$(rpc "$ROOT" ctl getblockcount)"
  echo "[$(ts)] activation progress height=$current_height target=$TARGET_PRE_POS"
done
wait_all_equal_height "$TARGET_PRE_POS" || { stage_fail "STAGE 8 — MNPoS activation" "timeout waiting for pre-PoS convergence"; exit 1; }
capture_checkpoint "activation_boundary"
sync_mocktime_to_tip

set +e
rpc "$ROOT" ctl keypoolrefill 200 >/dev/null 2>&1 || true
POW_AFTER_POS_ATTEMPT="$(rpc "$ROOT" ctl setgenerate true 1 2>&1)"
POW_AFTER_POS_RC=$?
set -e
printf '%s\n' "$POW_AFTER_POS_ATTEMPT" > "$ROOT/pow_after_pos_attempt.txt"
printf '%s\n' "$POW_AFTER_POS_RC" > "$ROOT/pow_after_pos_attempt.rc"
if [ "$POW_AFTER_POS_RC" -eq 0 ]; then
  stage_fail "STAGE 8 — MNPoS activation" "PoW generation succeeded unexpectedly at/after PoS boundary"
  exit 1
fi

POS_DEADLINE=$(( $(date +%s) + POS_WAIT_SECS ))
FIRST_POS_HEIGHT=""
while [ "$(date +%s)" -lt "$POS_DEADLINE" ]; do
  sync_mocktime_to_tip
  h="$(rpc "$ROOT" ctl getblockcount)"
  if [ "$h" -gt "$TARGET_PRE_POS" ]; then
    FIRST_POS_HEIGHT="$h"
    break
  fi
  echo "[$(ts)] waiting for first PoS block, height=$h target>$TARGET_PRE_POS"
  sleep 1
done
stage_end "STAGE 8 — MNPoS activation"

if [ -n "$FIRST_POS_HEIGHT" ]; then
  stage_begin "STAGE 9 — repeated MNPoS block production"
  FIRST_POS_HASH="$(rpc "$ROOT" ctl getblockhash "$FIRST_POS_HEIGHT")"
  printf '%s\n' "$FIRST_POS_HEIGHT" > "$ROOT/pos.first.height"
  printf '%s\n' "$FIRST_POS_HASH" > "$ROOT/pos.first.hash"
  capture_checkpoint "first_pos_block"

  POST_TARGET=$((FIRST_POS_HEIGHT + 19))
  POST_DEADLINE=$(( $(date +%s) + POST_POS_WAIT_SECS ))
  reached_post_target=0
  post_iter=0
  while [ "$(date +%s)" -lt "$POST_DEADLINE" ]; do
    post_iter=$((post_iter + 1))
    sync_mocktime_to_tip
    current_post_height="$(rpc "$ROOT" ctl getblockcount)"
    capture_checkpoint "post_activation_batch_${post_iter}"
    if [ "$current_post_height" -ge "$POST_TARGET" ]; then
      reached_post_target=1
      break
    fi
    echo "[$(ts)] waiting for post-activation block target current=$current_post_height target=$POST_TARGET"
    sleep 2
  done
  if [ "$reached_post_target" -ne 1 ]; then
    stage_fail "STAGE 9 — repeated MNPoS block production" "timeout waiting for post-activation block target"
    exit 1
  fi

  python3 - "$BIN_DIR" "$ROOT" "$RPC_USER" "$RPC_PASS" "$FIRST_POS_HEIGHT" "$POST_TARGET" > "$ROOT/pos_blocks_summary.json" <<'PY'
import json, subprocess, sys
bin_dir = sys.argv[1]
root = sys.argv[2]
rpc_user = sys.argv[3]
rpc_pass = sys.argv[4]
first = int(sys.argv[5])
target = int(sys.argv[6])
cmd_prefix = [f"{bin_dir}/crown-cli", f"-datadir={root}/ctl", f"-rpcuser={rpc_user}", f"-rpcpassword={rpc_pass}"]
rows = []
end = target
height_now = int(subprocess.check_output(cmd_prefix + ["getblockcount"]).decode().strip())
if end > height_now:
    end = height_now
for h in range(first, end + 1):
    bh = subprocess.check_output(cmd_prefix + ["getblockhash", str(h)]).decode().strip()
    blk = json.loads(subprocess.check_output(cmd_prefix + ["getblock", bh]).decode())
    rows.append({"height": h, "hash": bh, "flags": blk.get("flags", ""), "proofhash": blk.get("proofhash", "")})
print(json.dumps(rows, indent=2))
PY
  stage_end "STAGE 9 — repeated MNPoS block production"
else
  stage_fail "STAGE 8 — MNPoS activation" "no PoS block observed before timeout"
  exit 1
fi

stage_begin "STAGE 10 — reward/accounting checks"
reconnect_topology "$ROOT"
reinforce_observer_connectivity
capture_checkpoint "final_convergence_start"
wait_tip_hash_convergence "$FINAL_CONVERGENCE_WAIT_SECS" "$FINAL_CONVERGENCE_POLL_SECS" 1 || { stage_fail "STAGE 10 — reward/accounting checks" "timeout waiting for final tip+hash convergence"; capture_checkpoint "final_convergence_timeout"; exit 1; }
set_staker_mocktime 0 || true
sleep 1
wait_tip_hash_convergence "$FINAL_CONVERGENCE_WAIT_SECS" "$FINAL_CONVERGENCE_POLL_SECS" 0 || { stage_fail "STAGE 10 — reward/accounting checks" "timeout waiting for quiesced tip+hash convergence"; capture_checkpoint "final_quiesced_convergence_timeout"; exit 1; }
capture_checkpoint "final_chain_converged"
wait_service_list_convergence "$LIST_CONVERGENCE_WAIT_SECS" "$FINAL_CONVERGENCE_POLL_SECS" || { stage_fail "STAGE 10 — reward/accounting checks" "timeout waiting for MN/SN list convergence after tip convergence"; capture_checkpoint "final_list_convergence_timeout"; exit 1; }
capture_checkpoint "final_list_converged"
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.final.json"
  rpc "$ROOT" "$n" getbestblockhash > "$ROOT/$n.besthash.final.txt"
  rpc "$ROOT" "$n" getblockcount > "$ROOT/$n.height.final.txt"
done
python3 - "$ROOT" <<'PY'
import sys, pathlib
root = pathlib.Path(sys.argv[1])
nodes = ["ctl", "mn1", "sn1", "obs"]
heights = {n: int((root / f"{n}.height.final.txt").read_text().strip()) for n in nodes}
hashes = {n: (root / f"{n}.besthash.final.txt").read_text().strip() for n in nodes}
if len(set(heights.values())) != 1:
    raise SystemExit("height divergence: %s" % heights)
if len(set(hashes.values())) != 1:
    raise SystemExit("besthash divergence: %s" % hashes)
print('{"final_height": %d, "final_besthash": "%s"}' % (next(iter(heights.values())), next(iter(hashes.values()))))
PY
stage_end "STAGE 10 — reward/accounting checks"

stage_begin "STAGE 11 — cleanup"
set_all_mocktime 0 || true
echo "Phase 1I capture complete. mode=$([ "$PHASE1I_DEEP_VALIDATION" = "1" ] && echo deep || echo fast) artifacts=$ROOT"
stage_end "STAGE 11 — cleanup"
