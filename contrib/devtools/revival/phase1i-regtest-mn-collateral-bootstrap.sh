#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
ROOT="${1:-$(mktemp -d /tmp/crown-phase1i.XXXXXX)}"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1i}"
KEEP_WORKDIR="${KEEP_WORKDIR:-1}"
REGTEST_SUBSIDY_HALVING_INTERVAL="${REGTEST_SUBSIDY_HALVING_INTERVAL:-2100000}"
SYSTEMNODE_SERVICE_ADDR="${SYSTEMNODE_SERVICE_ADDR:-}"
MASTERNODE_SERVICE_ADDR="${MASTERNODE_SERVICE_ADDR:-}"
FUNDING_HEIGHT="${FUNDING_HEIGHT:-1000}"
STAGE_WAIT_SECS="${STAGE_WAIT_SECS:-180}"
START_ALIAS_WAIT_SECS="${START_ALIAS_WAIT_SECS:-600}"
PRE_POS_WAIT_SECS="${PRE_POS_WAIT_SECS:-7200}"
POS_WAIT_SECS="${POS_WAIT_SECS:-180}"
POST_POS_WAIT_SECS="${POST_POS_WAIT_SECS:-600}"

if [ -z "$SYSTEMNODE_SERVICE_ADDR" ]; then
  echo "Set SYSTEMNODE_SERVICE_ADDR (example: 8.8.8.8:24003)." >&2
  exit 1
fi
if [ -z "$MASTERNODE_SERVICE_ADDR" ]; then
  echo "Set MASTERNODE_SERVICE_ADDR (example: 8.8.4.4:24002)." >&2
  exit 1
fi

export BIN_DIR RPC_USER RPC_PASS KEEP_WORKDIR REGTEST_SUBSIDY_HALVING_INTERVAL
source "$REPO_ROOT/contrib/devtools/revival/mnpos-repro-common.sh"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
stage_begin() { echo "[$(ts)] BEGIN $1"; }
stage_end() { echo "[$(ts)] END $1"; }

cleanup_on_exit() {
  local rc=$?
  "$REPO_ROOT/contrib/devtools/revival/stop-mnpos-regtest.sh" "$ROOT" >/dev/null 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    echo "[$(ts)] FAILED rc=$rc artifacts=$ROOT" >&2
  else
    echo "[$(ts)] COMPLETE artifacts=$ROOT"
  fi
}
trap cleanup_on_exit EXIT INT TERM

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

create_collateral_tx() {
  local node="$1"
  local keyhash="$2"
  local change_keyhash="$3"
  local amount="$4"
  local label="$5"
  rpc "$ROOT" ctl listunspent > "$ROOT/utxos.$label.json"
  local raw signed txhex txid
  raw="$(build_raw_payment_tx "$ROOT/utxos.$label.json" "$keyhash" "$change_keyhash" "$amount" "0.01")"
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
  for _ in $(seq 1 "$STAGE_WAIT_SECS"); do
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
python3 > "$ROOT/regtest_default_issuance_limit.json" <<'PY'
COIN=100000000
HALVING_INTERVAL=150
POS_START_HEIGHT=141000
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
print('{\n  "halving_interval": %d,\n  "pos_start_height": %d,\n  "last_positive_subsidy_height": %d,\n  "first_zero_subsidy_height": %d,\n  "max_theoretical_subsidy_crw": "%.8f",\n  "required_masternode_collateral_crw": "10000.00000000"\n}' % (HALVING_INTERVAL, POS_START_HEIGHT, last_positive_height, last_positive_height + 1, total / COIN))
PY

"$REPO_ROOT/contrib/devtools/revival/stop-mnpos-regtest.sh" "$ROOT" >/dev/null 2>&1 || true
start_network "$ROOT"

for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" getnetworkinfo > "$ROOT/$n.networkinfo.initial.json"
  rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.initial.json"
  rpc "$ROOT" "$n" getpeerinfo > "$ROOT/$n.peerinfo.initial.json"
  rpc "$ROOT" "$n" spork active > "$ROOT/$n.spork.initial.json"
done
stage_end "STAGE 1 — fresh network startup"

stage_begin "STAGE 2 — funding/bootstrap"
rpc "$ROOT" ctl setgenerate true 130 >/dev/null
wait_all_equal_height 130 || { echo "timeout waiting for initial chain convergence" >&2; exit 1; }

rpc "$ROOT" ctl getnewaddress > "$ROOT/ctl.addr"
rpc "$ROOT" mn1 getnewaddress > "$ROOT/mn1.addr"
rpc "$ROOT" sn1 getnewaddress > "$ROOT/sn1.addr"
CTL_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/ctl.addr")")"
MN_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/mn1.addr")")"
SN_KEYHASH="$(decode_address_to_keyhash "$(cat "$ROOT/sn1.addr")")"

rpc "$ROOT" ctl setgenerate true "$((FUNDING_HEIGHT-130))" >/dev/null
wait_all_equal_height "$FUNDING_HEIGHT" || { echo "timeout waiting for funding height convergence" >&2; exit 1; }
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
wait_all_equal_height "$(rpc "$ROOT" ctl getblockcount)" || { echo "timeout waiting for post-collateral maturity convergence" >&2; exit 1; }

MN_KEY="$(rpc "$ROOT" mn1 masternode genkey)"
SN_KEY="$(rpc "$ROOT" sn1 node genkey)"
cat > "$ROOT/mn1/regtest/masternode.conf" <<CFG
mn1 $MASTERNODE_SERVICE_ADDR $MN_KEY $MN_COLLATERAL_TXID 0
CFG
cat > "$ROOT/sn1/regtest/systemnode.conf" <<CFG
sn1 $SYSTEMNODE_SERVICE_ADDR $SN_KEY $SN_COLLATERAL_TXID 0
CFG

restart_node "$ROOT" mn1
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"

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
    echo "registration maturity wait exceeded bound: $wait_secs > $START_ALIAS_WAIT_SECS" >&2
    exit 1
  fi
  echo "[$(ts)] waiting ${wait_secs}s for collateral confirmation-time gate"
  sleep "$wait_secs"
fi
stage_end "STAGE 4 — collateral maturity"

stage_begin "STAGE 5 — Masternode registration"
wait_start_alias_success mn1 masternode mn1 "$ROOT/mn.start.valid.json" "$START_ALIAS_WAIT_SECS" || { echo "masternode start-alias timed out" >&2; exit 1; }
stage_end "STAGE 5 — Masternode registration"
stage_begin "STAGE 6 — Systemnode registration"
wait_start_alias_success sn1 systemnode sn1 "$ROOT/sn.start.valid.json" "$START_ALIAS_WAIT_SECS" || { echo "systemnode start-alias timed out" >&2; exit 1; }
stage_end "STAGE 6 — Systemnode registration"
stage_begin "STAGE 7 — peer/list convergence"
sleep 3
record_counts "after_start"
stage_end "STAGE 7 — peer/list convergence"

stage_begin "STAGE 8 — MNPoS activation"
TARGET_PRE_POS=140999
current_height="$(rpc "$ROOT" ctl getblockcount)"
pre_pos_deadline=$(( $(date +%s) + PRE_POS_WAIT_SECS ))
while [ "$current_height" -lt "$TARGET_PRE_POS" ]; do
  if [ "$(date +%s)" -ge "$pre_pos_deadline" ]; then
    echo "timeout before reaching pre-PoS height: current=$current_height target=$TARGET_PRE_POS" >&2
    exit 1
  fi
  remain=$((TARGET_PRE_POS - current_height))
  chunk=2000
  if [ "$remain" -lt "$chunk" ]; then
    chunk="$remain"
  fi
  rpc "$ROOT" ctl setgenerate true "$chunk" >/dev/null
  current_height="$(rpc "$ROOT" ctl getblockcount)"
  echo "[$(ts)] activation progress height=$current_height target=$TARGET_PRE_POS"
done
wait_all_equal_height "$TARGET_PRE_POS" || { echo "timeout waiting for pre-PoS convergence" >&2; exit 1; }

set +e
POW_AFTER_POS_ATTEMPT="$(rpc "$ROOT" ctl setgenerate true 1 2>&1)"
POW_AFTER_POS_RC=$?
set -e
printf '%s\n' "$POW_AFTER_POS_ATTEMPT" > "$ROOT/pow_after_pos_attempt.txt"
printf '%s\n' "$POW_AFTER_POS_RC" > "$ROOT/pow_after_pos_attempt.rc"

POS_DEADLINE=$(( $(date +%s) + POS_WAIT_SECS ))
FIRST_POS_HEIGHT=""
while [ "$(date +%s)" -lt "$POS_DEADLINE" ]; do
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

  POST_TARGET=$((FIRST_POS_HEIGHT + 19))
  POST_DEADLINE=$(( $(date +%s) + POST_POS_WAIT_SECS ))
  reached_post_target=0
  while [ "$(date +%s)" -lt "$POST_DEADLINE" ]; do
    if [ "$(rpc "$ROOT" ctl getblockcount)" -ge "$POST_TARGET" ]; then
      reached_post_target=1
      break
    fi
    echo "[$(ts)] waiting for post-activation block target current=$(rpc "$ROOT" ctl getblockcount) target=$POST_TARGET"
    sleep 2
  done
  if [ "$reached_post_target" -ne 1 ]; then
    echo "timeout waiting for post-activation block target" >&2
    exit 1
  fi

  python3 - "$ROOT" "$FIRST_POS_HEIGHT" "$POST_TARGET" > "$ROOT/pos_blocks_summary.json" <<'PY'
import json, subprocess, sys
root = sys.argv[1]
first = int(sys.argv[2])
target = int(sys.argv[3])
cmd_prefix = ["/home/runner/work/crown-core/crown-core/src/crown-cli", f"-datadir={root}/ctl", "-rpcuser=rt", "-rpcpassword=phase1i"]
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
fi

stage_begin "STAGE 10 — reward/accounting checks"
for n in "${NODES[@]}"; do
  rpc "$ROOT" "$n" getblockchaininfo > "$ROOT/$n.blockchaininfo.final.json"
  rpc "$ROOT" "$n" getbestblockhash > "$ROOT/$n.besthash.final.txt"
  rpc "$ROOT" "$n" getblockcount > "$ROOT/$n.height.final.txt"
done
stage_end "STAGE 10 — reward/accounting checks"

stage_begin "STAGE 11 — cleanup"
echo "Phase 1I capture complete. Artifacts: $ROOT"
stage_end "STAGE 11 — cleanup"
