#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
ROOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --srcdir)
      SRC_DIR="$2"
      shift 2
      ;;
    --tmpdir)
      ROOT="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$ROOT" ]; then
  ROOT="$(mktemp -d /tmp/crown-phase1g-test.XXXXXX)"
fi

export BIN_DIR="$SRC_DIR"
source "$REPO_ROOT/contrib/devtools/revival/mnpos-repro-common.sh"
trap 'cleanup_root "$ROOT"' EXIT

json_field() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get(sys.argv[1], ""))' "$1"
}

assert_counts() {
  local expected="$1"
  for node in "${NODES[@]}"; do
    local count
    count="$(rpc "$ROOT" "$node" systemnode count)"
    if [ "$count" != "$expected" ]; then
      echo "unexpected systemnode count on $node: got $count expected $expected" >&2
      render_counts "$ROOT" >&2
      exit 1
    fi
  done
}

start_network "$ROOT"

rpc "$ROOT" sn1 getnewaddress > "$ROOT/sn1.tcrw"
rpc "$ROOT" ctl getnewaddress > "$ROOT/ctl.tcrw"
SN_KEYHASH="$(decode_keyhash "$(cat "$ROOT/sn1.tcrw")")"
CTL_KEYHASH="$(decode_keyhash "$(cat "$ROOT/ctl.tcrw")")"

rpc "$ROOT" ctl setgenerate true 700 >/dev/null
wait_height "$ROOT" 700

COLLATERAL_TXID="$(build_collateral_transaction "$ROOT" "$SN_KEYHASH" "$CTL_KEYHASH")"
write_systemnode_config "$ROOT" "$COLLATERAL_TXID"
restart_node "$ROOT" sn1
reconnect_topology "$ROOT"

rpc "$ROOT" ctl setgenerate true 14 >/dev/null
wait_height "$ROOT" 714

RESULT_14="$(rpc "$ROOT" sn1 systemnode start-alias sn1)"
if [ "$(printf '%s\n' "$RESULT_14" | json_field result)" != "failed" ]; then
  echo "expected 14-confirmation start-alias failure" >&2
  printf '%s\n' "$RESULT_14" >&2
  exit 1
fi
if ! printf '%s\n' "$RESULT_14" | grep -q "Input must have at least 15 confirmations"; then
  echo "expected 14-confirmation error message" >&2
  printf '%s\n' "$RESULT_14" >&2
  exit 1
fi
assert_counts 0

rpc "$ROOT" ctl setgenerate true 6 >/dev/null
wait_height "$ROOT" 720

CONF15_TIME="$(find_conf15_time "$ROOT" "$COLLATERAL_TXID")"
NOW="$(date -u +%s)"
if [ "$NOW" -ge "$CONF15_TIME" ]; then
  echo "expected wall clock to remain behind the 15-confirmation block time for the immediate-start repro" >&2
  echo "wallclock=$NOW conf15_time=$CONF15_TIME" >&2
  exit 1
fi

RESULT_EARLY="$(rpc "$ROOT" sn1 systemnode start-alias sn1)"
if [ "$(printf '%s\n' "$RESULT_EARLY" | json_field result)" != "failed" ]; then
  echo "expected immediate post-maturity start-alias failure" >&2
  printf '%s\n' "$RESULT_EARLY" >&2
  exit 1
fi
if ! printf '%s\n' "$RESULT_EARLY" | grep -q "Systemnode broadcast rejected by local validation"; then
  echo "expected local validation rejection message" >&2
  printf '%s\n' "$RESULT_EARLY" >&2
  exit 1
fi
assert_counts 0
if ! grep -q "Bad sigTime .*15 conf block is at" "$ROOT/sn1/regtest/debug.log"; then
  echo "expected local sigTime rejection log entry" >&2
  exit 1
fi

SLEEP_FOR=$((CONF15_TIME - NOW + 1))
if [ "$SLEEP_FOR" -gt 0 ]; then
  sleep "$SLEEP_FOR"
fi

RESULT_VALID="$(rpc "$ROOT" sn1 systemnode start-alias sn1)"
if [ "$(printf '%s\n' "$RESULT_VALID" | json_field result)" != "successful" ]; then
  echo "expected eventual valid registration success" >&2
  printf '%s\n' "$RESULT_VALID" >&2
  exit 1
fi
sleep 3
assert_counts 1

SN_STATUS="$(rpc "$ROOT" sn1 systemnode list status | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sorted(data.items()))')"
CTL_STATUS="$(rpc "$ROOT" ctl systemnode list status | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sorted(data.items()))')"
MN1_STATUS="$(rpc "$ROOT" mn1 systemnode list status | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sorted(data.items()))')"
OBS_STATUS="$(rpc "$ROOT" obs systemnode list status | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sorted(data.items()))')"

if [ "$SN_STATUS" != "$CTL_STATUS" ] || [ "$SN_STATUS" != "$MN1_STATUS" ] || [ "$SN_STATUS" != "$OBS_STATUS" ]; then
  echo "systemnode list status diverged after valid registration" >&2
  printf 'sn1=%s\nctl=%s\nmn1=%s\nobs=%s\n' "$SN_STATUS" "$CTL_STATUS" "$MN1_STATUS" "$OBS_STATUS" >&2
  exit 1
fi

echo "systemnode registration divergence test passed"
