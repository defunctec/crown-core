#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-/tmp/crown-phase1d}"
BIN_DIR="${BIN_DIR:-$(cd "$(dirname "$0")/../../.." && pwd)/src}"
RPC_USER="${RPC_USER:-rt}"
RPC_PASS="${RPC_PASS:-phase1d}"
NODES=(ctl mn1 sn1 obs)

mkdir -p "$ROOT"
umask 077

find_pids_for_datadir() {
  local datadir="$1"
  local found
  while read -r pid args; do
    found=0
    for token in $args; do
      if [ "$token" = "-datadir=$datadir" ]; then
        found=1
        break
      fi
    done
    if [ "$found" -eq 1 ] && [[ "$args" == *"crownd"* ]]; then
      echo "$pid"
    fi
  done < <(ps -eo pid=,args=)
}

write_conf() {
  local n="$1" rpcport port bind
  case "$n" in
    ctl) rpcport=18401; port=24001; bind=127.0.0.1 ;;
    mn1) rpcport=18402; port=24002; bind=127.0.0.1 ;;
    sn1) rpcport=18403; port=24003; bind=127.0.0.1 ;;
    obs) rpcport=18404; port=24004; bind=127.0.0.1 ;;
  esac
  mkdir -p "$ROOT/$n"
  cat > "$ROOT/$n/crown.conf" <<CFG
regtest=1
server=1
daemon=1
listen=1
rpcuser=$RPC_USER
rpcpassword=$RPC_PASS
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
rpcport=$rpcport
port=$port
bind=$bind
discover=0
dns=0
dnsseed=0
upnp=0
onlynet=ipv4
logtimestamps=1
printtoconsole=0
fallbackfee=0.001
txindex=1
CFG
  chmod 600 "$ROOT/$n/crown.conf"
}

for n in "${NODES[@]}"; do
  write_conf "$n"
  "$BIN_DIR/crownd" -datadir="$ROOT/$n" >/dev/null
  datadir="$ROOT/$n"
  rpc_unreachable=1
  ready=0
  for _ in $(seq 1 60); do
    if "$BIN_DIR/crown-cli" -datadir="$ROOT/$n" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" getblockcount >/dev/null 2>&1; then
      ready=1
      rpc_unreachable=0
      pid="$(find_pids_for_datadir "$datadir" | head -n1 || true)"
      if [ -n "$pid" ]; then
        echo "$pid" > "$ROOT/$n/crownd.pid"
      fi
      break
    fi
    if ! find_pids_for_datadir "$datadir" >/dev/null 2>&1; then
      echo "Node '$n' exited before RPC became ready (datadir=$datadir)" >&2
      exit 1
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    if [ "$rpc_unreachable" -eq 1 ]; then
      echo "Failed to start node '$n' (RPC not ready after 60s, datadir=$datadir)" >&2
    fi
    exit 1
  fi
done

"$BIN_DIR/crown-cli" -datadir="$ROOT/ctl" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24002 add >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/ctl" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24003 add >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/ctl" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24004 add >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/mn1" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24001 add >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/sn1" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24001 add >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/obs" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24001 add >/dev/null || true

"$BIN_DIR/crown-cli" -datadir="$ROOT/ctl" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24002 onetry >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/ctl" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24003 onetry >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/ctl" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24004 onetry >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/mn1" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24001 onetry >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/sn1" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24001 onetry >/dev/null || true
"$BIN_DIR/crown-cli" -datadir="$ROOT/obs" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" addnode 127.0.0.1:24001 onetry >/dev/null || true

echo "Started nodes in $ROOT"
