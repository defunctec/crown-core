#!/usr/bin/env bash
set -euo pipefail

PHASE2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PHASE2_DIR/../../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
CROWND_BIN="${CROWND_BIN:-$BIN_DIR/crownd}"
CROWNCLI_BIN="${CROWNCLI_BIN:-$BIN_DIR/crown-cli}"
PHASE2_RPC_PORT_BASE="${PHASE2_RPC_PORT_BASE:-29000}"
PHASE2_RPC_PORT_SPAN="${PHASE2_RPC_PORT_SPAN:-1000}"

log() {
  printf '[phase2] %s\n' "$*" >&2
}

phase2_discover_rpc_port_for_datadir() {
  local datadir="$1"
  local pid
  pid="$(phase2_find_crownd_pid_for_datadir "$datadir" || true)"
  [ -n "$pid" ] || { printf '\n'; return 0; }

  if [ -r "/proc/$pid/cmdline" ]; then
    python3 - "$pid" <<'PY'
import sys
pid=sys.argv[1]
try:
    with open(f"/proc/{pid}/cmdline","rb") as f:
        raw=f.read()
except Exception:
    print("")
    raise SystemExit(0)
parts=[p.decode("utf-8", errors="ignore") for p in raw.split(b"\x00") if p]
for i, arg in enumerate(parts):
    if arg.startswith('-rpcport='):
        v=arg.split('=',1)[1]
        print(v if v.isdigit() else "")
        raise SystemExit(0)
    if arg == '-rpcport' and i + 1 < len(parts):
        v=parts[i+1]
        print(v if v.isdigit() else "")
        raise SystemExit(0)
print("")
PY
    return 0
  fi

  if command -v ps >/dev/null 2>&1; then
    local args
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    python3 - "$args" <<'PY'
import shlex, sys
args_text=sys.argv[1]
try:
    parts=shlex.split(args_text)
except Exception:
    parts=args_text.split()
for i,arg in enumerate(parts):
    if arg.startswith('-rpcport='):
        v=arg.split('=',1)[1]
        print(v if v.isdigit() else "")
        raise SystemExit(0)
    if arg == '-rpcport' and i+1 < len(parts):
        v=parts[i+1]
        print(v if v.isdigit() else "")
        raise SystemExit(0)
print("")
PY
    return 0
  fi

  printf '\n'
}

die() {
  printf '[phase2][error] %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

require_bins() {
  [ -x "$CROWND_BIN" ] || die "crownd not found/executable at: $CROWND_BIN"
  [ -x "$CROWNCLI_BIN" ] || die "crown-cli not found/executable at: $CROWNCLI_BIN"
}

phase2_rpc_user_file() {
  local datadir="$1"
  printf '%s\n' "$datadir/phase2-rpc-user"
}

phase2_rpc_password_file() {
  local datadir="$1"
  printf '%s\n' "$datadir/phase2-rpc-password"
}

ensure_phase2_rpc_credentials() {
  local datadir="$1"
  local user_file pass_file
  user_file="$(phase2_rpc_user_file "$datadir")"
  pass_file="$(phase2_rpc_password_file "$datadir")"

  if [ ! -s "$user_file" ]; then
    python3 - <<'PY' > "$user_file"
import secrets
print(f"phase2rpc_{secrets.token_hex(4)}")
PY
  fi
  if [ ! -s "$pass_file" ]; then
    python3 - <<'PY' > "$pass_file"
import secrets
print(secrets.token_hex(16))
PY
  fi
  chmod 600 "$user_file" "$pass_file" >/dev/null 2>&1 || true
}

phase2_rpc_user() {
  local datadir="$1"
  ensure_phase2_rpc_credentials "$datadir"
  tr -d '\r\n' < "$(phase2_rpc_user_file "$datadir")"
}

phase2_rpc_password() {
  local datadir="$1"
  ensure_phase2_rpc_credentials "$datadir"
  tr -d '\r\n' < "$(phase2_rpc_password_file "$datadir")"
}

abs_path() {
  python3 - "$1" <<'PY'
import os,sys
print(os.path.abspath(sys.argv[1]))
PY
}

phase2_pid_matches_datadir() {
  local pid="$1"
  local datadir="$2"
  local canonical
  canonical="$(canonical_path "$datadir")"

  if [ -r "/proc/$pid/cmdline" ]; then
    python3 - "$pid" "$canonical" <<'PY'
import os, sys
pid=sys.argv[1]
target=os.path.realpath(sys.argv[2])
try:
    with open(f"/proc/{pid}/cmdline","rb") as f:
        raw=f.read()
except Exception:
    raise SystemExit(1)
parts=[p.decode("utf-8", errors="ignore") for p in raw.split(b"\x00") if p]
if not parts:
    raise SystemExit(1)
exe=os.path.basename(parts[0]).lower()
if "crownd" not in exe:
    raise SystemExit(1)
for i,arg in enumerate(parts):
    if arg.startswith('-datadir='):
        v=arg.split('=',1)[1]
    elif arg == '-datadir' and i + 1 < len(parts):
        v=parts[i+1]
    else:
        continue
    if os.path.realpath(v) == target:
        raise SystemExit(0)
raise SystemExit(1)
PY
    return $?
  fi

  if command -v ps >/dev/null 2>&1; then
    local comm args
    comm="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d '\r\n' || true)"
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    [[ "$comm" == *crownd* ]] || return 1
    phase2_args_match_datadir "$canonical" "$args"
    return $?
  fi

  return 1
}

canonical_path() {
  python3 - "$1" <<'PY'
import os,sys
print(os.path.realpath(sys.argv[1]))
PY
}

is_archive_path() {
  local p="$1"
  local lower="${p,,}"
  [[ "$lower" =~ \.(7z|zip|tar|tar\.gz|tgz)$ ]]
}

ensure_chain_data_dir() {
  local d="$1"
  [ -d "$d" ] || die "Datadir does not exist: $d"
  [ -d "$d/blocks" ] || die "Datadir missing blocks/: $d/blocks"
  [ -d "$d/chainstate" ] || die "Datadir missing chainstate/: $d/chainstate"
}

ensure_disposable_chaincopy_dir() {
  local d="$1"
  ensure_chain_data_dir "$d"
}

assert_phase2_working_copy_marker() {
  local datadir="$1"
  local marker="$datadir/phase2-working-copy.json"
  [ -f "$marker" ] || die "Datadir is missing phase2 working-copy marker: $marker. Use phase2-prepare-working-copies.sh first."
}

assert_mainnet_config_only() {
  local datadir="$1"
  local conf="$datadir/crown.conf"
  [ -f "$conf" ] || return 0

  python3 - "$conf" <<'PY'
import re,sys
conf=sys.argv[1]
bad=[]
for raw in open(conf, encoding='utf-8', errors='ignore'):
    line=raw.strip()
    if not line or line.startswith('#'):
        continue
    line=line.split('#', 1)[0].strip()
    if not line:
        continue
    compact=re.sub(r'\s+', '', line.lower())
    if compact.startswith('[') and compact.endswith(']') and compact in ('[main]','[test]','[regtest]'):
        bad.append(raw.rstrip('\n'))
        continue
    if re.match(r'^(testnet|regtest|devnet|chain)\s*=', compact):
        bad.append(raw.rstrip('\n'))
if bad:
    print("Chain-selection configuration detected in crown.conf (not allowed for Phase 2 runtime datadirs):")
    for item in bad:
        print(item)
    raise SystemExit(1)
PY
}

start_crownd() {
  local datadir="$1"
  shift
  local rpc_port started=0 rpc_user rpc_password
  rpc_user="$(phase2_rpc_user "$datadir")"
  rpc_password="$(phase2_rpc_password "$datadir")"
  rm -f "$datadir/phase2-rpc-port"
  while IFS= read -r rpc_port; do
    [ -n "$rpc_port" ] || continue
    if "$CROWND_BIN" -datadir="$datadir" -server=1 -daemon=1 -pid="$datadir/crownd.phase2.pid" -rpcport="$rpc_port" -rpcuser="$rpc_user" -rpcpassword="$rpc_password" "$@" >/dev/null 2>&1; then
      local pid launched waited
      pid=""
      launched=0
      waited=0
      while [ "$waited" -lt 10 ]; do
        if [ -z "$pid" ] && [ -f "$datadir/crownd.phase2.pid" ]; then
          pid="$(tr -cd '0-9' < "$datadir/crownd.phase2.pid" || true)"
        fi
        if [ -n "$pid" ] && ! kill -0 "$pid" >/dev/null 2>&1; then
          break
        fi
        if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
          launched=1
          break
        fi
        sleep 1
        waited=$((waited + 1))
      done
      if [ "$launched" -eq 1 ]; then
        printf '%s\n' "$rpc_port" > "$datadir/phase2-rpc-port"
        started=1
        break
      fi
      "$CROWNCLI_BIN" -datadir="$datadir" -rpcconnect=127.0.0.1 -rpcport="$rpc_port" -rpcuser="$rpc_user" -rpcpassword="$rpc_password" stop >/dev/null 2>&1 || true
      if [ -n "$pid" ]; then
        kill "$pid" >/dev/null 2>&1 || true
        local shutdown_wait=0
        while [ "$shutdown_wait" -lt 10 ] && kill -0 "$pid" >/dev/null 2>&1; do
          sleep 1
          shutdown_wait=$((shutdown_wait + 1))
        done
        if kill -0 "$pid" >/dev/null 2>&1; then
          die "crownd start probe left a running process after failed readiness check (pid=$pid, datadir=$datadir)"
        fi
      fi
      rm -f "$datadir/crownd.phase2.pid"
    fi
  done < <(phase2_rpc_port_candidates "$datadir")

  [ "$started" -eq 1 ] || die "Failed to start crownd for datadir $datadir (no usable RPC port found, or daemon exited during launch probe)"
}

wait_rpc_ready() {
  local datadir="$1"
  local max_wait="${2:-180}"
  local waited=0 rpc_user rpc_password pid seen_process launch_grace
  rpc_user="$(phase2_rpc_user "$datadir")"
  rpc_password="$(phase2_rpc_password "$datadir")"
  pid=""
  seen_process=0
  launch_grace=15
  if [ -f "$datadir/crownd.phase2.pid" ]; then
    pid="$(tr -cd '0-9' < "$datadir/crownd.phase2.pid" || true)"
    [ -n "$pid" ] && seen_process=1
  fi
  while [ "$waited" -lt "$max_wait" ]; do
    if "$CROWNCLI_BIN" -datadir="$datadir" -rpcconnect=127.0.0.1 -rpcport="$(phase2_rpc_port "$datadir")" -rpcuser="$rpc_user" -rpcpassword="$rpc_password" getblockcount >/dev/null 2>&1; then
      return 0
    fi
    if [ -z "$pid" ]; then
      if [ -f "$datadir/crownd.phase2.pid" ]; then
        pid="$(tr -cd '0-9' < "$datadir/crownd.phase2.pid" || true)"
      fi
      if [ -z "$pid" ]; then
        local probe_pid
        probe_pid="$(phase2_find_crownd_pid_for_datadir "$datadir" || true)"
        if [ -n "$probe_pid" ]; then
          pid="$probe_pid"
        fi
      fi
      if [ -n "$pid" ]; then
        seen_process=1
      elif [ "$seen_process" -eq 1 ] || [ "$waited" -ge "$launch_grace" ]; then
        log "crownd process for datadir not found before RPC became ready (waited=${waited}s, datadir=$datadir)"
        return 1
      fi
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" >/dev/null 2>&1; then
      local rediscovered_pid
      rediscovered_pid="$(phase2_find_crownd_pid_for_datadir "$datadir" || true)"
      if [ -n "$rediscovered_pid" ] && [ "$rediscovered_pid" != "$pid" ]; then
        pid="$rediscovered_pid"
        printf '%s\n' "$pid" > "$datadir/crownd.phase2.pid"
      else
        log "crownd exited before RPC became ready (pid=$pid, waited=${waited}s, datadir=$datadir)"
        return 1
      fi
    fi
    local remaining sleep_step
    remaining=$((max_wait - waited))
    sleep_step=2
    if [ "$remaining" -lt "$sleep_step" ]; then
      sleep_step="$remaining"
    fi
    sleep "$sleep_step"
    waited=$((waited + sleep_step))
  done
  log "RPC readiness timed out after ${max_wait}s while crownd remained running (datadir=$datadir)"
  return 1
}

stop_crownd() {
  local datadir="$1"
  local port pid waited rpc_user rpc_password port_known=0
  if [ -f "$datadir/phase2-rpc-port" ]; then
    port="$(tr -cd '0-9' < "$datadir/phase2-rpc-port" || true)"
    if [ -n "$port" ]; then
      port_known=1
    fi
  fi
  if [ "$port_known" -eq 0 ]; then
    port="$(phase2_discover_rpc_port_for_datadir "$datadir" || true)"
    if [ -n "$port" ]; then
      port_known=1
    fi
  fi
  if [ "$port_known" -eq 0 ]; then
    port="$(phase2_default_rpc_port "$datadir")"
  fi
  rpc_user="$(phase2_rpc_user "$datadir")"
  rpc_password="$(phase2_rpc_password "$datadir")"
  pid=""
  if [ -f "$datadir/crownd.phase2.pid" ]; then
    pid="$(tr -cd '0-9' < "$datadir/crownd.phase2.pid" || true)"
  fi

  if [ "$port_known" -eq 1 ]; then
    "$CROWNCLI_BIN" -datadir="$datadir" -rpcconnect=127.0.0.1 -rpcport="$port" -rpcuser="$rpc_user" -rpcpassword="$rpc_password" stop >/dev/null 2>&1 || true
  fi

  waited=0
  while [ "$waited" -lt 120 ]; do
    if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
      local probe_pid
      probe_pid="$(phase2_find_crownd_pid_for_datadir "$datadir" || true)"
      if [ -n "$probe_pid" ]; then
        pid="$probe_pid"
      fi
    fi
    local pid_alive=0 rpc_alive=0
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      pid_alive=1
    fi
    if [ "$port_known" -eq 1 ]; then
      if "$CROWNCLI_BIN" -datadir="$datadir" -rpcconnect=127.0.0.1 -rpcport="$port" -rpcuser="$rpc_user" -rpcpassword="$rpc_password" getblockcount >/dev/null 2>&1; then
        rpc_alive=1
      fi
    fi
    if [ "$pid_alive" -eq 0 ] && [ "$rpc_alive" -eq 0 ]; then
      local replacement_pid
      replacement_pid="$(phase2_find_crownd_pid_for_datadir "$datadir" || true)"
      if [ -n "$replacement_pid" ] && [ "$replacement_pid" != "$pid" ]; then
        pid="$replacement_pid"
        continue
      fi
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
    local final_probe_pid
    final_probe_pid="$(phase2_find_crownd_pid_for_datadir "$datadir" || true)"
    if [ -n "$final_probe_pid" ]; then
      pid="$final_probe_pid"
    fi
  fi
  local pid_alive_final=0 rpc_alive_final=0
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    pid_alive_final=1
  fi
  if [ "$port_known" -eq 1 ]; then
    if "$CROWNCLI_BIN" -datadir="$datadir" -rpcconnect=127.0.0.1 -rpcport="$port" -rpcuser="$rpc_user" -rpcpassword="$rpc_password" getblockcount >/dev/null 2>&1; then
      rpc_alive_final=1
    fi
  fi
  if [ "$pid_alive_final" -eq 1 ] || [ "$rpc_alive_final" -eq 1 ]; then
    die "Failed to stop crownd cleanly for datadir: $datadir"
  fi

  rm -f "$datadir/crownd.phase2.pid" "$datadir/phase2-rpc-port"
}

rpc() {
  local datadir="$1"
  shift
  "$CROWNCLI_BIN" -datadir="$datadir" -rpcconnect=127.0.0.1 -rpcport="$(phase2_rpc_port "$datadir")" -rpcuser="$(phase2_rpc_user "$datadir")" -rpcpassword="$(phase2_rpc_password "$datadir")" "$@"
}

assert_rpc_not_ready() {
  local datadir="$1"
  assert_no_crownd_for_datadir "$datadir"
}

assert_no_crownd_for_datadir() {
  local datadir="$1"
  local canonical
  canonical="$(canonical_path "$datadir")"

  if [ -f "$datadir/crownd.phase2.pid" ]; then
    local pid
    pid="$(tr -cd '0-9' < "$datadir/crownd.phase2.pid" || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      if phase2_pid_matches_datadir "$pid" "$datadir"; then
        die "A crownd process is still running for datadir (pid file): $datadir/crownd.phase2.pid"
      else
        rm -f "$datadir/crownd.phase2.pid"
      fi
    fi
  fi

  if [ ! -d /proc ]; then
    if command -v pgrep >/dev/null 2>&1; then
      while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        local comm args
        comm="$(ps -p "$candidate" -o comm= 2>/dev/null | tr -d '\r\n' || true)"
        args="$(ps -p "$candidate" -o args= 2>/dev/null || true)"
        [[ "$comm" == *crownd* ]] || continue
        if phase2_args_match_datadir "$canonical" "$args"; then
          die "A crownd process with matching -datadir is already running: $datadir"
        fi
      done < <(pgrep -f -- "crownd.*-datadir" || true)
    else
      die "Cannot verify active crownd process for datadir safety: neither /proc nor pgrep is available"
    fi
    return 0
  fi

  local proc_check_status=0
  python3 - "$canonical" <<'PY' || proc_check_status=$?
import glob, os, sys
target = os.path.realpath(sys.argv[1])
for cmdline_path in glob.glob('/proc/[0-9]*/cmdline'):
    try:
        with open(cmdline_path, 'rb') as f:
            raw = f.read()
    except Exception:
        continue
    if not raw:
        continue
    parts = [p.decode('utf-8', errors='ignore') for p in raw.split(b'\x00') if p]
    if not parts:
        continue
    exe = os.path.basename(parts[0]).lower()
    if 'crownd' not in exe:
        continue
    for i, arg in enumerate(parts):
        if arg.startswith('-datadir='):
            value = arg.split('=', 1)[1]
        elif arg == '-datadir' and i + 1 < len(parts):
            value = parts[i + 1]
        else:
            continue
        if os.path.realpath(value) == target:
            raise SystemExit(1)
PY
  case "$proc_check_status" in
    0) ;;
    1) die "A crownd process with matching -datadir is already running: $datadir" ;;
    *) die "Failed to inspect running processes for datadir lock safety: $datadir" ;;
  esac
}

phase2_find_crownd_pid_for_datadir() {
  local datadir="$1"
  local canonical
  canonical="$(canonical_path "$datadir")"

  if [ -d /proc ]; then
    python3 - "$canonical" <<'PY'
import glob, os, sys
target = os.path.realpath(sys.argv[1])
for cmdline_path in glob.glob('/proc/[0-9]*/cmdline'):
    try:
        with open(cmdline_path, 'rb') as f:
            raw = f.read()
    except Exception:
        continue
    if not raw:
        continue
    parts = [p.decode('utf-8', errors='ignore') for p in raw.split(b'\x00') if p]
    if not parts:
        continue
    exe = os.path.basename(parts[0]).lower()
    if 'crownd' not in exe:
        continue
    for i, arg in enumerate(parts):
        if arg.startswith('-datadir='):
            value = arg.split('=', 1)[1]
        elif arg == '-datadir' and i + 1 < len(parts):
            value = parts[i + 1]
        else:
            continue
        if os.path.realpath(value) == target:
            print(os.path.basename(os.path.dirname(cmdline_path)))
            raise SystemExit(0)
print("")
PY
    return 0
  fi

  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r candidate; do
      [ -n "$candidate" ] || continue
      local comm args
      comm="$(ps -p "$candidate" -o comm= 2>/dev/null | tr -d '\r\n' || true)"
      args="$(ps -p "$candidate" -o args= 2>/dev/null || true)"
      [[ "$comm" == *crownd* ]] || continue
      if phase2_args_match_datadir "$canonical" "$args"; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done < <(pgrep -f -- "crownd.*-datadir" || true)
    printf '\n'
    return 0
  fi

  printf '\n'
}

phase2_args_match_datadir() {
  local canonical="$1"
  local args="$2"
  python3 - "$canonical" "$args" <<'PY'
import os, shlex, sys
target = os.path.realpath(sys.argv[1])
args_text = sys.argv[2]
try:
    parts = shlex.split(args_text)
except Exception:
    parts = args_text.split()
for i, arg in enumerate(parts):
    if arg.startswith('-datadir='):
        value = arg.split('=', 1)[1]
    elif arg == '-datadir' and i + 1 < len(parts):
        value = parts[i + 1]
    else:
        continue
    if os.path.realpath(value) == target:
        raise SystemExit(0)
raise SystemExit(1)
PY
}

phase2_rpc_port() {
  local datadir="$1"
  if [ -f "$datadir/phase2-rpc-port" ]; then
    local file_port
    file_port="$(tr -cd '0-9' < "$datadir/phase2-rpc-port" || true)"
    if [ -n "$file_port" ]; then
      printf '%s\n' "$file_port"
      return 0
    fi
  fi
  local discovered_port
  discovered_port="$(phase2_discover_rpc_port_for_datadir "$datadir" || true)"
  if [ -n "$discovered_port" ]; then
    printf '%s\n' "$discovered_port"
    return 0
  fi
  phase2_default_rpc_port "$datadir"
}

phase2_default_rpc_port() {
  local datadir="$1"
  python3 - "$datadir" "$PHASE2_RPC_PORT_BASE" "$PHASE2_RPC_PORT_SPAN" <<'PY'
import hashlib, os, sys
path = os.path.realpath(sys.argv[1]).encode("utf-8")
base = int(sys.argv[2])
span = int(sys.argv[3])
if span < 1:
    raise SystemExit("PHASE2_RPC_PORT_SPAN must be >= 1")
if base < 1024 or base > 65535:
    raise SystemExit("PHASE2_RPC_PORT_BASE must be between 1024 and 65535")
max_span = 65535 - base + 1
effective_span = min(span, max_span)
h = int(hashlib.sha256(path).hexdigest()[:8], 16)
print(base + (h % effective_span))
PY
}

phase2_rpc_port_candidates() {
  local datadir="$1"
  python3 - "$datadir" "$PHASE2_RPC_PORT_BASE" "$PHASE2_RPC_PORT_SPAN" <<'PY'
import hashlib, os, sys
path = os.path.realpath(sys.argv[1]).encode("utf-8")
base = int(sys.argv[2])
span = int(sys.argv[3])
if span < 1:
    raise SystemExit("PHASE2_RPC_PORT_SPAN must be >= 1")
if base < 1024 or base > 65535:
    raise SystemExit("PHASE2_RPC_PORT_BASE must be between 1024 and 65535")
max_span = 65535 - base + 1
effective_span = min(span, max_span)
h = int(hashlib.sha256(path).hexdigest()[:8], 16)
start = base + (h % effective_span)
for i in range(effective_span):
    port = base + ((start - base + i) % effective_span)
    print(port)
PY
}

expected_mainnet_params_json() {
  local ref="$PHASE2_DIR/mainnet-identity-reference.json"
  [ -f "$ref" ] || die "Missing mainnet identity reference file: $ref"
  cat "$ref"
}

scan_block_files_json() {
  local datadir="$1"
  python3 - "$datadir/blocks" <<'PY'
import glob,json,os,re,sys
blocks_dir=sys.argv[1]
blk=[]
rev=[]
for path in sorted(glob.glob(os.path.join(blocks_dir, 'blk*.dat'))):
    m=re.search(r'blk([0-9]+)\.dat$', os.path.basename(path))
    if not m:
        continue
    blk.append({"file": os.path.basename(path), "index": int(m.group(1)), "size_bytes": os.path.getsize(path)})
for path in sorted(glob.glob(os.path.join(blocks_dir, 'rev*.dat'))):
    m=re.search(r'rev([0-9]+)\.dat$', os.path.basename(path))
    if not m:
        continue
    rev.append({"file": os.path.basename(path), "index": int(m.group(1)), "size_bytes": os.path.getsize(path)})

indices=[x['index'] for x in blk]
contiguous=False
gaps=[]
if indices:
    contiguous=(indices[0]==0)
    prev=indices[0]
    for idx in indices[1:]:
        if idx != prev + 1:
            contiguous=False
            gaps.append({"after": prev, "before": idx})
        prev=idx

pruned_status='UNKNOWN'
rationale=[]
if not blk:
    pruned_status='UNKNOWN'
    rationale.append('No blk*.dat files found; block history is missing or unreadable in this working copy.')
elif indices[0] > 0:
    pruned_status='YES'
    rationale.append('First blk file index is greater than zero, indicating earlier files are absent.')
elif gaps:
    pruned_status='YES'
    rationale.append('Gap(s) detected in blk file numbering, indicating missing historical block files.')
else:
    pruned_status='NO'
    rationale.append('blk files are contiguous starting at blk00000.dat; historical files appear complete on disk.')

print(json.dumps({
    "blocks_dir": blocks_dir,
    "blk_file_count": len(blk),
    "rev_file_count": len(rev),
    "blk_files": blk,
    "rev_files": rev,
    "contiguous_from_zero": contiguous,
    "index_gaps": gaps,
    "history_appears_pruned": pruned_status,
    "missing_block_data": len(blk) == 0,
    "pruned_rationale": rationale,
}, indent=2))
PY
}

read_blk_magic_hex() {
  local datadir="$1"
  python3 - "$datadir/blocks" <<'PY'
import glob, os, sys
blocks_dir=sys.argv[1]
blk0=os.path.join(blocks_dir,'blk00000.dat')
if not os.path.exists(blk0):
    files=glob.glob(os.path.join(blocks_dir,'blk*.dat'))
    def index_of(path):
        name=os.path.basename(path)
        if not (name.startswith('blk') and name.endswith('.dat')):
            return 10**18
        middle=name[3:-4]
        return int(middle) if middle.isdigit() else 10**18
    files=sorted(files, key=index_of)
    if not files:
        print('')
        raise SystemExit(0)
    blk0=files[0]
with open(blk0,'rb') as f:
    data=f.read(4)
if len(data) != 4:
    print('')
else:
    print(data.hex())
PY
}
