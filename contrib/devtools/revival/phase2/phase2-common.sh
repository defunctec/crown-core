#!/usr/bin/env bash
set -euo pipefail

PHASE2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PHASE2_DIR/../../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/src}"
CROWND_BIN="${CROWND_BIN:-$BIN_DIR/crownd}"
CROWNCLI_BIN="${CROWNCLI_BIN:-$BIN_DIR/crown-cli}"

log() {
  printf '[phase2] %s\n' "$*" >&2
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

abs_path() {
  python3 - "$1" <<'PY'
import os,sys
print(os.path.abspath(sys.argv[1]))
PY
}

is_archive_path() {
  local p="$1"
  local lower="${p,,}"
  [[ "$lower" =~ \.(7z|zip|tar|tar\.gz|tgz)$ ]]
}

ensure_disposable_chaincopy_dir() {
  local d="$1"
  [ -d "$d" ] || die "Datadir does not exist: $d"
  [ -d "$d/blocks" ] || die "Datadir missing blocks/: $d/blocks"
  [ -d "$d/chainstate" ] || die "Datadir missing chainstate/: $d/chainstate"
}

start_crownd() {
  local datadir="$1"
  shift
  "$CROWND_BIN" -datadir="$datadir" -server=1 -daemon=1 "$@" >/dev/null
}

wait_rpc_ready() {
  local datadir="$1"
  local max_wait="${2:-180}"
  local waited=0
  while [ "$waited" -lt "$max_wait" ]; do
    if "$CROWNCLI_BIN" -datadir="$datadir" getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

stop_crownd() {
  local datadir="$1"
  "$CROWNCLI_BIN" -datadir="$datadir" stop >/dev/null 2>&1 || true
}

rpc() {
  local datadir="$1"
  shift
  "$CROWNCLI_BIN" -datadir="$datadir" "$@"
}

assert_rpc_not_ready() {
  local datadir="$1"
  if "$CROWNCLI_BIN" -datadir="$datadir" getblockcount >/dev/null 2>&1; then
    die "A crownd instance appears to be running already for datadir: $datadir"
  fi
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
