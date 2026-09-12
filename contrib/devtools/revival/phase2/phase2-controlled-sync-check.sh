#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/devtools/revival/phase2/phase2-common.sh
source "$SCRIPT_DIR/phase2-common.sh"

usage() {
  cat <<USAGE
Usage:
  $0 --datadir <disposable_sync_copy_dir> [--outdir <output_dir>] [--poll-seconds <n>] [--min-runtime-seconds <n>] [--max-runtime-seconds <n>] [--stagnation-polls <n>]

Notes:
  - Use a dedicated disposable SYNC working copy (not the OFFLINE working copy).
  - This mode allows normal mainnet networking to check continuation and newer-tip availability.
USAGE
}

DATADIR=""
OUTDIR=""
POLL_SECONDS="30"
MIN_RUNTIME_SECONDS="600"
MAX_RUNTIME_SECONDS="3600"
STAGNATION_POLLS="6"

while [ $# -gt 0 ]; do
  case "$1" in
    --datadir)
      DATADIR="${2:-}"; shift 2 ;;
    --outdir)
      OUTDIR="${2:-}"; shift 2 ;;
    --poll-seconds)
      POLL_SECONDS="${2:-}"; shift 2 ;;
    --min-runtime-seconds)
      MIN_RUNTIME_SECONDS="${2:-}"; shift 2 ;;
    --max-runtime-seconds)
      MAX_RUNTIME_SECONDS="${2:-}"; shift 2 ;;
    --stagnation-polls)
      STAGNATION_POLLS="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

[ -n "$DATADIR" ] || { usage; die "--datadir is required"; }
require_cmd python3
require_bins

DATADIR="$(abs_path "$DATADIR")"
if is_archive_path "$DATADIR"; then
  die "Refusing archive path. Provide an extracted disposable sync working copy directory instead."
fi
ensure_disposable_chaincopy_dir "$DATADIR"
assert_phase2_working_copy_marker "$DATADIR"
assert_mainnet_config_only "$DATADIR"
assert_rpc_not_ready "$DATADIR"

if [ -z "$OUTDIR" ]; then
  OUTDIR="$(dirname "$DATADIR")/$(basename "$DATADIR").phase2-sync-output"
fi
OUTDIR="$(abs_path "$OUTDIR")"
mkdir -p "$OUTDIR"

SYNC_RESULT_JSON="$OUTDIR/phase2-sync-result.json"
PEER_SUMMARY_JSON="$OUTDIR/phase2-peer-summary.json"

cleanup() {
  stop_crownd "$DATADIR"
}
trap cleanup EXIT

log "Starting controlled sync check on disposable sync copy: $DATADIR"
start_crownd "$DATADIR" -testnet=0 -regtest=0 -listen=0 -upnp=0 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcallowip=::1
wait_rpc_ready "$DATADIR" 300 || die "crownd RPC did not become ready for controlled sync check"

rpc "$DATADIR" getblockchaininfo > "$OUTDIR/start-blockchaininfo.json"
CHAIN_NAME="$(python3 - "$OUTDIR/start-blockchaininfo.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1])).get("chain",""))
PY
)"
[ "$CHAIN_NAME" = "main" ] || die "Expected mainnet chain, got: ${CHAIN_NAME:-UNKNOWN}"
START_HASH="$(rpc "$DATADIR" getbestblockhash)"
START_HEIGHT="$(rpc "$DATADIR" getblockcount)"
rpc "$DATADIR" getblock "$START_HASH" > "$OUTDIR/start-tip-block.json"
START_GENESIS="$(rpc "$DATADIR" getblockhash 0)"

python3 - "$OUTDIR" <<'PY'
import json,sys
json.dump({"polls": []}, open(f"{sys.argv[1]}/sync-polls.json","w"), indent=2)
PY

START_TS="$(date +%s)"
LAST_HASH="$START_HASH"
STAGNANT=0
SEEN_PEER=0

while true; do
  NOW_TS="$(date +%s)"
  ELAPSED=$((NOW_TS - START_TS))

  rpc "$DATADIR" getblockchaininfo > "$OUTDIR/blockchaininfo.current.json"
  rpc "$DATADIR" getpeerinfo > "$OUTDIR/peerinfo.current.json"
  PEER_COUNT_NOW="$(python3 - "$OUTDIR/peerinfo.current.json" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
print(len(data) if isinstance(data, list) else 0)
PY
)"
  if [ "$PEER_COUNT_NOW" -gt 0 ]; then
    SEEN_PEER=1
  fi
  CUR_HASH="$(rpc "$DATADIR" getbestblockhash)"
  CUR_HEIGHT="$(rpc "$DATADIR" getblockcount)"
  rpc "$DATADIR" getblock "$CUR_HASH" > "$OUTDIR/tip.current.json"

  python3 - "$OUTDIR" "$ELAPSED" "$CUR_HEIGHT" "$CUR_HASH" <<'PY'
import datetime, json, sys
outdir=sys.argv[1]
elapsed=int(sys.argv[2])
height=int(sys.argv[3])
besthash=sys.argv[4]

bci=json.load(open(f"{outdir}/blockchaininfo.current.json"))
peerinfo=json.load(open(f"{outdir}/peerinfo.current.json"))
tip=json.load(open(f"{outdir}/tip.current.json"))

snapshot={
  "captured_at_utc": datetime.datetime.utcnow().isoformat()+"Z",
  "elapsed_seconds": elapsed,
  "height": height,
  "headers": bci.get("headers"),
  "bestblockhash": besthash,
  "tip_time": tip.get("time"),
  "connection_count": len(peerinfo),
  "peer_heights": [
    {
      "addr": p.get("addr"),
      "subver": p.get("subver"),
      "startingheight": p.get("startingheight"),
      "synced_headers": p.get("synced_headers"),
      "synced_blocks": p.get("synced_blocks"),
      "inbound": p.get("inbound"),
    }
    for p in peerinfo
  ],
}

polls=json.load(open(f"{outdir}/sync-polls.json"))
polls["polls"].append(snapshot)
json.dump(polls, open(f"{outdir}/sync-polls.json","w"), indent=2)
PY

  if [ "$CUR_HASH" = "$LAST_HASH" ]; then
    STAGNANT=$((STAGNANT + 1))
  else
    STAGNANT=0
    LAST_HASH="$CUR_HASH"
  fi

  HEADERS_EQ_BLOCKS="$(python3 - "$OUTDIR/blockchaininfo.current.json" <<'PY'
import json,sys
i=json.load(open(sys.argv[1]))
h=i.get('headers')
b=i.get('blocks')
print('1' if isinstance(h,int) and isinstance(b,int) and h == b else '0')
PY
)"

  if [ "$ELAPSED" -ge "$MIN_RUNTIME_SECONDS" ] && [ "$STAGNANT" -ge "$STAGNATION_POLLS" ] && [ "$HEADERS_EQ_BLOCKS" = "1" ] && [ "$SEEN_PEER" -eq 1 ]; then
    break
  fi

  if [ "$ELAPSED" -ge "$MAX_RUNTIME_SECONDS" ]; then
    break
  fi

  sleep "$POLL_SECONDS"
done

rpc "$DATADIR" getblockchaininfo > "$OUTDIR/final-blockchaininfo.json"
FINAL_HASH="$(rpc "$DATADIR" getbestblockhash)"
FINAL_HEIGHT="$(rpc "$DATADIR" getblockcount)"
rpc "$DATADIR" getblock "$FINAL_HASH" > "$OUTDIR/final-tip-block.json"
rpc "$DATADIR" getpeerinfo > "$OUTDIR/final-peerinfo.json"
rpc "$DATADIR" getchaintips > "$OUTDIR/final-chaintips.json"

python3 - "$OUTDIR" "$SYNC_RESULT_JSON" "$PEER_SUMMARY_JSON" "$START_HEIGHT" "$START_HASH" "$FINAL_HEIGHT" "$FINAL_HASH" "$START_GENESIS" "$MIN_RUNTIME_SECONDS" "$MAX_RUNTIME_SECONDS" "$POLL_SECONDS" "$STAGNATION_POLLS" <<'PY'
import datetime, json, sys
(
  outdir, sync_result_path, peer_summary_path,
  start_height, start_hash, final_height, final_hash, start_genesis,
  min_runtime, max_runtime, poll_seconds, stagnation_polls,
) = sys.argv[1:13]

start_height=int(start_height)
final_height=int(final_height)

start_bci=json.load(open(f"{outdir}/start-blockchaininfo.json"))
final_bci=json.load(open(f"{outdir}/final-blockchaininfo.json"))
start_tip=json.load(open(f"{outdir}/start-tip-block.json"))
final_tip=json.load(open(f"{outdir}/final-tip-block.json"))
final_peers=json.load(open(f"{outdir}/final-peerinfo.json"))
chaintips=json.load(open(f"{outdir}/final-chaintips.json"))
polls=json.load(open(f"{outdir}/sync-polls.json")).get("polls", [])

height_to_hash={}
reorg_events=[]
for snap in polls:
    h=snap.get('height')
    hh=snap.get('bestblockhash')
    if isinstance(h, int) and isinstance(hh, str):
        prior=height_to_hash.get(h)
        if prior is None:
            height_to_hash[h]=hh
        elif prior != hh:
            reorg_events.append({
                'height': h,
                'previous_hash': prior,
                'new_hash': hh,
                'captured_at_utc': snap.get('captured_at_utc'),
            })

peer_rows=[]
peer_addrs=set()
peer_startingheights=[]
peer_synced_headers=[]
peer_synced_blocks=[]
for snap in polls:
    for p in snap.get('peer_heights', []):
      addr=p.get('addr')
      if addr:
          peer_addrs.add(addr)
      if isinstance(p.get('startingheight'), int):
          peer_startingheights.append(p['startingheight'])
      if isinstance(p.get('synced_headers'), int):
          peer_synced_headers.append(p['synced_headers'])
      if isinstance(p.get('synced_blocks'), int):
          peer_synced_blocks.append(p['synced_blocks'])

for p in final_peers:
    peer_rows.append({
        'addr': p.get('addr'),
        'subver': p.get('subver'),
        'startingheight': p.get('startingheight'),
        'synced_headers': p.get('synced_headers'),
        'synced_blocks': p.get('synced_blocks'),
        'inbound': p.get('inbound'),
        'version': p.get('version'),
    })

max_peer_height=max(peer_startingheights) if peer_startingheights else None
max_peer_synced_headers=max(peer_synced_headers) if peer_synced_headers else None
max_peer_synced_blocks=max(peer_synced_blocks) if peer_synced_blocks else None

first_poll = polls[0] if polls else {}
initial_peer_synced_headers = []
initial_peer_synced_blocks = []
for p in first_poll.get('peer_heights', []):
    if isinstance(p.get('synced_headers'), int):
        initial_peer_synced_headers.append(p['synced_headers'])
    if isinstance(p.get('synced_blocks'), int):
        initial_peer_synced_blocks.append(p['synced_blocks'])
initial_max_peer_synced_headers = max(initial_peer_synced_headers) if initial_peer_synced_headers else None
initial_max_peer_synced_blocks = max(initial_peer_synced_blocks) if initial_peer_synced_blocks else None

start_headers = start_bci.get('headers') if isinstance(start_bci.get('headers'), int) else None
final_headers = final_bci.get('headers') if isinstance(final_bci.get('headers'), int) else None
newer_blocks_exist = (
    final_height > start_height
    or (start_headers is not None and final_headers is not None and final_headers > start_headers)
    or (
        initial_max_peer_synced_headers is not None
        and max_peer_synced_headers is not None
        and max_peer_synced_headers > initial_max_peer_synced_headers
    )
    or (
        initial_max_peer_synced_blocks is not None
        and max_peer_synced_blocks is not None
        and max_peer_synced_blocks > initial_max_peer_synced_blocks
    )
)
headers_blocks_equal = final_bci.get('headers') == final_bci.get('blocks')
active_tip_entries=[x for x in chaintips if x.get('status')=='active'] if isinstance(chaintips,list) else []
chain_continues_normally = (start_bci.get('chain') == 'main' and final_bci.get('chain') == 'main' and len(active_tip_entries) == 1)

sync_result={
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'mode': 'controlled-sync-check',
    'safety': {
        'operates_on_disposable_copy_only': True,
        'offline_copy_reused': 'USER_MANAGED_UNKNOWN',
    },
    'start': {
        'height': start_height,
        'best_hash': start_hash,
        'tip_time': start_tip.get('time'),
        'tip_hash': start_hash,
        'genesis_hash': start_genesis,
    },
    'final': {
        'height': final_height,
        'best_hash': final_hash,
        'tip_time': final_tip.get('time'),
        'headers': final_bci.get('headers'),
        'chainwork': final_bci.get('chainwork'),
        'connections': len(final_peers),
    },
    'observations': {
        'peer_count_observed_max': max((snap.get('connection_count',0) for snap in polls), default=0),
        'unique_peers_observed': len(peer_addrs),
        'max_peer_startingheight_observed': max_peer_height,
        'initial_max_peer_synced_headers': initial_max_peer_synced_headers,
        'initial_max_peer_synced_blocks': initial_max_peer_synced_blocks,
        'max_peer_synced_headers_observed': max_peer_synced_headers,
        'max_peer_synced_blocks_observed': max_peer_synced_blocks,
        'newer_blocks_exist': newer_blocks_exist,
        'chain_continues_normally': chain_continues_normally,
        'reorg_detected': len(reorg_events) > 0,
        'reorg_events': reorg_events,
        'headers_equal_blocks_final': headers_blocks_equal,
        'poll_count': len(polls),
        'convergence_basis': {
            'min_runtime_seconds': int(min_runtime),
            'max_runtime_seconds': int(max_runtime),
            'poll_seconds': int(poll_seconds),
            'stagnation_polls': int(stagnation_polls),
        },
    },
    'limitations': [
        'Peer-reported heights are advisory and may differ by peer version and sync state.',
        'No single peer is treated as authoritative; convergence must be interpreted from aggregate evidence.',
    ],
}

peer_summary={
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'mode': 'controlled-sync-check',
    'final_peers': peer_rows,
    'poll_samples': polls,
}

json.dump(sync_result, open(sync_result_path, 'w'), indent=2)
json.dump(peer_summary, open(peer_summary_path, 'w'), indent=2)
PY

log "Controlled sync check complete."
log "Output: $SYNC_RESULT_JSON"
log "Output: $PEER_SUMMARY_JSON"
