#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/devtools/revival/phase2/phase2-common.sh
source "$SCRIPT_DIR/phase2-common.sh"

usage() {
  cat <<USAGE
Usage:
  $0 --datadir <disposable_working_copy_dir> [--outdir <output_dir>] [--archive-name <name>] [--archive-sha256 <hex>]

Notes:
  - --datadir must point to a disposable extracted working copy containing blocks/ and chainstate/.
  - Never pass crown-old-chain.7z directly.
USAGE
}

DATADIR=""
OUTDIR=""
ARCHIVE_NAME="crown-old-chain.7z"
ARCHIVE_SHA256="56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0"

while [ $# -gt 0 ]; do
  case "$1" in
    --datadir)
      DATADIR="${2:-}"; shift 2 ;;
    --outdir)
      OUTDIR="${2:-}"; shift 2 ;;
    --archive-name)
      ARCHIVE_NAME="${2:-}"; shift 2 ;;
    --archive-sha256)
      ARCHIVE_SHA256="${2:-}"; shift 2 ;;
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
  die "Refusing archive path. Provide an extracted disposable working copy directory instead."
fi
ensure_disposable_chaincopy_dir "$DATADIR"
assert_phase2_working_copy_marker "$DATADIR"
assert_mainnet_config_only "$DATADIR"
assert_rpc_not_ready "$DATADIR"

if [ -z "$OUTDIR" ]; then
  OUTDIR="$DATADIR/phase2-offline-output"
fi
OUTDIR="$(abs_path "$OUTDIR")"
mkdir -p "$OUTDIR"

CHAIN_BASELINE_JSON="$OUTDIR/phase2-chain-baseline.json"
UTXO_SUMMARY_JSON="$OUTDIR/phase2-utxo-summary.json"
CHECKPOINT_RESULT_JSON="$OUTDIR/phase2-checkpoint-verification.json"

cleanup() {
  stop_crownd "$DATADIR"
}
trap cleanup EXIT

log "Starting offline baseline against disposable working copy: $DATADIR"
start_crownd "$DATADIR" -testnet=0 -regtest=0 -listen=0 -dnsseed=0 -dns=0 -discover=0 -upnp=0 -connect=0 -maxconnections=0 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcallowip=::1
wait_rpc_ready "$DATADIR" 240 || die "crownd RPC did not become ready for offline baseline"

rpc "$DATADIR" getblockchaininfo > "$OUTDIR/blockchaininfo.json"
rpc "$DATADIR" getnetworkinfo > "$OUTDIR/networkinfo.json"
rpc "$DATADIR" getchaintips > "$OUTDIR/chaintips.json"
BEST_HASH="$(rpc "$DATADIR" getbestblockhash)"
HEIGHT="$(rpc "$DATADIR" getblockcount)"
GENESIS_HASH="$(rpc "$DATADIR" getblockhash 0)"
rpc "$DATADIR" getblock "$BEST_HASH" > "$OUTDIR/tip-block.json"
rpc "$DATADIR" getblock "$GENESIS_HASH" > "$OUTDIR/genesis-block.json"

VERIFYCHAIN_RESULT="UNKNOWN"
if rpc "$DATADIR" verifychain 4 288 > "$OUTDIR/verifychain.json" 2>/dev/null; then
  VERIFYCHAIN_RESULT="$(python3 - "$OUTDIR/verifychain.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]))
if v is True:
    print('true')
elif v is False:
    print('false')
else:
    print('INVALID_RESPONSE')
PY
)"
else
  echo '{"error":"verifychain RPC failed"}' > "$OUTDIR/verifychain.json"
  VERIFYCHAIN_RESULT="ERROR"
fi

TXOUTSET_AVAILABLE="false"
if rpc "$DATADIR" gettxoutsetinfo > "$OUTDIR/txoutsetinfo.json" 2>/dev/null; then
  TXOUTSET_AVAILABLE="true"
else
  echo '{"error":"gettxoutsetinfo RPC failed"}' > "$OUTDIR/txoutsetinfo.json"
fi

expected_mainnet_params_json > "$OUTDIR/expected-mainnet-params.json"
scan_block_files_json "$DATADIR" > "$OUTDIR/block-file-inventory.json"
OBSERVED_MAGIC_HEX="$(read_blk_magic_hex "$DATADIR" || true)"

python3 - "$OUTDIR" "$HEIGHT" <<'PY'
import json,sys
outdir=sys.argv[1]
height=int(sys.argv[2])
exp=json.load(open(f"{outdir}/expected-mainnet-params.json"))
results=[]
for cp in exp.get("checkpoints", []):
    h=cp["height"]
    if h > height:
        continue
    results.append({"height": h, "expected_hash": cp["hash"]})
json.dump({"to_check": results}, open(f"{outdir}/checkpoint-plan.json","w"), indent=2)
PY

python3 - "$CROWNCLI_BIN" "$DATADIR" "$OUTDIR/checkpoint-plan.json" "$CHECKPOINT_RESULT_JSON" <<'PY'
import json,subprocess,sys

crowncli=sys.argv[1]
datadir=sys.argv[2]
plan=json.load(open(sys.argv[3]))
out_path=sys.argv[4]

checks=[]
for item in plan.get('to_check', []):
    h=item['height']
    expected=item['expected_hash'].lower()
    try:
        observed=subprocess.check_output(
            [crowncli, f'-datadir={datadir}', 'getblockhash', str(h)],
            text=True
        ).strip().lower()
        checks.append({
            'height': h,
            'expected_hash': expected,
            'observed_hash': observed,
            'match': observed == expected,
        })
    except subprocess.CalledProcessError as e:
        checks.append({
            'height': h,
            'expected_hash': expected,
            'observed_hash': None,
            'match': False,
            'error': str(e),
        })

mismatches=[c for c in checks if not c.get('match')]
out={
    'checked_count': len(checks),
    'matched_count': len(checks)-len(mismatches),
    'mismatch_count': len(mismatches),
    'mismatches': mismatches,
    'checks': checks,
}
json.dump(out, open(out_path,'w'), indent=2)
PY

python3 - "$OUTDIR" "$CHAIN_BASELINE_JSON" "$UTXO_SUMMARY_JSON" "$DATADIR" "$ARCHIVE_NAME" "$ARCHIVE_SHA256" "$BEST_HASH" "$HEIGHT" "$GENESIS_HASH" "$VERIFYCHAIN_RESULT" "$TXOUTSET_AVAILABLE" "$OBSERVED_MAGIC_HEX" <<'PY'
import datetime, json, sys
(
    outdir, baseline_path, utxo_path, datadir,
    archive_name, archive_sha256,
    best_hash, height, genesis_hash,
    verifychain_result, txoutset_available, observed_magic_hex,
) = sys.argv[1:13]

height=int(height)
txoutset_available=(txoutset_available.lower()=='true')

blockchaininfo=json.load(open(f"{outdir}/blockchaininfo.json"))
networkinfo=json.load(open(f"{outdir}/networkinfo.json"))
tip_block=json.load(open(f"{outdir}/tip-block.json"))
block_inventory=json.load(open(f"{outdir}/block-file-inventory.json"))
expected=json.load(open(f"{outdir}/expected-mainnet-params.json"))
checkpoint_result=json.load(open(f"{outdir}/phase2-checkpoint-verification.json"))
verifychain_json=json.load(open(f"{outdir}/verifychain.json"))

if txoutset_available:
    txoutset=json.load(open(f"{outdir}/txoutsetinfo.json"))
else:
    txoutset=None

verifychain_readable = (verifychain_result == 'true')
chainstate_readable = txoutset_available or verifychain_readable
verifychain_issue = None
if verifychain_result == 'ERROR':
    verifychain_issue = 'verifychain RPC failed'
elif verifychain_result == 'INVALID_RESPONSE':
    verifychain_issue = 'verifychain returned non-boolean payload'

identity_mismatches=[]
if blockchaininfo.get('chain') != 'main':
    identity_mismatches.append('RPC chain is not main')
if genesis_hash.lower() != expected.get('genesis_hash','').lower():
    identity_mismatches.append('Genesis hash mismatch')
if observed_magic_hex and observed_magic_hex.lower() != expected.get('message_start_hex','').lower():
    identity_mismatches.append('Block file network magic mismatch')
if checkpoint_result.get('mismatch_count', 0) > 0:
    identity_mismatches.append('One or more known checkpoints mismatched')

mainnet_confirmed=(len(identity_mismatches)==0)

tip_time = tip_block.get('time')
tip_time_iso = None
if isinstance(tip_time, int):
    tip_time_iso = datetime.datetime.utcfromtimestamp(tip_time).isoformat() + 'Z'

baseline={
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'mode': 'offline-baseline',
    'safety': {
        'networking_disabled': True,
        'operates_on_disposable_copy_only': True,
        'archive_file_touched': False,
    },
    'archive_reference': {
        'archive_name': archive_name,
        'archive_sha256': archive_sha256,
    },
    'working_copy_datadir': datadir,
    'chain_identity': {
        'expected_from_source': {
            'network': expected.get('network'),
            'genesis_hash': expected.get('genesis_hash'),
            'message_start_hex': expected.get('message_start_hex'),
            'default_port': expected.get('default_port'),
            'subsidy_halving_interval': expected.get('subsidy_halving_interval'),
            'checkpoint_count': len(expected.get('checkpoints', [])),
        },
        'observed': {
            'rpc_chain': blockchaininfo.get('chain'),
            'genesis_hash': genesis_hash,
            'observed_blockfile_magic_hex': observed_magic_hex or None,
            'network_version': networkinfo.get('version'),
            'protocol_version': networkinfo.get('protocolversion'),
        },
        'checkpoint_verification': {
            'checked_count': checkpoint_result.get('checked_count'),
            'matched_count': checkpoint_result.get('matched_count'),
            'mismatch_count': checkpoint_result.get('mismatch_count'),
            'mismatches': checkpoint_result.get('mismatches', []),
        },
        'mainnet_identity_confirmed': mainnet_confirmed,
        'mismatches': identity_mismatches,
    },
    'archive_tip': {
        'height': height,
        'best_hash': best_hash,
        'tip_time': tip_time,
        'tip_time_iso': tip_time_iso,
        'headers': blockchaininfo.get('headers'),
        'difficulty': blockchaininfo.get('difficulty'),
        'chainwork': blockchaininfo.get('chainwork'),
    },
    'chainstate': {
        'readable': chainstate_readable,
        'verifychain_result': verifychain_result,
        'verifychain_raw': verifychain_json,
        'db_compatibility_issues': None if txoutset_available else 'gettxoutsetinfo unavailable or failed; inspect txoutsetinfo.json error',
        'verifychain_issue': verifychain_issue,
    },
    'block_file_inventory': block_inventory,
    'later_supply_reconstruction_inputs': {
        'txoutsetinfo': txoutset,
        'chaintips_file': f"{outdir}/chaintips.json",
        'tip_block_file': f"{outdir}/tip-block.json",
    },
    'limitations': [
        'This script does not calculate historical issuance; it records reproducible baseline inputs for later Phase 2 calculations.',
        'Pruned/completeness status is inferred from blk file continuity and may require manual confirmation.',
    ],
}

utxo_summary={
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'mode': 'offline-baseline',
    'working_copy_datadir': datadir,
    'available': txoutset_available,
    'txoutsetinfo': txoutset,
}

json.dump(baseline, open(baseline_path, 'w'), indent=2)
json.dump(utxo_summary, open(utxo_path, 'w'), indent=2)
PY

log "Offline baseline complete."
log "Output: $CHAIN_BASELINE_JSON"
log "Output: $UTXO_SUMMARY_JSON"
log "Output: $CHECKPOINT_RESULT_JSON"
