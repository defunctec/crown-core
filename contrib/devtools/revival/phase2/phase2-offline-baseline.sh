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
  OUTDIR="$(dirname "$DATADIR")/$(basename "$DATADIR").phase2-offline-output"
fi
OUTDIR="$(abs_path "$OUTDIR")"
mkdir -p "$OUTDIR"

CHAIN_BASELINE_JSON="$OUTDIR/phase2-chain-baseline.json"
UTXO_SUMMARY_JSON="$OUTDIR/phase2-utxo-summary.json"
CHECKPOINT_RESULT_JSON="$OUTDIR/phase2-checkpoint-verification.json"
FORK_ANALYSIS_JSON="$OUTDIR/phase2-fork-analysis.json"
FORK_HISTORY_JSON="$OUTDIR/phase2-fork-history-evidence.json"
FORK_BLOCKS_DIR="$OUTDIR/phase2-fork-blocks"

cleanup() {
  stop_crownd "$DATADIR"
}
trap cleanup EXIT

log "Starting offline baseline against disposable working copy: $DATADIR"
start_crownd "$DATADIR" -testnet=0 -regtest=0 -listen=0 -dnsseed=0 -dns=0 -discover=0 -upnp=0 -connect=0 -maxconnections=0 -onlynet=ipv4 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1
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
with open(sys.argv[1], encoding='utf-8') as f:
    v=json.load(f)
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

python3 - "$CROWNCLI_BIN" "$DATADIR" "$(phase2_rpc_port "$DATADIR")" "$(phase2_rpc_user "$DATADIR")" "$(phase2_rpc_password "$DATADIR")" "$OUTDIR/checkpoint-plan.json" "$CHECKPOINT_RESULT_JSON" <<'PY'
import json,subprocess,sys

crowncli=sys.argv[1]
datadir=sys.argv[2]
rpc_port=sys.argv[3]
rpc_user=sys.argv[4]
rpc_password=sys.argv[5]
plan=json.load(open(sys.argv[6]))
out_path=sys.argv[7]

checks=[]
for item in plan.get('to_check', []):
    h=item['height']
    expected=item['expected_hash'].lower()
    try:
        observed=subprocess.check_output(
            [
                crowncli,
                f'-datadir={datadir}',
                '-rpcconnect=127.0.0.1',
                f'-rpcport={rpc_port}',
                f'-rpcuser={rpc_user}',
                f'-rpcpassword={rpc_password}',
                'getblockhash',
                str(h),
            ],
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

mkdir -p "$FORK_BLOCKS_DIR"
python3 - "$CROWNCLI_BIN" "$DATADIR" "$(phase2_rpc_port "$DATADIR")" "$(phase2_rpc_user "$DATADIR")" "$(phase2_rpc_password "$DATADIR")" "$OUTDIR/chaintips.json" "$FORK_ANALYSIS_JSON" "$FORK_BLOCKS_DIR" <<'PY'
import datetime
import json
import os
import subprocess
import sys

crowncli, datadir, rpc_port, rpc_user, rpc_password, chaintips_path, out_path, blocks_dir = sys.argv[1:9]
with open(chaintips_path, encoding='utf-8') as f:
    tips = json.load(f)

def rpc(*args):
    cmd = [
        crowncli,
        f'-datadir={datadir}',
        '-rpcconnect=127.0.0.1',
        f'-rpcport={rpc_port}',
        f'-rpcuser={rpc_user}',
        f'-rpcpassword={rpc_password}',
    ] + [str(a) for a in args]
    out = subprocess.check_output(cmd, text=True)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out.strip()

def maybe_iso(ts):
    if isinstance(ts, int):
        return datetime.datetime.utcfromtimestamp(ts).isoformat() + 'Z'
    return None

def block_bundle(block_hash, tip_status=None):
    b = rpc('getblock', block_hash)
    pos_keys = [
        'flags', 'proofhash', 'modifier', 'modifierchecksum',
        'entropybit', 'chaintrust', 'mint', 'stake',
        'stakeModifier', 'stakeModifierV2', 'stakemodifier',
        'stakepointer', 'masternode', 'systemnode', 'mnpayments', 'snpayments'
    ]
    pos_meta = {k: b[k] for k in pos_keys if k in b}
    return {
        'hash': b.get('hash'),
        'height': b.get('height'),
        'previousblockhash': b.get('previousblockhash'),
        'time': b.get('time'),
        'time_iso': maybe_iso(b.get('time')),
        'difficulty': b.get('difficulty'),
        'chainwork': b.get('chainwork'),
        'confirmations': b.get('confirmations'),
        'status': tip_status,
        'tx_count': len(b.get('tx', [])) if isinstance(b.get('tx'), list) else None,
        'version': b.get('version'),
        'versionHex': b.get('versionHex'),
        'pos_mnpos_metadata': pos_meta,
    }, b

def as_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default

FORK_PROXIMITY_WINDOW = 32
FORK_SELECTION_TIEBREAK = 'nearest-height-then-longest-branchlen'
MAX_ANCESTRY_STEPS = 1000000

active = [t for t in tips if t.get('status') == 'active']
valid_forks = [t for t in tips if t.get('status') == 'valid-fork']
best_height = max((as_int(t.get('height', -1), -1) for t in active), default=-1)
near_best = [t for t in tips if t.get('status') in ('active', 'valid-fork') and abs(as_int(t.get('height', -1), -1) - best_height) <= FORK_PROXIMITY_WINDOW]

selected_active = max(active, key=lambda t: as_int(t.get('height', -1), -1)) if active else None
selected_fork = None
candidate_forks = [t for t in near_best if t.get('status') == 'valid-fork']
if candidate_forks:
    selected_fork = sorted(candidate_forks, key=lambda t: (abs(as_int(t.get('height', -1), -1) - best_height), -as_int(t.get('branchlen', 0), 0)))[0]

analysis = {
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'source': {
        'chaintips_file': chaintips_path,
        'best_height_from_active_tip': best_height,
        'selection_policy': {
            'near_best_window_blocks': FORK_PROXIMITY_WINDOW,
            'valid_fork_tiebreak': FORK_SELECTION_TIEBREAK,
            'max_ancestry_steps': MAX_ANCESTRY_STEPS,
        },
    },
    'tips': {
        'active': active,
        'valid_fork': valid_forks,
        'near_best_active_or_valid_fork': near_best,
    },
    'selected_pair': None,
    'common_ancestor': None,
    'first_divergent': None,
    'branch_metrics': None,
    'selection': {
        'archived_node_selected_active_branch': True,
        'strictly_greater_chainwork_branch': None,
    },
    'ancestry_resolution': {
        'resolved': False,
        'error': None,
    },
    'divergent_blocks_export_dir': blocks_dir,
    'divergent_block_exports': {'active': [], 'competing': []},
}

if selected_active and selected_fork:
    active_summary, active_block = block_bundle(selected_active['hash'], selected_active.get('status'))
    fork_summary, fork_block = block_bundle(selected_fork['hash'], selected_fork.get('status'))

    a = {'hash': active_block['hash'], 'height': int(active_block['height']), 'prev': active_block.get('previousblockhash')}
    f = {'hash': fork_block['hash'], 'height': int(fork_block['height']), 'prev': fork_block.get('previousblockhash')}
    active_chain = []
    fork_chain = []

    ancestry_error = None
    steps = 0
    while a['hash'] != f['hash']:
        steps += 1
        if steps > MAX_ANCESTRY_STEPS:
            ancestry_error = f'ancestry walk exceeded max steps ({MAX_ANCESTRY_STEPS}) before finding common ancestor'
            break
        if a['height'] > f['height']:
            active_chain.append(dict(a))
            if not a.get('prev'):
                ancestry_error = 'active branch reached block without previousblockhash before common ancestor'
                break
            hb = rpc('getblock', a['prev'])
            a = {'hash': hb['hash'], 'height': int(hb['height']), 'prev': hb.get('previousblockhash')}
        elif f['height'] > a['height']:
            fork_chain.append(dict(f))
            if not f.get('prev'):
                ancestry_error = 'competing branch reached block without previousblockhash before common ancestor'
                break
            hb = rpc('getblock', f['prev'])
            f = {'hash': hb['hash'], 'height': int(hb['height']), 'prev': hb.get('previousblockhash')}
        else:
            active_chain.append(dict(a))
            fork_chain.append(dict(f))
            if not a.get('prev') or not f.get('prev'):
                ancestry_error = 'one branch reached block without previousblockhash before common ancestor at equal height'
                break
            ab = rpc('getblock', a['prev'])
            fb = rpc('getblock', f['prev'])
            a = {'hash': ab['hash'], 'height': int(ab['height']), 'prev': ab.get('previousblockhash')}
            f = {'hash': fb['hash'], 'height': int(fb['height']), 'prev': fb.get('previousblockhash')}

    if ancestry_error is None:
        common_ancestor = {'height': a['height'], 'hash': a['hash']}
        first_div_active = active_chain[-1] if active_chain else None
        first_div_fork = fork_chain[-1] if fork_chain else None

        for side_name, chain in (('active', active_chain), ('competing', fork_chain)):
            for node in reversed(chain):
                full = rpc('getblock', node['hash'])
                out_file = os.path.join(blocks_dir, f'{side_name}-h{full["height"]}-{full["hash"]}.json')
                with open(out_file, 'w', encoding='utf-8') as fp:
                    json.dump(full, fp, indent=2)
                analysis['divergent_block_exports'][side_name].append(out_file)

    aw = int(active_summary.get('chainwork') or '0', 16)
    fw = int(fork_summary.get('chainwork') or '0', 16)
    stronger = 'active' if aw > fw else ('competing' if fw > aw else 'equal')

    analysis['selected_pair'] = {
        'active_tip': active_summary,
        'competing_tip': fork_summary,
    }
    if ancestry_error is None:
        analysis['common_ancestor'] = common_ancestor
        analysis['first_divergent'] = {
            'active_branch': first_div_active,
            'competing_branch': first_div_fork,
        }
        analysis['branch_metrics'] = {
            'active_branch_divergent_length': len(active_chain),
            'competing_branch_divergent_length': len(fork_chain),
            'active_tip_chainwork': active_summary.get('chainwork'),
            'competing_tip_chainwork': fork_summary.get('chainwork'),
            'active_tip_height': active_summary.get('height'),
            'competing_tip_height': fork_summary.get('height'),
        }
        analysis['ancestry_resolution'] = {'resolved': True, 'error': None}
    else:
        analysis['ancestry_resolution'] = {'resolved': False, 'error': ancestry_error}
    analysis['selection']['strictly_greater_chainwork_branch'] = stronger if stronger != 'equal' else None

with open(out_path, 'w', encoding='utf-8') as fp:
    json.dump(analysis, fp, indent=2)
PY

python3 - "$REPO_ROOT" "$FORK_HISTORY_JSON" <<'PY'
import json
import subprocess
import sys

repo_root, out_path = sys.argv[1:3]
terms = ['stakepointer', 'EMERGENCY_STAKEPOINTERS', 'reorg', 'fork', 'split', 'recovery', 'checkpoint']

def run(args):
    return subprocess.check_output(args, text=True).strip()

history = {'terms': {}, 'focused_commit': None}
for term in terms:
    cmd = ['git', '-C', repo_root, 'log', '--date=iso', '--pretty=format:%H%x09%ad%x09%an%x09%s', '-n', '25', '--grep', term, '-i']
    out = run(cmd)
    rows = []
    if out:
        for line in out.splitlines():
            parts = line.split('\t', 3)
            if len(parts) == 4:
                rows.append({'commit': parts[0], 'date': parts[1], 'author': parts[2], 'subject': parts[3]})
    history['terms'][term] = rows

focus = '361f5c574aff8de59e52f403d715986b53e6e355'
try:
    stat = run(['git', '-C', repo_root, 'show', '--name-only', '--pretty=format:%H%x09%ad%x09%an%x09%s', '--date=iso', focus])
    lines = [x for x in stat.splitlines() if x.strip()]
    if lines:
        h, d, a, s = lines[0].split('\t', 3)
        history['focused_commit'] = {
            'commit': h, 'date': d, 'author': a, 'subject': s,
            'changed_files': lines[1:],
        }
except Exception as e:
    history['focused_commit'] = {'error': str(e)}

with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(history, f, indent=2)
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
log "Output: $FORK_ANALYSIS_JSON"
log "Output: $FORK_HISTORY_JSON"
