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
EXPECTED_MAINNET_GENESIS="0000000085370d5e122f64f4ab19c68614ff3df78c8d13cb814fd7e69a1dc6da"
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
TERMINAL_FORK_JSON="$OUTDIR/phase2-terminal-fork-forensics.json"
STABILITY_WINDOW_JSON="$OUTDIR/phase2-stability-window-analysis.json"
FORK_BLOCKS_DIR="$OUTDIR/phase2-fork-blocks"
STABILITY_ANCHOR_UTC="2025-08-19T23:59:59Z"
STABILITY_LOOKBACK_DAYS="90"
PROVISIONAL_SNAPSHOT_CUTOFF_UTC="2025-07-01T23:59:59Z"
PROVISIONAL_SNAPSHOT_HEIGHT="5420279"
PROVISIONAL_SNAPSHOT_HASH="8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed"
PROVISIONAL_SNAPSHOT_TIMESTAMP_UTC="2025-07-01T23:59:24Z"

cleanup() {
  stop_crownd "$DATADIR"
}
trap cleanup EXIT

log "Starting offline baseline against disposable working copy: $DATADIR"
start_crownd "$DATADIR" -testnet=0 -regtest=0 -listen=0 -dnsseed=0 -dns=0 -discover=0 -upnp=0 -maxconnections=0 -onlynet=ipv4 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1
wait_rpc_ready "$DATADIR" 240 || die "crownd RPC did not become ready for offline baseline"

GENESIS_HASH="$(rpc "$DATADIR" getblockhash 0)"
CHAIN_NAME="$(rpc "$DATADIR" getblockchaininfo | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chain",""))')"
BEST_HASH="$(rpc "$DATADIR" getbestblockhash)"
HEIGHT="$(rpc "$DATADIR" getblockcount)"
[ "$CHAIN_NAME" = "main" ] || die "Refusing offline baseline evidence collection: expected chain=main but got chain=${CHAIN_NAME:-UNKNOWN} (height=$HEIGHT, best_hash=$BEST_HASH, genesis=$GENESIS_HASH)"
[ "$GENESIS_HASH" = "$EXPECTED_MAINNET_GENESIS" ] || die "Refusing offline baseline evidence collection: expected genesis=$EXPECTED_MAINNET_GENESIS but got genesis=$GENESIS_HASH (chain=${CHAIN_NAME:-UNKNOWN}, height=$HEIGHT, best_hash=$BEST_HASH)"

rpc "$DATADIR" getblockchaininfo > "$OUTDIR/blockchaininfo.json"
rpc "$DATADIR" getnetworkinfo > "$OUTDIR/networkinfo.json"
rpc "$DATADIR" getchaintips > "$OUTDIR/chaintips.json"
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
import string

crowncli, datadir, rpc_port, rpc_user, rpc_password, chaintips_path, out_path, blocks_dir = sys.argv[1:9]
with open(chaintips_path, encoding='utf-8') as f:
    tips = json.load(f)

def serialize_rpc_arg(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return 'null'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return value

def build_rpc_cmd(*rpc_args):
    cmd = [
        crowncli,
        f'-datadir={datadir}',
        '-rpcconnect=127.0.0.1',
        f'-rpcport={rpc_port}',
        f'-rpcuser={rpc_user}',
        f'-rpcpassword={rpc_password}',
    ] + [serialize_rpc_arg(a) for a in rpc_args]
    forbidden = [item for item in cmd if item in ('True', 'False')]
    if forbidden:
        raise ValueError(f'forbidden Python bool literal in crown-cli argv: {forbidden}')
    return cmd

smoke_cmd = build_rpc_cmd('getblock', '00' * 32, False)
smoke_rawtx_cmd = build_rpc_cmd('getrawtransaction', '00' * 32, 1)
if smoke_cmd[-1] != 'false' or 'True' in smoke_cmd or 'False' in smoke_cmd:
    raise ValueError(f'getblock argv serialization regression: {smoke_cmd}')
if smoke_rawtx_cmd[-1] != '1' or 'True' in smoke_rawtx_cmd or 'False' in smoke_rawtx_cmd:
    raise ValueError(f'getrawtransaction argv serialization regression: {smoke_rawtx_cmd}')

def rpc(*args):
    cmd = build_rpc_cmd(*args)
    out = subprocess.check_output(cmd, text=True)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out.strip()

def maybe_iso(ts):
    if isinstance(ts, int):
        return datetime.datetime.utcfromtimestamp(ts).isoformat() + 'Z'
    return None

TIP_SUMMARY_FIELDS = [
    'hash', 'height', 'previousblockhash', 'time', 'time_iso', 'difficulty',
    'chainwork', 'confirmations', 'status', 'tx_count', 'version', 'versionHex',
    'pos_mnpos_metadata',
]
POS_MNPOS_FIELDS = [
    'flags', 'proofhash', 'modifier', 'modifierchecksum',
    'entropybit', 'chaintrust', 'mint', 'stake',
    'stakeModifier', 'stakeModifierV2', 'stakemodifier',
    'stakepointer', 'masternode', 'systemnode', 'mnpayments', 'snpayments'
]

def block_bundle(block_hash, tip_status=None):
    b = rpc('getblock', block_hash)
    pos_meta = {k: b[k] for k in POS_MNPOS_FIELDS if k in b}
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

def parse_chainwork(value):
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.startswith('0x'):
        text = text[2:]
    if not text or any(ch not in string.hexdigits for ch in text):
        return None
    try:
        return int(text, 16)
    except Exception:
        return None

FORK_PROXIMITY_WINDOW = 32
FORK_SELECTION_TIEBREAK = 'nearest-height-then-longest-branchlen'
MAX_ANCESTRY_STEPS = 1000000

active = [t for t in tips if t.get('status') == 'active']
valid_forks = [t for t in tips if t.get('status') == 'valid-fork']
best_height_from_active = max((as_int(t.get('height', -1), -1) for t in active), default=-1)
best_height_overall = max((as_int(t.get('height', -1), -1) for t in tips), default=-1)
best_height = best_height_from_active if best_height_from_active >= 0 else best_height_overall

selected_active = max(active, key=lambda t: as_int(t.get('height', -1), -1)) if active else None
selection_anchor_height = as_int(selected_active.get('height', -1), -1) if selected_active else best_height
near_best = [t for t in tips if t.get('status') in ('active', 'valid-fork') and abs(as_int(t.get('height', -1), -1) - selection_anchor_height) <= FORK_PROXIMITY_WINDOW]
selected_fork = None
candidate_forks = [t for t in near_best if t.get('status') == 'valid-fork']
if candidate_forks:
    selected_fork = sorted(candidate_forks, key=lambda t: (abs(as_int(t.get('height', -1), -1) - selection_anchor_height), -as_int(t.get('branchlen', 0), 0)))[0]

analysis = {
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'source': {
        'chaintips_file': chaintips_path,
        'best_height_from_active_tip': best_height,
        'best_height_fallback_used': (best_height_from_active < 0 and best_height_overall >= 0),
        'selection_anchor_height': selection_anchor_height,
        'selection_policy': {
            'near_best_window_blocks': FORK_PROXIMITY_WINDOW,
            'valid_fork_tiebreak': FORK_SELECTION_TIEBREAK,
            'max_ancestry_steps': MAX_ANCESTRY_STEPS,
            'tip_summary_fields': TIP_SUMMARY_FIELDS,
            'tip_pos_mnpos_fields': POS_MNPOS_FIELDS,
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
        'chainwork_comparison_error': None,
    },
    'ancestry_resolution': {
        'resolved': False,
        'error': None,
    },
    'divergent_blocks_export_dir': blocks_dir,
    'divergent_branches': {'active': [], 'competing': []},
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
        active_chain_ancestor_to_tip = list(reversed(active_chain))
        fork_chain_ancestor_to_tip = list(reversed(fork_chain))
        analysis['divergent_branches']['active'] = active_chain_ancestor_to_tip
        analysis['divergent_branches']['competing'] = fork_chain_ancestor_to_tip
        first_div_active = active_chain_ancestor_to_tip[0] if active_chain_ancestor_to_tip else None
        first_div_fork = fork_chain_ancestor_to_tip[0] if fork_chain_ancestor_to_tip else None

        for side_name, chain in (('active', active_chain_ancestor_to_tip), ('competing', fork_chain_ancestor_to_tip)):
            for node in chain:
                full = rpc('getblock', node['hash'])
                out_file = os.path.join(blocks_dir, f'{side_name}-h{full["height"]}-{full["hash"]}.json')
                with open(out_file, 'w', encoding='utf-8') as fp:
                    json.dump(full, fp, indent=2)
                analysis['divergent_block_exports'][side_name].append(out_file)

    analysis['selected_pair'] = {
        'active_tip': active_summary,
        'competing_tip': fork_summary,
    }
    aw = parse_chainwork(active_summary.get('chainwork'))
    fw = parse_chainwork(fork_summary.get('chainwork'))
    if aw is not None and fw is not None:
        stronger = 'active' if aw > fw else ('competing' if fw > aw else 'equal')
        analysis['selection']['strictly_greater_chainwork_branch'] = stronger if stronger != 'equal' else None
    else:
        analysis['selection']['chainwork_comparison_error'] = 'missing or non-hex chainwork in selected tip summary'

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

with open(out_path, 'w', encoding='utf-8') as fp:
    json.dump(analysis, fp, indent=2)
PY

python3 - "$CROWNCLI_BIN" "$DATADIR" "$(phase2_rpc_port "$DATADIR")" "$(phase2_rpc_user "$DATADIR")" "$(phase2_rpc_password "$DATADIR")" "$FORK_ANALYSIS_JSON" "$TERMINAL_FORK_JSON" <<'PY'
import datetime
import json
import struct
import subprocess
import sys

crowncli, datadir, rpc_port, rpc_user, rpc_password, fork_analysis_path, out_path = sys.argv[1:8]
fork_analysis = json.load(open(fork_analysis_path, encoding='utf-8'))

def serialize_rpc_arg(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return 'null'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return value

def build_rpc_cmd(*rpc_args):
    cmd = [
        crowncli,
        f'-datadir={datadir}',
        '-rpcconnect=127.0.0.1',
        f'-rpcport={rpc_port}',
        f'-rpcuser={rpc_user}',
        f'-rpcpassword={rpc_password}',
    ] + [serialize_rpc_arg(a) for a in rpc_args]
    forbidden = [item for item in cmd if item in ('True', 'False')]
    if forbidden:
        raise ValueError(f'forbidden Python bool literal in crown-cli argv: {forbidden}')
    return cmd

smoke_cmd = build_rpc_cmd('getblock', '00' * 32, False)
smoke_rawtx_cmd = build_rpc_cmd('getrawtransaction', '00' * 32, 1)
if smoke_cmd[-1] != 'false' or 'True' in smoke_cmd or 'False' in smoke_cmd:
    raise ValueError(f'getblock argv serialization regression: {smoke_cmd}')
if smoke_rawtx_cmd[-1] != '1' or 'True' in smoke_rawtx_cmd or 'False' in smoke_rawtx_cmd:
    raise ValueError(f'getrawtransaction argv serialization regression: {smoke_rawtx_cmd}')

def rpc(*args):
    cmd = build_rpc_cmd(*args)
    out = subprocess.check_output(cmd, text=True)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out.strip()

def maybe_iso(ts):
    if isinstance(ts, int):
        return datetime.datetime.utcfromtimestamp(ts).isoformat() + 'Z'
    return None

def read_compact_size(buf, pos):
    if pos >= len(buf):
        raise ValueError('unexpected end of buffer while reading compact size')
    first = buf[pos]
    pos += 1
    if first < 253:
        return first, pos
    if first == 253:
        if pos + 2 > len(buf):
            raise ValueError('compact size uint16 truncated')
        return struct.unpack_from('<H', buf, pos)[0], pos + 2
    if first == 254:
        if pos + 4 > len(buf):
            raise ValueError('compact size uint32 truncated')
        return struct.unpack_from('<I', buf, pos)[0], pos + 4
    if pos + 8 > len(buf):
        raise ValueError('compact size uint64 truncated')
    return struct.unpack_from('<Q', buf, pos)[0], pos + 8

def le_uint256_hex(raw):
    if len(raw) != 32:
        raise ValueError('expected 32-byte hash')
    return raw[::-1].hex()

def parse_tx(buf, pos):
    start = pos
    if pos + 4 > len(buf):
        raise ValueError('truncated transaction version')
    n32bit_version = struct.unpack_from('<I', buf, pos)[0]
    pos += 4
    version = n32bit_version & 0xffff
    tx_type = (n32bit_version >> 16) & 0xffff

    vin_count, pos = read_compact_size(buf, pos)
    for _ in range(vin_count):
        if pos + 36 > len(buf):
            raise ValueError('truncated tx input outpoint')
        pos += 32 + 4
        script_len, pos = read_compact_size(buf, pos)
        if pos + script_len + 4 > len(buf):
            raise ValueError('truncated tx input script or sequence')
        pos += script_len + 4

    vout_count, pos = read_compact_size(buf, pos)
    for _ in range(vout_count):
        if pos + 8 > len(buf):
            raise ValueError('truncated tx output value')
        pos += 8
        pk_len, pos = read_compact_size(buf, pos)
        if pos + pk_len > len(buf):
            raise ValueError('truncated tx output script')
        pos += pk_len

    if pos + 4 > len(buf):
        raise ValueError('truncated tx locktime')
    pos += 4

    extra_payload_hex = None
    if version >= 3 and tx_type != 0:
        extra_len, pos = read_compact_size(buf, pos)
        if pos + extra_len > len(buf):
            raise ValueError('truncated special tx extra payload')
        extra_payload_hex = buf[pos:pos + extra_len].hex()
        pos += extra_len

    return {
        'hex': buf[start:pos].hex(),
        'version': version,
        'type': tx_type,
        'extra_payload_hex': extra_payload_hex,
    }, pos

def parse_pubkey(buf, pos):
    key_len, pos = read_compact_size(buf, pos)
    if pos + key_len > len(buf):
        raise ValueError('truncated pubkey')
    key_hex = buf[pos:pos + key_len].hex()
    return {'length': key_len, 'hex': key_hex}, pos + key_len

def parse_block(block_hex):
    buf = bytes.fromhex(block_hex)
    if len(buf) < 81:
        raise ValueError('block payload too short')
    pos = 80
    tx_count, pos = read_compact_size(buf, pos)
    txs = []
    for _ in range(tx_count):
        tx, pos = parse_tx(buf, pos)
        txs.append(tx)

    pos_data = {
        'present': False,
        'block_signature_hex': None,
        'block_signature_length': 0,
        'stakepointer': None,
        'serialized_tail_hex': None,
        'unparsed_trailing_hex': None,
    }
    if pos < len(buf):
        tail_start = pos
        sig_len, pos = read_compact_size(buf, pos)
        if pos + sig_len > len(buf):
            raise ValueError('truncated block signature')
        block_sig = buf[pos:pos + sig_len]
        pos += sig_len
        if pos + 68 > len(buf):
            raise ValueError('truncated stakepointer fixed fields')
        hash_block = le_uint256_hex(buf[pos:pos + 32])
        pos += 32
        txid = le_uint256_hex(buf[pos:pos + 32])
        pos += 32
        n_pos = struct.unpack_from('<I', buf, pos)[0]
        pos += 4
        pubkey_pos, pos = parse_pubkey(buf, pos)
        pubkey_collateral, pos = parse_pubkey(buf, pos)
        sig_over_len, pos = read_compact_size(buf, pos)
        if pos + sig_over_len > len(buf):
            raise ValueError('truncated collateral signover')
        sign_over = buf[pos:pos + sig_over_len]
        pos += sig_over_len
        pos_data = {
            'present': True,
            'block_signature_hex': block_sig.hex(),
            'block_signature_length': sig_len,
            'stakepointer': {
                'hash_block': hash_block,
                'txid': txid,
                'n_pos': n_pos,
                'pubkey_proof_of_stake': pubkey_pos,
                'pubkey_collateral': pubkey_collateral,
                'collateral_signover_signature_hex': sign_over.hex(),
                'collateral_signover_signature_length': sig_over_len,
            },
            'serialized_tail_hex': buf[tail_start:pos].hex(),
            'unparsed_trailing_hex': buf[pos:].hex() if pos < len(buf) else None,
        }

    return {'txs': txs, 'pos_data': pos_data, 'raw_block_hex': block_hex}

def output_summary(vout):
    script = vout.get('scriptPubKey') or {}
    return {
        'n': vout.get('n'),
        'value': vout.get('value'),
        'script_type': script.get('type'),
        'script_hex': script.get('hex'),
        'addresses': script.get('addresses', []),
        'req_sigs': script.get('reqSigs'),
    }

def is_null_prevout(vin_item):
    txid = vin_item.get('txid')
    vout = vin_item.get('vout')
    return (
        isinstance(txid, str)
        and txid == ('0' * 64)
        and vout in (-1, 4294967295)
    )

def classify_tx(decoded, tx_index, proof_type):
    vin = decoded.get('vin', [])
    vout = decoded.get('vout', [])
    is_coinbase = bool(vin) and isinstance(vin[0], dict) and 'coinbase' in vin[0]
    is_coinstake = (
        proof_type == 'PoS'
        and tx_index == 1
        and len(vin) == 1
        and len(vout) == 1
        and isinstance(vin[0], dict)
        and 'coinbase' not in vin[0]
        and is_null_prevout(vin[0])
    )
    vin_outpoints = []
    for item in vin:
        if isinstance(item, dict) and 'txid' in item and 'vout' in item:
            vin_outpoints.append({'txid': item.get('txid'), 'vout': item.get('vout')})
    return {
        'is_coinbase': is_coinbase,
        'is_coinstake': is_coinstake,
        'vin_outpoints': vin_outpoints,
        'outputs': [output_summary(v) for v in vout],
    }

def nonempty_payment(outputs, index):
    if index >= len(outputs):
        return None
    out = outputs[index]
    if out.get('value') in (None, '0.00000000', 0, 0.0) and not out.get('script_hex'):
        return None
    return out

def tx_lookup_from_block(block_hash):
    parsed = parse_block(rpc('getblock', block_hash, False))
    mapping = {}
    decoded_list = []
    for index, tx in enumerate(parsed['txs']):
        decoded = rpc('decoderawtransaction', tx['hex'])
        mapping[decoded.get('txid')] = {
            'index': index,
            'hex': tx['hex'],
            'decoded': decoded,
            'parsed': tx,
        }
        decoded_list.append(mapping[decoded.get('txid')])
    return parsed, mapping, decoded_list

def block_forensics(block_hash):
    summary = rpc('getblock', block_hash)
    parsed, tx_map, decoded_list = tx_lookup_from_block(block_hash)
    proof_type = summary.get('proof_type')
    transactions = []
    coinbase_outputs = []
    coinstake_reward = None
    for tx_info in decoded_list:
        decoded = tx_info['decoded']
        classification = classify_tx(decoded, tx_info['index'], proof_type)
        if classification['is_coinbase']:
            coinbase_outputs = classification['outputs']
        if classification['is_coinstake'] and classification['outputs']:
            coinstake_reward = classification['outputs'][0]
        transactions.append({
            'index': tx_info['index'],
            'txid': decoded.get('txid'),
            'hex': tx_info['hex'],
            'version': decoded.get('version'),
            'locktime': decoded.get('locktime'),
            'extra_payload_hex': tx_info['parsed'].get('extra_payload_hex'),
            **classification,
            'decoded': decoded,
        })

    pos_tail = parsed['pos_data']
    stake_source = None
    if pos_tail.get('stakepointer'):
        pointer = pos_tail['stakepointer']
        pointer_block = rpc('getblock', pointer['hash_block'])
        pointer_parsed, pointer_map, _ = tx_lookup_from_block(pointer['hash_block'])
        pointer_tx = pointer_map.get(pointer['txid'])
        pointer_vout = None
        if pointer_tx:
            vouts = pointer_tx['decoded'].get('vout', [])
            if isinstance(pointer['n_pos'], int) and 0 <= pointer['n_pos'] < len(vouts):
                pointer_vout = output_summary(vouts[pointer['n_pos']])
        stake_source = {
            'stakepointer_outpoint': f"{pointer['txid']}:{pointer['n_pos']}",
            'pointer_block_hash': pointer['hash_block'],
            'pointer_block_height': pointer_block.get('height'),
            'pointer_block_time': pointer_block.get('time'),
            'pointer_block_time_iso': maybe_iso(pointer_block.get('time')),
            'pointer_block_confirmations': pointer_block.get('confirmations'),
            'referenced_tx_found': pointer_tx is not None,
            'referenced_tx_hex': pointer_tx['hex'] if pointer_tx else None,
            'referenced_tx_decoded': pointer_tx['decoded'] if pointer_tx else None,
            'referenced_vout': pointer_vout,
            'age_blocks': (summary.get('height') - pointer_block.get('height')) if isinstance(summary.get('height'), int) and isinstance(pointer_block.get('height'), int) else None,
            'age_seconds': (summary.get('time') - pointer_block.get('time')) if isinstance(summary.get('time'), int) and isinstance(pointer_block.get('time'), int) else None,
            'pointer_block_tx_count': len(pointer_parsed['txs']),
        }

    masternode_payment = nonempty_payment(coinbase_outputs, 1)
    systemnode_payment = nonempty_payment(coinbase_outputs, 2)
    treasury_payments = [out for out in coinbase_outputs[3:] if out.get('value') not in (None, '0.00000000', 0, 0.0) or out.get('script_hex')]

    return {
        'hash': summary.get('hash'),
        'height': summary.get('height'),
        'time': summary.get('time'),
        'time_iso': maybe_iso(summary.get('time')),
        'previousblockhash': summary.get('previousblockhash'),
        'proof_type': proof_type,
        'chainwork': summary.get('chainwork'),
        'rpc_summary': summary,
        'raw_serialized': pos_tail,
        'transactions': transactions,
        'coinstake_reward_destination': coinstake_reward,
        'masternode_payment': masternode_payment,
        'systemnode_payment': systemnode_payment,
        'treasury_or_budget_payments': treasury_payments,
        'stake_source': stake_source,
    }

selected = fork_analysis.get('selected_pair') or {}
branches = fork_analysis.get('divergent_branches') or {}
active_branch = branches.get('active') or []
competing_branch = branches.get('competing') or []
terminal_active = active_branch[-2:] if len(active_branch) >= 2 else active_branch
terminal_competing = competing_branch[-2:] if len(competing_branch) >= 2 else competing_branch

analysis = {
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'selected_pair': selected,
    'common_ancestor': fork_analysis.get('common_ancestor'),
    'terminal_blocks': {'active': [], 'competing': []},
    'comparisons': {
        'per_height': [],
        'stake_source_reuse': {},
        'reward_structure_notes': [],
    },
    'limitations': [
        'This artifact uses archived block data plus RPC decoding from the local working copy only.',
        'Treasury/budget payment identification is based on observed coinbase output layout and may require code review for final interpretation.',
    ],
}

for side_name, chain in (('active', terminal_active), ('competing', terminal_competing)):
    for node in chain:
        analysis['terminal_blocks'][side_name].append(block_forensics(node['hash']))

active_by_height = {b['height']: b for b in analysis['terminal_blocks']['active'] if isinstance(b.get('height'), int)}
competing_by_height = {b['height']: b for b in analysis['terminal_blocks']['competing'] if isinstance(b.get('height'), int)}
all_stake_sources = {}
for side_name in ('active', 'competing'):
    for block in analysis['terminal_blocks'][side_name]:
        source = (block.get('stake_source') or {}).get('stakepointer_outpoint')
        if source:
            all_stake_sources.setdefault(source, []).append({'side': side_name, 'height': block.get('height'), 'hash': block.get('hash')})

analysis['comparisons']['stake_source_reuse'] = {
    'unique_outpoints': sorted(all_stake_sources),
    'reused_outpoints': {k: v for k, v in all_stake_sources.items() if len(v) > 1},
}

for height in sorted(set(active_by_height) & set(competing_by_height)):
    active_block = active_by_height[height]
    competing_block = competing_by_height[height]
    active_source = (active_block.get('stake_source') or {}).get('stakepointer_outpoint')
    competing_source = (competing_block.get('stake_source') or {}).get('stakepointer_outpoint')
    analysis['comparisons']['per_height'].append({
        'height': height,
        'active_hash': active_block.get('hash'),
        'competing_hash': competing_block.get('hash'),
        'active_time_iso': active_block.get('time_iso'),
        'competing_time_iso': competing_block.get('time_iso'),
        'same_chainwork': active_block.get('chainwork') == competing_block.get('chainwork'),
        'different_stake_source': active_source != competing_source,
        'active_stake_source': active_source,
        'competing_stake_source': competing_source,
        'active_coinstake_reward_destination': active_block.get('coinstake_reward_destination'),
        'competing_coinstake_reward_destination': competing_block.get('coinstake_reward_destination'),
        'active_masternode_payment': active_block.get('masternode_payment'),
        'competing_masternode_payment': competing_block.get('masternode_payment'),
        'active_systemnode_payment': active_block.get('systemnode_payment'),
        'competing_systemnode_payment': competing_block.get('systemnode_payment'),
        'active_treasury_or_budget_payments': active_block.get('treasury_or_budget_payments'),
        'competing_treasury_or_budget_payments': competing_block.get('treasury_or_budget_payments'),
    })

with open(out_path, 'w', encoding='utf-8') as fp:
    json.dump(analysis, fp, indent=2)
PY

if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
python3 - "$REPO_ROOT" "$FORK_HISTORY_JSON" <<'PY'
import json
import subprocess
import sys

repo_root, out_path = sys.argv[1:3]
terms = ['stakepointer', 'EMERGENCY_STAKEPOINTERS', 'reorg', 'fork', 'split', 'recovery', 'checkpoint']
focused_commits = [
    '0d70f38a42d695e0a22bc690c4194537f5a0857b',
    '361f5c574aff8de59e52f403d715986b53e6e355',
]
window_start = '2025-05-21'
window_end = '2025-08-31'

def run(args):
    try:
        return subprocess.check_output(args, text=True).strip()
    except Exception:
        return None

history = {
    'terms': {},
    'focused_commit': None,
    'focused_commits': {},
    'windowed_recovery_commits': [],
    'git_available': True,
    'errors': [],
}
for term in terms:
    cmd = ['git', '-C', repo_root, 'log', '--date=iso', '--pretty=format:%H%x09%ad%x09%an%x09%s', '-n', '25', '--grep', term, '--fixed-strings', '-i']
    out = run(cmd)
    rows = []
    if out is None:
        history['git_available'] = False
        history['errors'].append('git log unavailable for term search')
    elif out:
        for line in out.splitlines():
            parts = line.split('\t', 3)
            if len(parts) == 4:
                rows.append({'commit': parts[0], 'date': parts[1], 'author': parts[2], 'subject': parts[3]})
    history['terms'][term] = rows

for commit in focused_commits:
    subject = run(['git', '-C', repo_root, 'show', '-s', '--format=%H%x09%ad%x09%an%x09%s', '--date=iso', commit])
    files = run(['git', '-C', repo_root, 'show', '--format=', '--name-only', commit])
    patch = run([
        'git', '-C', repo_root, 'show', '--format=', '--unified=8', commit,
        '--', 'src/init.cpp', 'src/main.cpp', 'src/masternode.cpp', 'src/systemnode.cpp', 'src/wallet.cpp', '.github/workflows/main.yml'
    ])
    entry = {
        'summary': None,
        'changed_files': [line for line in (files or '').splitlines() if line.strip()],
        'focused_patch': patch.splitlines() if patch else [],
    }
    if subject:
        parts = subject.split('\t', 3)
        if len(parts) == 4:
            entry['summary'] = {'commit': parts[0], 'date': parts[1], 'author': parts[2], 'subject': parts[3]}
    history['focused_commits'][commit] = entry

window_query = run([
    'git', '-C', repo_root, 'log',
    '--since=' + window_start,
    '--until=' + window_end,
    '--date=iso',
    '--pretty=format:%H%x09%ad%x09%an%x09%s',
    '--grep=stakepointer|recovery|emergency|fork|reorg|checkpoint',
    '-E',
])
if window_query:
    for line in window_query.splitlines():
        parts = line.split('\t', 3)
        if len(parts) == 4:
            history['windowed_recovery_commits'].append({
                'commit': parts[0],
                'date': parts[1],
                'author': parts[2],
                'subject': parts[3],
            })

with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(history, f, indent=2)
PY
else
  python3 - "$FORK_HISTORY_JSON" <<'PY'
import json,sys
out_path=sys.argv[1]
history={'terms': {}, 'focused_commit': None, 'git_available': False, 'errors': []}
history['errors'].append('git executable not found or repository is not a git worktree')
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(history, f, indent=2)
PY
fi

python3 - "$CROWNCLI_BIN" "$DATADIR" "$(phase2_rpc_port "$DATADIR")" "$(phase2_rpc_user "$DATADIR")" "$(phase2_rpc_password "$DATADIR")" "$DATADIR/blocks" "$BEST_HASH" "$STABILITY_WINDOW_JSON" "$STABILITY_ANCHOR_UTC" "$STABILITY_LOOKBACK_DAYS" "$PROVISIONAL_SNAPSHOT_CUTOFF_UTC" "$PROVISIONAL_SNAPSHOT_HEIGHT" "$PROVISIONAL_SNAPSHOT_HASH" "$PROVISIONAL_SNAPSHOT_TIMESTAMP_UTC" <<'PY'
import collections
import datetime
import glob
import hashlib
import json
import os
import statistics
import struct
import subprocess
import sys

(
    crowncli, datadir, rpc_port, rpc_user, rpc_password,
    blocks_dir, best_hash, out_path, anchor_utc, lookback_days,
    provisional_cutoff_utc, provisional_height, provisional_hash, provisional_timestamp_utc,
) = sys.argv[1:15]
lookback_days = int(lookback_days)
provisional_height = int(provisional_height)
anchor_dt = datetime.datetime.strptime(anchor_utc, '%Y-%m-%dT%H:%M:%SZ')
anchor_ts = int(anchor_dt.replace(tzinfo=datetime.timezone.utc).timestamp())
window_seconds = lookback_days * 24 * 60 * 60
surround_seconds = 7 * 24 * 60 * 60
min_ts = anchor_ts - window_seconds
scan_min_ts = min_ts - surround_seconds
max_ts = anchor_ts + 24 * 60 * 60

def serialize_rpc_arg(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return 'null'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return value

def build_rpc_cmd(*rpc_args):
    cmd = [
        crowncli,
        f'-datadir={datadir}',
        '-rpcconnect=127.0.0.1',
        f'-rpcport={rpc_port}',
        f'-rpcuser={rpc_user}',
        f'-rpcpassword={rpc_password}',
    ] + [serialize_rpc_arg(a) for a in rpc_args]
    forbidden = [item for item in cmd if item in ('True', 'False')]
    if forbidden:
        raise ValueError(f'forbidden Python bool literal in crown-cli argv: {forbidden}')
    return cmd

smoke_cmd = build_rpc_cmd('getblock', '00' * 32, False)
smoke_rawtx_cmd = build_rpc_cmd('getrawtransaction', '00' * 32, 1)
if smoke_cmd[-1] != 'false' or 'True' in smoke_cmd or 'False' in smoke_cmd:
    raise ValueError(f'getblock argv serialization regression: {smoke_cmd}')
if smoke_rawtx_cmd[-1] != '1' or 'True' in smoke_rawtx_cmd or 'False' in smoke_rawtx_cmd:
    raise ValueError(f'getrawtransaction argv serialization regression: {smoke_rawtx_cmd}')

def rpc(*args):
    cmd = build_rpc_cmd(*args)
    out = subprocess.check_output(cmd, text=True)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out.strip()

def maybe_iso(ts):
    if isinstance(ts, int):
        return datetime.datetime.utcfromtimestamp(ts).isoformat() + 'Z'
    return None

def dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def le_uint256_hex(raw):
    return raw[::-1].hex()

def scan_recent_headers():
    recent = {}
    errors = []
    for path in sorted(glob.glob(os.path.join(blocks_dir, 'blk*.dat'))):
        with open(path, 'rb') as f:
            while True:
                offset = f.tell()
                prefix = f.read(8)
                if not prefix:
                    break
                if len(prefix) < 8:
                    errors.append(f'{os.path.basename(path)}:{offset}: truncated block-file prefix')
                    break
                size = struct.unpack('<I', prefix[4:8])[0]
                payload = f.read(size)
                if len(payload) != size:
                    errors.append(f'{os.path.basename(path)}:{offset}: truncated block payload ({len(payload)} of {size})')
                    break
                if len(payload) < 80:
                    continue
                header = payload[:80]
                ts = struct.unpack_from('<I', header, 68)[0]
                if ts < scan_min_ts or ts > max_ts:
                    continue
                block_hash = dsha256(header)[::-1].hex()
                recent[block_hash] = {
                    'hash': block_hash,
                    'prev': le_uint256_hex(header[4:36]),
                    'time': ts,
                    'time_iso': maybe_iso(ts),
                    'version': struct.unpack_from('<I', header, 0)[0],
                    'file': os.path.basename(path),
                    'offset': offset,
                    'size_bytes': size,
                }
    return recent, errors

def get_active_window(best_hash):
    active = []
    active_map = {}
    current = best_hash
    while current:
        block = rpc('getblock', current)
        entry = {
            'hash': block.get('hash'),
            'height': block.get('height'),
            'time': block.get('time'),
            'time_iso': maybe_iso(block.get('time')),
            'previousblockhash': block.get('previousblockhash'),
            'chainwork': block.get('chainwork'),
            'proof_type': block.get('proof_type'),
        }
        active.append(entry)
        active_map[entry['hash']] = entry
        if not isinstance(entry['time'], int) or entry['time'] < scan_min_ts or not entry.get('previousblockhash'):
            break
        current = entry['previousblockhash']
    active.reverse()
    return active, active_map

recent_headers, scan_errors = scan_recent_headers()
active_recent, active_map = get_active_window(best_hash)
recent_non_active = {h: rec for h, rec in recent_headers.items() if h not in active_map and rec.get('time') is not None}
non_active_prev_hashes = {rec['prev'] for rec in recent_non_active.values() if rec.get('prev')}

rpc_cache = {}
def rpc_block(block_hash):
    if block_hash not in rpc_cache:
        try:
            rpc_cache[block_hash] = rpc('getblock', block_hash)
        except Exception:
            rpc_cache[block_hash] = None
    return rpc_cache[block_hash]

def enrich_record(record):
    block = rpc_block(record['hash'])
    enriched = dict(record)
    if block is not None:
        enriched.update({
            'height': block.get('height'),
            'chainwork': block.get('chainwork'),
            'proof_type': block.get('proof_type'),
            'confirmations': block.get('confirmations'),
        })
    else:
        enriched.update({
            'height': None,
            'chainwork': None,
            'proof_type': None,
            'confirmations': None,
            'rpc_unavailable': True,
        })
    return enriched

def resolve_branch(tip_record):
    branch = []
    seen = set()
    current = tip_record
    common_ancestor = None
    while current and current['hash'] not in seen:
        seen.add(current['hash'])
        enriched = enrich_record(current)
        branch.append(enriched)
        prev_hash = current.get('prev')
        if not prev_hash:
            break
        if prev_hash in active_map:
            common_ancestor = active_map[prev_hash]
            break
        if prev_hash in recent_non_active:
            current = recent_non_active[prev_hash]
            continue
        fallback = rpc_block(prev_hash)
        if fallback is None:
            break
        fallback_record = {
            'hash': fallback.get('hash'),
            'prev': fallback.get('previousblockhash'),
            'time': fallback.get('time'),
            'time_iso': maybe_iso(fallback.get('time')),
            'version': fallback.get('version'),
            'file': None,
            'offset': None,
            'size_bytes': None,
        }
        if fallback.get('confirmations', -1) > 0:
            common_ancestor = {
                'hash': fallback.get('hash'),
                'height': fallback.get('height'),
                'time': fallback.get('time'),
                'time_iso': maybe_iso(fallback.get('time')),
                'chainwork': fallback.get('chainwork'),
                'proof_type': fallback.get('proof_type'),
            }
            break
        current = fallback_record

    branch.reverse()
    tip = branch[-1] if branch else enrich_record(tip_record)
    active_competitor = None
    if isinstance(tip.get('height'), int):
        active_competitor = next((b for b in active_recent if b.get('height') == tip['height']), None)
    return {
        'tip': tip,
        'common_ancestor': common_ancestor,
        'branchlen': len(branch),
        'blocks': branch,
        'active_competitor_at_tip_height': active_competitor,
    }

branch_tips = []
for record in recent_non_active.values():
    if record['hash'] in non_active_prev_hashes:
        continue
    if not isinstance(record.get('time'), int) or record['time'] < min_ts or record['time'] > max_ts:
        continue
    branch_tips.append(resolve_branch(record))

branch_tips.sort(key=lambda b: (b['tip'].get('time') or 0, b['tip'].get('height') or -1, b['tip'].get('hash') or ''))

active_window = [b for b in active_recent if isinstance(b.get('time'), int) and min_ts <= b['time'] <= anchor_ts]
intervals = []
for prev, cur in zip(active_window, active_window[1:]):
    delta = cur['time'] - prev['time']
    intervals.append({
        'from_height': prev.get('height'),
        'to_height': cur.get('height'),
        'from_hash': prev.get('hash'),
        'to_hash': cur.get('hash'),
        'from_time_iso': prev.get('time_iso'),
        'to_time_iso': cur.get('time_iso'),
        'delta_seconds': delta,
    })
median_gap = int(statistics.median([x['delta_seconds'] for x in intervals])) if intervals else None
long_gap_threshold = max(6 * 60 * 60, (median_gap or 0) * 3) if median_gap is not None else 6 * 60 * 60
long_gaps = [gap for gap in intervals if gap['delta_seconds'] >= long_gap_threshold]

daily_counts = collections.Counter()
for block in active_window:
    daily_counts[block['time_iso'][:10]] += 1
median_daily_blocks = statistics.median(daily_counts.values()) if daily_counts else None
daily_rate_anomalies = []
if median_daily_blocks:
    for day, count in sorted(daily_counts.items()):
        if count < (median_daily_blocks / 2):
            daily_rate_anomalies.append({'date': day, 'blocks': count, 'median_blocks_per_day': median_daily_blocks})

def nearby_branch(branch, block_time):
    times = []
    if isinstance(branch['tip'].get('time'), int):
        times.append(branch['tip']['time'])
    if branch.get('common_ancestor') and isinstance(branch['common_ancestor'].get('time'), int):
        times.append(branch['common_ancestor']['time'])
    return any(abs(t - block_time) <= surround_seconds for t in times)

def nearby_gap(gap, block_time):
    return abs(datetime.datetime.strptime(gap['to_time_iso'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp() - block_time) <= surround_seconds

def candidate_at(label, target_utc):
    target_ts = int(datetime.datetime.strptime(target_utc, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())
    block = None
    for item in active_window:
        if item['time'] <= target_ts:
            block = item
        else:
            break
    if block is None:
        return None
    branches = [b for b in branch_tips if nearby_branch(b, block['time'])]
    gaps = [g for g in long_gaps if nearby_gap(g, block['time'])]
    fork_depths = [b['branchlen'] for b in branches]
    uncontested = not any(
        b.get('active_competitor_at_tip_height') and b['active_competitor_at_tip_height'].get('height') == block.get('height')
        for b in branches
    )
    if not branches and not gaps:
        confidence = 'high'
        reason = 'No nearby competing branch tips or long-gap anomalies were observed in the surrounding 7-day window.'
    elif max(fork_depths, default=0) <= 1 and len(gaps) == 0:
        confidence = 'medium'
        reason = 'Only shallow nearby branch activity was observed and no long-gap anomaly was detected.'
    else:
        confidence = 'low'
        reason = 'Nearby competing branch activity or long-gap anomalies are present in the surrounding 7-day window.'
    return {
        'label': label,
        'selection_rule': 'last active-chain block at or before requested_cutoff_utc',
        'requested_cutoff_utc': target_utc,
        'height': block.get('height'),
        'hash': block.get('hash'),
        'timestamp_utc': block.get('time_iso'),
        'resolved_block_precedes_cutoff_by_seconds': target_ts - block.get('time'),
        'chainwork': block.get('chainwork'),
        'lies_on_uncontested_active_ancestry': uncontested,
        'nearby_competing_forks': [
            {
                'tip_height': b['tip'].get('height'),
                'tip_hash': b['tip'].get('hash'),
                'tip_time_utc': b['tip'].get('time_iso'),
                'branchlen': b.get('branchlen'),
                'common_ancestor_height': (b.get('common_ancestor') or {}).get('height'),
                'common_ancestor_hash': (b.get('common_ancestor') or {}).get('hash'),
            }
            for b in branches
        ],
        'surrounding_window_fork_count': len(branches),
        'surrounding_window_max_fork_depth': max(fork_depths, default=0),
        'nearby_long_block_gaps': gaps,
        'confidence': confidence,
        'reason': reason,
    }

required_candidates = [
    candidate_at('last_active_block_at_or_before_2025-08-01T23:59:59Z', '2025-08-01T23:59:59Z'),
    candidate_at('last_active_block_at_or_before_2025-07-01T23:59:59Z', '2025-07-01T23:59:59Z'),
]
required_candidates = [c for c in required_candidates if c is not None]

anomaly_timestamps = []
anomaly_timestamps.extend([b['tip']['time'] for b in branch_tips if isinstance(b['tip'].get('time'), int)])
anomaly_timestamps.extend([
    int(datetime.datetime.strptime(g['to_time_iso'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())
    for g in long_gaps
])
suggested_candidate = None
if anomaly_timestamps:
    earliest_anomaly = min(anomaly_timestamps)
    probe_time = earliest_anomaly - 1
    for item in active_window:
        if item['time'] <= probe_time:
            suggested_candidate = item
        else:
            break
if suggested_candidate is not None:
    auto_candidate = candidate_at('last_active_block_before_detected_instability', suggested_candidate['time_iso'])
    if auto_candidate and auto_candidate['hash'] not in {c['hash'] for c in required_candidates}:
        required_candidates.append(auto_candidate)

provisional_snapshot_candidate = candidate_at('provisional_legacy_holder_revival_snapshot', provisional_cutoff_utc)
provisional_snapshot_decision = {
    'status': 'fixed',
    'purpose': 'provisional economic/holder entitlement reference point only',
    'selection_rule': 'last active-chain block at or before 2025-07-01T23:59:59Z',
    'resolved_block': {
        'height': provisional_height,
        'hash': provisional_hash,
        'timestamp_utc': provisional_timestamp_utc,
        'chainwork': provisional_snapshot_candidate.get('chainwork') if provisional_snapshot_candidate else None,
    },
    'decision_reasons': [
        'lies on uncontested active ancestry',
        'no detected competing forks in the surrounding audit window',
        'no nearby long-block-gap anomaly',
        'active-chain production around this period was normal',
        'materially predates the late-July/August degradation, prolonged stalls, terminal equal-chainwork fork, and later emergency stakepointer recovery work',
    ],
    'explicit_non_goals': [
        'does not truncate historical Crown chain recovery at this height',
        'does not declare later historical blocks invalid',
        'does not choose either terminal August fork as canonical',
        'does not automatically determine which addresses or UTXOs are eligible',
    ],
    'follow_on_phases': {
        'phase2b': 'Reconstruct the UTXO/holder distribution at exactly height 5420279.',
        'phase2c': [
            'masternode/systemnode collateral',
            'treasury/project-controlled funds',
            'known exchange/custody holdings',
            'wrapped-CRW reserve/custody UTXOs',
            'other special categories needed to prevent double entitlement',
        ],
    },
    'tooling_note': 'Snapshot candidate records now carry both requested_cutoff_utc and resolved block timestamp so a nominal date label cannot be mistaken for exact same-day block production.',
}
if provisional_snapshot_candidate is not None:
    provisional_snapshot_decision['candidate_evidence'] = provisional_snapshot_candidate
    provisional_snapshot_decision['resolved_block_matches_expected'] = (
        provisional_snapshot_candidate.get('height') == provisional_height
        and provisional_snapshot_candidate.get('hash') == provisional_hash
        and provisional_snapshot_candidate.get('timestamp_utc') == provisional_timestamp_utc
    )
else:
    provisional_snapshot_decision['candidate_evidence'] = None
    provisional_snapshot_decision['resolved_block_matches_expected'] = False

analysis = {
    'generated_at_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'analysis_window': {
        'anchor_utc': anchor_utc,
        'lookback_days': lookback_days,
        'window_start_utc': maybe_iso(min_ts),
        'surrounding_window_days': 7,
    },
    'active_chain_window': {
        'block_count': len(active_window),
        'first_block': active_window[0] if active_window else None,
        'last_block': active_window[-1] if active_window else None,
        'median_block_gap_seconds': median_gap,
        'long_gap_threshold_seconds': long_gap_threshold,
    },
    'fork_activity': {
        'competing_branch_tips': branch_tips,
        'branch_count': len(branch_tips),
        'max_branch_depth': max((b['branchlen'] for b in branch_tips), default=0),
    },
    'reorg_indicators': [
        {
            'tip_height': b['tip'].get('height'),
            'tip_hash': b['tip'].get('hash'),
            'tip_time_utc': b['tip'].get('time_iso'),
            'branchlen': b.get('branchlen'),
            'common_ancestor_height': (b.get('common_ancestor') or {}).get('height'),
            'active_competitor_hash': (b.get('active_competitor_at_tip_height') or {}).get('hash'),
        }
        for b in branch_tips
    ],
    'block_production_rate': {
        'blocks_per_day': dict(sorted(daily_counts.items())),
        'median_blocks_per_day': median_daily_blocks,
        'daily_rate_anomalies': daily_rate_anomalies,
    },
    'long_block_gaps': long_gaps,
    'stakepointer_or_pos_anomalies_detectable': [
        'Terminal competing branches remain PoS and should be cross-referenced with phase2-terminal-fork-forensics.json for stake-source outpoint differences.',
        'This windowed analysis focuses on fork timing, depth, and active-chain block cadence rather than a full stakepointer decode of every recent block.',
    ],
    'provisional_revival_snapshot_decision': provisional_snapshot_decision,
    'snapshot_candidates': required_candidates,
    'scan_diagnostics': {
        'recent_header_count': len(recent_headers),
        'recent_non_active_header_count': len(recent_non_active),
        'scan_errors': scan_errors,
    },
    'limitations': [
        'Competing-branch detection in this artifact is derived from recent block-file headers plus RPC height lookups; it does not treat any external network as canonical.',
        'Historical reorgs are reconstructable only to the extent that competing blocks remain present in the preserved archive.',
        'A requested calendar cutoff may resolve to an earlier block when the chain had already stalled; use requested_cutoff_utc together with timestamp_utc when interpreting snapshot candidates.',
    ],
}

with open(out_path, 'w', encoding='utf-8') as fp:
    json.dump(analysis, fp, indent=2)
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
stability_window=json.load(open(f"{outdir}/phase2-stability-window-analysis.json"))

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
    'analysis_artifacts': {
        'fork_analysis_file': f"{outdir}/phase2-fork-analysis.json",
        'fork_history_file': f"{outdir}/phase2-fork-history-evidence.json",
        'terminal_fork_forensics_file': f"{outdir}/phase2-terminal-fork-forensics.json",
        'stability_window_file': f"{outdir}/phase2-stability-window-analysis.json",
    },
    'phase2a_project_decisions': {
        'provisional_revival_snapshot': stability_window.get('provisional_revival_snapshot_decision'),
    },
    'limitations': [
        'This script does not calculate historical issuance; it records reproducible baseline inputs for later Phase 2 calculations.',
        'The provisional snapshot decision defines the economic reference point only; Phase 2B/2C still determine distribution and exclusions at that exact height.',
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
log "Output: $TERMINAL_FORK_JSON"
log "Output: $STABILITY_WINDOW_JSON"
