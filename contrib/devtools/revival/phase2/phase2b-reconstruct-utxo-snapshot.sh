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
  - --datadir must point to a disposable Phase 2 working copy (never preserved source, never archive).
  - Networking is disabled; reconstruction/export is local only.
USAGE
}

DATADIR=""
OUTDIR=""
ARCHIVE_NAME="crown-old-chain.7z"
ARCHIVE_SHA256="56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0"
EXPECTED_MAINNET_GENESIS="0000000085370d5e122f64f4ab19c68614ff3df78c8d13cb814fd7e69a1dc6da"
SNAPSHOT_HEIGHT="5420279"
SNAPSHOT_HASH="8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed"
SNAPSHOT_TIMESTAMP_UTC="2025-07-01T23:59:24Z"
SNAPSHOT_CHAINWORK="00000000000000000000000000000000000000000055f92a16848adbe0b66cbe"

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
  OUTDIR="$(dirname "$DATADIR")/$(basename "$DATADIR").phase2b-output"
fi
OUTDIR="$(abs_path "$OUTDIR")"
mkdir -p "$OUTDIR"

METADATA_JSON="$OUTDIR/phase2b-snapshot-metadata.json"
UTXO_JSONL="$OUTDIR/phase2b-utxos.jsonl"
UTXO_CSV="$OUTDIR/phase2b-utxos.csv"
BALANCES_CSV="$OUTDIR/phase2b-address-script-balances.csv"
BALANCES_JSON="$OUTDIR/phase2b-address-script-balances.json"
DISTRIBUTION_JSON="$OUTDIR/phase2b-distribution-summary.json"
BLOCKCHAININFO_JSON="$OUTDIR/blockchaininfo-after-reconstruction.json"
TXOUTSETINFO_JSON="$OUTDIR/txoutsetinfo-after-reconstruction.json"
SNAPSHOT_BLOCK_JSON="$OUTDIR/snapshot-block.json"
CHAINTIPS_JSON="$OUTDIR/chaintips-after-reconstruction.json"
EXPORT_RPC_RESULT_JSON="$OUTDIR/exportutxosnapshot-result.json"
RECONSTRUCTION_AUDIT_JSON="$OUTDIR/phase2b-reconstruction-audit.json"

cleanup() {
  stop_crownd "$DATADIR"
}
trap cleanup EXIT

log "Starting Phase 2B reconstruction against disposable copy: $DATADIR"
start_crownd "$DATADIR" -testnet=0 -regtest=0 -staking=0 -listen=0 -dnsseed=0 -dns=0 -discover=0 -upnp=0 -maxconnections=0 -onlynet=ipv4 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1
wait_rpc_ready "$DATADIR" 300 || die "crownd RPC did not become ready for Phase 2B"

GENESIS_HASH="$(rpc "$DATADIR" getblockhash 0)"
CHAIN_NAME="$(rpc "$DATADIR" getblockchaininfo | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chain",""))')"
BEST_HASH_BEFORE="$(rpc "$DATADIR" getbestblockhash)"
BEST_HEIGHT_BEFORE="$(rpc "$DATADIR" getblockcount)"

[ "$CHAIN_NAME" = "main" ] || die "Refusing Phase 2B: expected chain=main but got chain=${CHAIN_NAME:-UNKNOWN}"
[ "$GENESIS_HASH" = "$EXPECTED_MAINNET_GENESIS" ] || die "Refusing Phase 2B: expected genesis=$EXPECTED_MAINNET_GENESIS but got $GENESIS_HASH"

ACTIVE_HASH_AT_SNAPSHOT_HEIGHT="$(rpc "$DATADIR" getblockhash "$SNAPSHOT_HEIGHT" 2>/dev/null || true)"
[ "$ACTIVE_HASH_AT_SNAPSHOT_HEIGHT" = "$SNAPSHOT_HASH" ] || die "Snapshot identity mismatch on active chain at height $SNAPSHOT_HEIGHT (expected $SNAPSHOT_HASH, got ${ACTIVE_HASH_AT_SNAPSHOT_HEIGHT:-MISSING})"

RECONSTRUCTION_METHOD="already_at_snapshot_tip"
RECONSTRUCTION_DETAIL="bestblock already equals selected snapshot hash"
INVALIDATED_BLOCK=""

if [ "$BEST_HASH_BEFORE" != "$SNAPSHOT_HASH" ]; then
  [ "$BEST_HEIGHT_BEFORE" -gt "$SNAPSHOT_HEIGHT" ] || die "Current best height ($BEST_HEIGHT_BEFORE) is below/equal snapshot height ($SNAPSHOT_HEIGHT) but best hash differs"
  NEXT_HEIGHT=$((SNAPSHOT_HEIGHT + 1))
  INVALIDATED_BLOCK="$(rpc "$DATADIR" getblockhash "$NEXT_HEIGHT" 2>/dev/null || true)"
  [ -n "$INVALIDATED_BLOCK" ] || die "Failed to resolve active-chain block at height $NEXT_HEIGHT for deterministic rollback"
  rpc "$DATADIR" invalidateblock "$INVALIDATED_BLOCK" >/dev/null
  RECONSTRUCTION_METHOD="invalidateblock_active_child"
  RECONSTRUCTION_DETAIL="invalidated active-chain child at height ${NEXT_HEIGHT} to rewind tip to selected snapshot"
fi

BEST_HASH_AFTER="$(rpc "$DATADIR" getbestblockhash)"
BEST_HEIGHT_AFTER="$(rpc "$DATADIR" getblockcount)"
[ "$BEST_HASH_AFTER" = "$SNAPSHOT_HASH" ] || die "Reconstruction failed closed: best hash after rewind is $BEST_HASH_AFTER (expected $SNAPSHOT_HASH)"
[ "$BEST_HEIGHT_AFTER" = "$SNAPSHOT_HEIGHT" ] || die "Reconstruction failed: best height after rewind is $BEST_HEIGHT_AFTER (expected $SNAPSHOT_HEIGHT)"

rpc "$DATADIR" getchaintips > "$CHAINTIPS_JSON"
rpc "$DATADIR" getblockchaininfo > "$BLOCKCHAININFO_JSON"
rpc "$DATADIR" getblock "$SNAPSHOT_HASH" > "$SNAPSHOT_BLOCK_JSON"

python3 - "$CHAINTIPS_JSON" "$SNAPSHOT_HASH" <<'PY'
import json
import sys

tips = json.load(open(sys.argv[1], encoding="utf-8"))
snapshot_hash = sys.argv[2].lower()
active = [t for t in tips if t.get("status") == "active"]
if len(active) != 1:
    raise SystemExit("expected exactly one active chain tip")
if (active[0].get("hash") or "").lower() != snapshot_hash:
    raise SystemExit("active tip hash does not match selected snapshot hash")
PY

python3 - "$SNAPSHOT_BLOCK_JSON" "$SNAPSHOT_HEIGHT" "$SNAPSHOT_HASH" "$SNAPSHOT_TIMESTAMP_UTC" "$SNAPSHOT_CHAINWORK" <<'PY'
import datetime
import json
import sys

block = json.load(open(sys.argv[1], encoding="utf-8"))
expected_height = int(sys.argv[2])
expected_hash = sys.argv[3].lower()
expected_timestamp_utc = sys.argv[4]
expected_chainwork = sys.argv[5].lower()

observed_height = int(block.get("height", -1))
observed_hash = (block.get("hash") or "").lower()
observed_chainwork = (block.get("chainwork") or "").lower()
observed_time = int(block.get("time", -1))
observed_timestamp_utc = datetime.datetime.utcfromtimestamp(observed_time).isoformat() + "Z" if observed_time >= 0 else ""

if observed_height != expected_height:
    raise SystemExit(f"snapshot height mismatch: expected {expected_height}, got {observed_height}")
if observed_hash != expected_hash:
    raise SystemExit(f"snapshot hash mismatch: expected {expected_hash}, got {observed_hash}")
if observed_timestamp_utc != expected_timestamp_utc:
    raise SystemExit(f"snapshot timestamp mismatch: expected {expected_timestamp_utc}, got {observed_timestamp_utc}")
if observed_chainwork != expected_chainwork:
    raise SystemExit(f"snapshot chainwork mismatch: expected {expected_chainwork}, got {observed_chainwork}")
PY

if ! rpc "$DATADIR" gettxoutsetinfo > "$TXOUTSETINFO_JSON" 2>/dev/null; then
  die "gettxoutsetinfo RPC failed at reconstructed snapshot state"
fi

if ! rpc "$DATADIR" exportutxosnapshot "$UTXO_JSONL" > "$EXPORT_RPC_RESULT_JSON" 2>/dev/null; then
  die "exportutxosnapshot RPC failed"
fi

TOOLING_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
BINARY_VERSION="$("$CROWND_BIN" --version | head -n1 | sed 's/[[:space:]]*$//')"

python3 - "$OUTDIR" "$UTXO_JSONL" "$UTXO_CSV" "$BALANCES_CSV" "$BALANCES_JSON" "$DISTRIBUTION_JSON" "$METADATA_JSON" "$RECONSTRUCTION_AUDIT_JSON" "$EXPORT_RPC_RESULT_JSON" "$TXOUTSETINFO_JSON" "$BLOCKCHAININFO_JSON" "$SNAPSHOT_BLOCK_JSON" "$SNAPSHOT_HEIGHT" "$SNAPSHOT_HASH" "$SNAPSHOT_TIMESTAMP_UTC" "$SNAPSHOT_CHAINWORK" "$ARCHIVE_NAME" "$ARCHIVE_SHA256" "$TOOLING_COMMIT" "$BINARY_VERSION" "$RECONSTRUCTION_METHOD" "$RECONSTRUCTION_DETAIL" "$INVALIDATED_BLOCK" <<'PY'
import csv
import datetime
import hashlib
import json
import math
import statistics
import sys
from collections import defaultdict
from decimal import Decimal, ROUND_DOWN

(
    outdir,
    utxo_jsonl_path,
    utxo_csv_path,
    balances_csv_path,
    balances_json_path,
    distribution_json_path,
    metadata_json_path,
    reconstruction_audit_json_path,
    export_result_path,
    txoutsetinfo_path,
    blockchaininfo_path,
    snapshot_block_path,
    snapshot_height,
    snapshot_hash,
    snapshot_timestamp_utc,
    snapshot_chainwork,
    archive_name,
    archive_sha256,
    tooling_commit,
    binary_version,
    reconstruction_method,
    reconstruction_detail,
    invalidated_block_hash,
) = sys.argv[1:24]

COIN = 100_000_000
snapshot_height = int(snapshot_height)


def to_sats(amount_value):
    if isinstance(amount_value, (int,)):
        return int(amount_value)
    d = Decimal(str(amount_value))
    return int((d * COIN).to_integral_value(rounding=ROUND_DOWN))


def crw_str_from_sats(sats):
    whole = sats // COIN
    frac = sats % COIN
    return f"{whole}.{frac:08d}"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


export_result = json.load(open(export_result_path, encoding="utf-8"))
txoutsetinfo = json.load(open(txoutsetinfo_path, encoding="utf-8"))
blockchaininfo = json.load(open(blockchaininfo_path, encoding="utf-8"))
snapshot_block = json.load(open(snapshot_block_path, encoding="utf-8"))

if (blockchaininfo.get("chain") or "") != "main":
    raise SystemExit("chain identity is not main at export time")

if int(export_result.get("height", -1)) != snapshot_height:
    raise SystemExit("export height does not match snapshot height")
if (export_result.get("bestblock") or "").lower() != snapshot_hash.lower():
    raise SystemExit("export bestblock does not match snapshot hash")
if int(txoutsetinfo.get("height", -1)) != snapshot_height:
    raise SystemExit("txoutsetinfo height does not match snapshot height")
if (txoutsetinfo.get("bestblock") or "").lower() != snapshot_hash.lower():
    raise SystemExit("txoutsetinfo bestblock does not match snapshot hash")

utxo_count = 0
utxo_total_sat = 0
address_bearing_outputs = 0
without_single_standard_address = 0
script_type_stats = defaultdict(lambda: {"utxo_count": 0, "value_sat": 0})
entity_balances = {}

with open(utxo_csv_path, "w", newline="", encoding="utf-8") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow([
        "txid",
        "vout",
        "outpoint",
        "value_sat",
        "value_crw",
        "script_type",
        "script_pub_key_hex",
        "addresses",
        "address_count",
        "single_standard_address",
        "creation_height",
        "is_block_reward",
        "block_reward_type_hint",
        "matches_historical_masternode_collateral_amount",
        "matches_historical_systemnode_collateral_amount",
    ])

    with open(utxo_jsonl_path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            txid = record["txid"]
            vout = int(record["vout"])
            outpoint = record.get("outpoint") or f"{txid}:{vout}"
            value_sat = int(record["value_sats"])
            value_crw = crw_str_from_sats(value_sat)
            script_type = record.get("script_type") or "nonstandard"
            script_hex = record.get("script_pub_key_hex") or ""
            addresses = record.get("addresses") or []
            address_count = int(record.get("address_count", len(addresses)))
            single_standard_address = bool(record.get("single_standard_address", False))
            creation_height = int(record.get("creation_height", -1))
            is_block_reward = bool(record.get("is_block_reward", False))
            block_reward_type_hint = record.get("block_reward_type_hint") or "none"
            mn_flag = bool(record.get("matches_historical_masternode_collateral_amount", value_sat == 10000 * COIN))
            sn_flag = bool(record.get("matches_historical_systemnode_collateral_amount", value_sat == 500 * COIN))

            if creation_height < 0 or creation_height > snapshot_height:
                raise SystemExit(f"invalid creation height at line {line_no}: {creation_height}")

            utxo_count += 1
            utxo_total_sat += value_sat
            script_type_stats[script_type]["utxo_count"] += 1
            script_type_stats[script_type]["value_sat"] += value_sat

            if address_count > 0:
                address_bearing_outputs += 1
            if not single_standard_address:
                without_single_standard_address += 1

            if single_standard_address and address_count == 1:
                entity_key = f"addr:{addresses[0]}"
                entity_kind = "address"
                entity_label = addresses[0]
                script_ref = None
            else:
                script_id = hashlib.sha256(bytes.fromhex(script_hex)).hexdigest() if script_hex else hashlib.sha256(b"").hexdigest()
                entity_key = f"script:{script_id}"
                entity_kind = "script"
                entity_label = script_id
                script_ref = script_hex

            if entity_key not in entity_balances:
                entity_balances[entity_key] = {
                    "entity": entity_label,
                    "entity_kind": entity_kind,
                    "script_identifier": entity_label if entity_kind == "script" else None,
                    "script_pub_key_hex": script_ref,
                    "script_type": script_type,
                    "utxo_count": 0,
                    "balance_sat": 0,
                    "candidate_masternode_collateral_utxos": 0,
                    "candidate_systemnode_collateral_utxos": 0,
                }
            entity_row = entity_balances[entity_key]
            entity_row["utxo_count"] += 1
            entity_row["balance_sat"] += value_sat
            if mn_flag:
                entity_row["candidate_masternode_collateral_utxos"] += 1
            if sn_flag:
                entity_row["candidate_systemnode_collateral_utxos"] += 1

            writer.writerow([
                txid,
                vout,
                outpoint,
                value_sat,
                value_crw,
                script_type,
                script_hex,
                "|".join(addresses),
                address_count,
                "true" if single_standard_address else "false",
                creation_height,
                "true" if is_block_reward else "false",
                block_reward_type_hint,
                "true" if mn_flag else "false",
                "true" if sn_flag else "false",
            ])

entities = list(entity_balances.values())
entities.sort(key=lambda r: (-r["balance_sat"], r["entity"]))

for row in entities:
    row["balance_crw"] = crw_str_from_sats(int(row["balance_sat"]))

with open(balances_csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "entity_kind",
        "entity",
        "script_identifier",
        "script_type",
        "utxo_count",
        "balance_sat",
        "balance_crw",
        "candidate_masternode_collateral_utxos",
        "candidate_systemnode_collateral_utxos",
    ])
    for row in entities:
        writer.writerow([
            row["entity_kind"],
            row["entity"],
            row["script_identifier"] or "",
            row["script_type"],
            row["utxo_count"],
            row["balance_sat"],
            row["balance_crw"],
            row["candidate_masternode_collateral_utxos"],
            row["candidate_systemnode_collateral_utxos"],
        ])

json.dump(
    {
        "snapshot_height": snapshot_height,
        "snapshot_hash": snapshot_hash,
        "entities": entities,
    },
    open(balances_json_path, "w", encoding="utf-8"),
    indent=2,
)

txoutset_total_sat = to_sats(txoutsetinfo.get("total_amount"))
export_total_sat = to_sats(export_result.get("exported_total_amount"))
export_chainstate_total_sat = to_sats(export_result.get("chainstate_total_amount"))
export_count = int(export_result.get("utxos_exported", -1))
export_chainstate_count = int(export_result.get("chainstate_txouts", -1))

checks = {
    "utxo_count_matches_export_result": utxo_count == export_count,
    "utxo_count_matches_chainstate": utxo_count == export_chainstate_count and utxo_count == int(txoutsetinfo.get("txouts", -1)),
    "total_sat_matches_export_result": utxo_total_sat == export_total_sat,
    "total_sat_matches_export_chainstate": utxo_total_sat == export_chainstate_total_sat,
    "total_sat_matches_txoutsetinfo": utxo_total_sat == txoutset_total_sat,
}
if not all(checks.values()):
    raise SystemExit(f"reconciliation failed: {checks}")

balances = [int(r["balance_sat"]) for r in entities]
entity_count = len(balances)
mean_sat = int(utxo_total_sat / entity_count) if entity_count else 0
median_sat = int(statistics.median(balances)) if entity_count else 0

def share_for_top(n):
    if entity_count == 0 or utxo_total_sat == 0:
        return {"entity_count": min(n, entity_count), "balance_sat": 0, "share": "0"}
    top_balance = sum(balances[: min(n, entity_count)])
    share = Decimal(top_balance) / Decimal(utxo_total_sat)
    return {
        "entity_count": min(n, entity_count),
        "balance_sat": int(top_balance),
        "share": format(share, "f"),
    }

band_defs = [
    ("<1 CRW", 0, 1 * COIN),
    ("1-10 CRW", 1 * COIN, 10 * COIN),
    ("10-100 CRW", 10 * COIN, 100 * COIN),
    ("100-500 CRW", 100 * COIN, 500 * COIN),
    ("500-1,000 CRW", 500 * COIN, 1_000 * COIN),
    ("1,000-5,000 CRW", 1_000 * COIN, 5_000 * COIN),
    ("5,000-10,000 CRW", 5_000 * COIN, 10_000 * COIN),
    ("10,000-50,000 CRW", 10_000 * COIN, 50_000 * COIN),
    ("50,000-100,000 CRW", 50_000 * COIN, 100_000 * COIN),
    ("100,000+ CRW", 100_000 * COIN, None),
]

bands = []
for label, low, high in band_defs:
    count = 0
    value = 0
    for b in balances:
        if b < low:
            continue
        if high is not None and b >= high:
            continue
        count += 1
        value += b
    bands.append(
        {
            "band": label,
            "entity_count": count,
            "balance_sat": int(value),
            "balance_crw": crw_str_from_sats(int(value)),
            "share_of_total": format((Decimal(value) / Decimal(utxo_total_sat)) if utxo_total_sat else Decimal(0), "f"),
        }
    )

curve_points = []
milestones = sorted({1, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, entity_count})
running = 0
for rank, bal in enumerate(balances, 1):
    running += bal
    if rank in milestones:
        curve_points.append(
            {
                "rank": rank,
                "cumulative_balance_sat": int(running),
                "cumulative_balance_crw": crw_str_from_sats(int(running)),
                "cumulative_share": format((Decimal(running) / Decimal(utxo_total_sat)) if utxo_total_sat else Decimal(0), "f"),
            }
        )

script_type_summary = []
for script_type in sorted(script_type_stats):
    row = script_type_stats[script_type]
    script_type_summary.append(
        {
            "script_type": script_type,
            "utxo_count": int(row["utxo_count"]),
            "value_sat": int(row["value_sat"]),
            "value_crw": crw_str_from_sats(int(row["value_sat"])),
        }
    )

largest_balances = [
    {
        "rank": i + 1,
        "entity_kind": row["entity_kind"],
        "entity": row["entity"],
        "balance_sat": int(row["balance_sat"]),
        "balance_crw": row["balance_crw"],
    }
    for i, row in enumerate(entities[:100])
]

distribution_summary = {
    "snapshot": {
        "height": snapshot_height,
        "hash": snapshot_hash,
        "timestamp_utc": snapshot_timestamp_utc,
        "chainwork": snapshot_chainwork,
    },
    "reconciliation": {
        "status": "pass",
        "checks": checks,
        "exported_utxo_count": utxo_count,
        "exported_total_sat": int(utxo_total_sat),
        "exported_total_crw": crw_str_from_sats(int(utxo_total_sat)),
        "chainstate_utxo_count": int(txoutsetinfo.get("txouts", 0)),
        "chainstate_total_sat": int(txoutset_total_sat),
        "chainstate_total_crw": crw_str_from_sats(int(txoutset_total_sat)),
    },
    "output_classification_counts": {
        "standard_address_bearing_outputs": int(address_bearing_outputs),
        "outputs_without_single_standard_address": int(without_single_standard_address),
    },
    "script_type_summary": script_type_summary,
    "entities": {
        "unique_entities": entity_count,
        "mean_balance_sat": int(mean_sat),
        "mean_balance_crw": crw_str_from_sats(int(mean_sat)),
        "median_balance_sat": int(median_sat),
        "median_balance_crw": crw_str_from_sats(int(median_sat)),
        "top_10_share": share_for_top(10),
        "top_100_share": share_for_top(100),
        "top_1000_share": share_for_top(1000),
    },
    "balance_bands": bands,
    "largest_balances": largest_balances,
    "cumulative_concentration_curve": curve_points,
}

json.dump(distribution_summary, open(distribution_json_path, "w", encoding="utf-8"), indent=2)

reconstruction_audit = {
    "snapshot": {
        "height": snapshot_height,
        "hash": snapshot_hash,
        "timestamp_utc": snapshot_timestamp_utc,
        "chainwork": snapshot_chainwork,
    },
    "reconstruction_method": reconstruction_method,
    "reconstruction_detail": reconstruction_detail,
    "invalidated_block_hash": invalidated_block_hash or None,
    "chain_identity": {
        "chain": blockchaininfo.get("chain"),
        "bestblockhash": blockchaininfo.get("bestblockhash"),
        "blocks": blockchaininfo.get("blocks"),
        "headers": blockchaininfo.get("headers"),
    },
    "snapshot_block": {
        "hash": snapshot_block.get("hash"),
        "height": snapshot_block.get("height"),
        "time": snapshot_block.get("time"),
        "chainwork": snapshot_block.get("chainwork"),
    },
    "export_result": export_result,
    "txoutsetinfo": txoutsetinfo,
}
json.dump(reconstruction_audit, open(reconstruction_audit_json_path, "w", encoding="utf-8"), indent=2)

artifact_paths = [
    utxo_jsonl_path,
    utxo_csv_path,
    balances_csv_path,
    balances_json_path,
    distribution_json_path,
    reconstruction_audit_json_path,
    export_result_path,
    txoutsetinfo_path,
]
artifacts = []
for path in artifact_paths:
    artifacts.append(
        {
            "path": path,
            "size_bytes": int(__import__("os").path.getsize(path)),
            "sha256": sha256_file(path),
        }
    )

metadata = {
    "snapshot": {
        "selection_rule": "last active-chain block at or before 2025-07-01T23:59:59Z",
        "height": snapshot_height,
        "hash": snapshot_hash,
        "timestamp_utc": snapshot_timestamp_utc,
        "chainwork": snapshot_chainwork,
    },
    "archive_provenance": {
        "archive_name": archive_name,
        "archive_sha256": archive_sha256.upper(),
    },
    "code_provenance": {
        "crown_audit_binary_version": binary_version,
        "crown_audit_binary_git_commit": tooling_commit,
        "tooling_git_commit": tooling_commit,
    },
    "generation": {
        "generated_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "reconstruction_method": reconstruction_method,
        "reconstruction_detail": reconstruction_detail,
    },
    "validation": {
        "chain_identity_main": blockchaininfo.get("chain") == "main",
        "bestblock_matches_snapshot": (blockchaininfo.get("bestblockhash") or "").lower() == snapshot_hash.lower(),
        "reconciliation_status": "pass",
        "checks": checks,
    },
    "artifacts": artifacts,
}
json.dump(metadata, open(metadata_json_path, "w", encoding="utf-8"), indent=2)
PY

log "Phase 2B snapshot export complete."
log "Metadata: $METADATA_JSON"
log "UTXO JSONL: $UTXO_JSONL"
log "UTXO CSV: $UTXO_CSV"
log "Aggregation CSV: $BALANCES_CSV"
log "Distribution summary: $DISTRIBUTION_JSON"
