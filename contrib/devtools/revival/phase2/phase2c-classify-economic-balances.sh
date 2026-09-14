#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage:
  $0 \
    --balances-jsonl <phase2b-address-script-balances.jsonl> \
    --distribution-json <phase2b-distribution-summary.json> \
    --metadata-json <phase2b-snapshot-metadata.json> \
    --audit-json <phase2b-reconstruction-audit.json> \
    [--attribution-json <phase2c-attribution-overrides.json>] \
    [--outdir <output_dir>] \
    [--expected-archive-sha256 <hex>] \
    [--expected-raw-export-commit <git_commit>] \
    [--expected-utxo-jsonl-sha256 <hex>]

Notes:
  - Post-processing only. Does not start crownd, does not mutate chainstate, and does not call RPC.
  - Uses integer satoshi arithmetic for all reconciliation and concentration metrics.
USAGE
}

BALANCES_JSONL=""
DISTRIBUTION_JSON=""
METADATA_JSON=""
AUDIT_JSON=""
ATTRIBUTION_JSON=""
OUTDIR=""

EXPECTED_ARCHIVE_SHA256="56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0"
EXPECTED_RAW_EXPORT_COMMIT="516e2eb694cb73c9b14fcbff2eaf02d8a47329a3"
EXPECTED_UTXO_JSONL_SHA256="99AF0EFC2026F58805E0219A13CCA5007309FE9DB380D0A559D0D245504B6C7F"
EXPECTED_TOTAL_CRW="34010803.11042473"
EXPECTED_POSITIVE_ENTITIES="17999"
EXPECTED_500_COUNT="2302"
EXPECTED_10000_COUNT="1239"
EXPECTED_HEIGHT="5420279"
EXPECTED_HASH="8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed"
EXPECTED_TIMESTAMP="2025-07-01T23:59:24Z"

while [ $# -gt 0 ]; do
  case "$1" in
    --balances-jsonl)
      BALANCES_JSONL="${2:-}"; shift 2 ;;
    --distribution-json)
      DISTRIBUTION_JSON="${2:-}"; shift 2 ;;
    --metadata-json)
      METADATA_JSON="${2:-}"; shift 2 ;;
    --audit-json)
      AUDIT_JSON="${2:-}"; shift 2 ;;
    --attribution-json)
      ATTRIBUTION_JSON="${2:-}"; shift 2 ;;
    --outdir)
      OUTDIR="${2:-}"; shift 2 ;;
    --expected-archive-sha256)
      EXPECTED_ARCHIVE_SHA256="${2:-}"; shift 2 ;;
    --expected-raw-export-commit)
      EXPECTED_RAW_EXPORT_COMMIT="${2:-}"; shift 2 ;;
    --expected-utxo-jsonl-sha256)
      EXPECTED_UTXO_JSONL_SHA256="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[phase2c][error] Unknown argument: $1" >&2
      exit 1 ;;
  esac
done

[ -n "$BALANCES_JSONL" ] || { usage; echo "[phase2c][error] --balances-jsonl is required" >&2; exit 1; }
[ -n "$DISTRIBUTION_JSON" ] || { usage; echo "[phase2c][error] --distribution-json is required" >&2; exit 1; }
[ -n "$METADATA_JSON" ] || { usage; echo "[phase2c][error] --metadata-json is required" >&2; exit 1; }
[ -n "$AUDIT_JSON" ] || { usage; echo "[phase2c][error] --audit-json is required" >&2; exit 1; }

BALANCES_JSONL="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$BALANCES_JSONL")"
DISTRIBUTION_JSON="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$DISTRIBUTION_JSON")"
METADATA_JSON="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$METADATA_JSON")"
AUDIT_JSON="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$AUDIT_JSON")"

[ -f "$BALANCES_JSONL" ] || { echo "[phase2c][error] Missing balances JSONL: $BALANCES_JSONL" >&2; exit 1; }
[ -f "$DISTRIBUTION_JSON" ] || { echo "[phase2c][error] Missing distribution JSON: $DISTRIBUTION_JSON" >&2; exit 1; }
[ -f "$METADATA_JSON" ] || { echo "[phase2c][error] Missing metadata JSON: $METADATA_JSON" >&2; exit 1; }
[ -f "$AUDIT_JSON" ] || { echo "[phase2c][error] Missing audit JSON: $AUDIT_JSON" >&2; exit 1; }

if [ -n "$ATTRIBUTION_JSON" ]; then
  ATTRIBUTION_JSON="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$ATTRIBUTION_JSON")"
  [ -f "$ATTRIBUTION_JSON" ] || { echo "[phase2c][error] Missing attribution JSON: $ATTRIBUTION_JSON" >&2; exit 1; }
fi

if [ -z "$OUTDIR" ]; then
  OUTDIR="$(dirname "$BALANCES_JSONL")"
fi
OUTDIR="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTDIR")"
mkdir -p "$OUTDIR"

python3 - "$BALANCES_JSONL" "$DISTRIBUTION_JSON" "$METADATA_JSON" "$AUDIT_JSON" "$ATTRIBUTION_JSON" "$OUTDIR" "$EXPECTED_ARCHIVE_SHA256" "$EXPECTED_RAW_EXPORT_COMMIT" "$EXPECTED_UTXO_JSONL_SHA256" "$EXPECTED_TOTAL_CRW" "$EXPECTED_POSITIVE_ENTITIES" "$EXPECTED_500_COUNT" "$EXPECTED_10000_COUNT" "$EXPECTED_HEIGHT" "$EXPECTED_HASH" "$EXPECTED_TIMESTAMP" <<'PY'
import datetime
import hashlib
import json
import os
import sys
from decimal import Decimal, ROUND_DOWN, getcontext

getcontext().prec = 80
COIN = 100_000_000

(
    balances_jsonl_path,
    distribution_json_path,
    metadata_json_path,
    audit_json_path,
    attribution_json_path,
    outdir,
    expected_archive_sha256,
    expected_raw_export_commit,
    expected_utxo_jsonl_sha256,
    expected_total_crw,
    expected_positive_entities,
    expected_500_count,
    expected_10000_count,
    expected_height,
    expected_hash,
    expected_timestamp,
) = sys.argv[1:17]

expected_total_sat = int((Decimal(expected_total_crw) * COIN).to_integral_value(rounding=ROUND_DOWN))
expected_positive_entities = int(expected_positive_entities)
expected_500_count = int(expected_500_count)
expected_10000_count = int(expected_10000_count)
expected_height = int(expected_height)

CATEGORIES = {
    "ordinary holder",
    "Masternode collateral",
    "Systemnode collateral",
    "exchange/custody",
    "Wrapped Crown reserve/custody",
    "stranded/inaccessible wrapped backing",
    "burn/unspendable if provable",
    "other identifiable special-purpose",
    "unknown",
}

CONFIDENCE = {"CONFIRMED", "HIGH CONFIDENCE", "PROBABLE", "POSSIBLE", "UNKNOWN"}
WRAPPED_STATUS = {
    "ACTIVE / REDEEMABLE",
    "BACKED BUT STRANDED",
    "PARTIALLY VERIFIABLE",
    "UNVERIFIABLE",
    "INCONSISTENT / UNBACKED",
    "UNKNOWN",
}


def crw_from_sats(sats: int) -> str:
    sign = "-" if sats < 0 else ""
    abs_sat = abs(sats)
    whole = abs_sat // COIN
    frac = abs_sat % COIN
    return f"{sign}{whole}.{frac:08d}"


def share_str(num: int, den: int) -> str:
    if den <= 0:
        return "0"
    return format(Decimal(num) / Decimal(den), "f")


def percent_str(num: int, den: int) -> str:
    if den <= 0:
        return "0"
    return format((Decimal(num) * Decimal(100)) / Decimal(den), "f")


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalize_confidence(value: str) -> str:
    if value in CONFIDENCE:
        return value
    raise SystemExit(f"invalid confidence value: {value}")


def normalize_category(value: str) -> str:
    if value in CATEGORIES:
        return value
    raise SystemExit(f"invalid category value: {value}")


distribution = load_json(distribution_json_path)
metadata = load_json(metadata_json_path)
audit = load_json(audit_json_path)

attribution = {}
if attribution_json_path:
    attribution = load_json(attribution_json_path)

checks = {}

snapshot = distribution.get("snapshot") or {}
checks["snapshot_height_matches_expected"] = int(snapshot.get("height", -1)) == expected_height
checks["snapshot_hash_matches_expected"] = str(snapshot.get("hash", "")).lower() == expected_hash.lower()
checks["snapshot_timestamp_matches_expected"] = str(snapshot.get("timestamp_utc", "")) == expected_timestamp

archive_sha = ((metadata.get("archive_provenance") or {}).get("archive_sha256") or "").upper()
checks["archive_sha256_matches_expected"] = archive_sha == expected_archive_sha256.upper()

raw_meta = metadata.get("raw_export") or {}
raw_audit = audit.get("raw_export") or {}
meta_commit = str(raw_meta.get("audit_binary_git_commit") or "").strip()
audit_commit = str(raw_audit.get("audit_binary_git_commit") or "").strip()
checks["raw_export_commit_matches_expected"] = (meta_commit == expected_raw_export_commit and audit_commit == expected_raw_export_commit)

meta_jsonl_sha = str(raw_meta.get("utxo_jsonl_sha256") or "").upper()
audit_jsonl_sha = str(((raw_audit.get("utxo_jsonl") or {}).get("sha256") or "")).upper()
checks["utxo_jsonl_sha256_matches_expected"] = (meta_jsonl_sha == expected_utxo_jsonl_sha256.upper() and audit_jsonl_sha == expected_utxo_jsonl_sha256.upper())

utxo_totals = distribution.get("utxo_totals") or {}
entity_summary = distribution.get("entity_summary") or {}
raw_collateral = distribution.get("collateral_sized_raw_utxos") or {}

checks["snapshot_total_sat_matches_expected"] = int(utxo_totals.get("total_value_sat", -1)) == expected_total_sat
checks["positive_entity_count_matches_expected"] = int(entity_summary.get("unique_positive_balance_entities", -1)) == expected_positive_entities
checks["raw_500_count_matches_expected"] = int(((raw_collateral.get("500_crw") or {}).get("utxo_count", -1))) == expected_500_count
checks["raw_10000_count_matches_expected"] = int(((raw_collateral.get("10000_crw") or {}).get("utxo_count", -1))) == expected_10000_count

if not all(checks.values()):
    fail_path = os.path.join(outdir, "phase2c-summary.json")
    payload = {
        "status": "fail",
        "phase2b_input_verified": "NO",
        "checks": checks,
        "required_report": {
            "PHASE_2B_INPUT_VERIFIED": "NO",
            "TOTAL_SNAPSHOT_CRW": crw_from_sats(expected_total_sat),
        },
    }
    with open(fail_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    raise SystemExit(f"Phase 2C input verification failed; see {fail_path}")

entity_overrides = attribution.get("entity_overrides") or []
control_entities_input = attribution.get("control_entities") or []
wrapped_override = attribution.get("wrapped_crown_analysis") or None

override_map = {}
for idx, item in enumerate(entity_overrides):
    ek = item.get("entity_kind")
    ent = item.get("entity")
    if ek not in {"address", "script"} or not isinstance(ent, str) or ent == "":
        raise SystemExit(f"invalid entity_overrides[{idx}] entity reference")
    key = f"{ek}:{ent}"
    if key in override_map:
        raise SystemExit(f"duplicate override for {key}")

    override = {
        "category": normalize_category(item.get("category", "unknown")),
        "confidence": normalize_confidence(item.get("confidence", "UNKNOWN")),
        "evidence": item.get("evidence") or ["No supporting evidence provided."],
        "unresolved_questions": item.get("unresolved_questions") or [],
        "control_entity_id": item.get("control_entity_id"),
        "node_collateral_label": item.get("node_collateral_label"),
        "node_collateral_confidence": item.get("node_collateral_confidence"),
        "notes": item.get("notes"),
    }
    if not isinstance(override["evidence"], list) or not all(isinstance(x, str) and x.strip() for x in override["evidence"]):
        raise SystemExit(f"invalid evidence list for override {key}")
    if override["node_collateral_confidence"] is not None:
        override["node_collateral_confidence"] = normalize_confidence(str(override["node_collateral_confidence"]))
    if override["node_collateral_label"] is not None and not isinstance(override["node_collateral_label"], str):
        raise SystemExit(f"invalid node_collateral_label for override {key}")
    override_map[key] = override

entity_rows = []
sha256 = hashlib.sha256()

with open(balances_jsonl_path, "rb") as f:
    for line_no, raw in enumerate(f, 1):
        sha256.update(raw)
        payload = raw.decode("utf-8").strip()
        if payload == "":
            continue
        row = json.loads(payload)
        ek = row.get("entity_kind")
        ent = row.get("entity")
        if ek not in {"address", "script"}:
            raise SystemExit(f"invalid entity_kind on line {line_no}")
        if not isinstance(ent, str) or ent == "":
            raise SystemExit(f"invalid entity on line {line_no}")

        balance_sat = int(row.get("balance_sat", 0))
        if balance_sat <= 0:
            continue

        c500 = int(row.get("candidate_500_utxo_count", 0))
        c10k = int(row.get("candidate_10000_utxo_count", 0))
        utxo_count = int(row.get("utxo_count", 0))

        collateral_sat = c500 * 500 * COIN + c10k * 10_000 * COIN
        if collateral_sat > balance_sat:
            raise SystemExit(f"collateral sat exceeds entity balance for {ek}:{ent}")

        key = f"{ek}:{ent}"
        override = override_map.get(key)

        category = "unknown"
        confidence = "UNKNOWN"
        evidence = ["No direct attribution evidence supplied for this entity in Phase 2C inputs."]
        unresolved_questions = ["Attribution evidence needed to classify beyond collateral-size heuristics."]

        if override is not None:
            category = override["category"]
            confidence = override["confidence"]
            evidence = override["evidence"]
            unresolved_questions = override["unresolved_questions"]

        if c500 == 0 and c10k == 0 and category == "unknown":
            unresolved_questions = ["No collateral-sized outputs; owner type remains unknown without external attribution."]

        node_collateral = {
            "masternode": {
                "candidate_utxo_count_10000": c10k,
                "candidate_value_sat": c10k * 10_000 * COIN,
                "candidate_value_crw": crw_from_sats(c10k * 10_000 * COIN),
                "assessment": "collateral-sized but unconfirmed" if c10k > 0 else "none observed",
                "confidence": "POSSIBLE" if c10k > 0 else "UNKNOWN",
            },
            "systemnode": {
                "candidate_utxo_count_500": c500,
                "candidate_value_sat": c500 * 500 * COIN,
                "candidate_value_crw": crw_from_sats(c500 * 500 * COIN),
                "assessment": "collateral-sized but unconfirmed" if c500 > 0 else "none observed",
                "confidence": "POSSIBLE" if c500 > 0 else "UNKNOWN",
            },
            "notes": "Numerical collateral-size evidence alone cannot prove active/owned node role.",
        }

        if override is not None and override.get("node_collateral_label"):
            label = override["node_collateral_label"]
            nconf = override.get("node_collateral_confidence") or confidence
            if "masternode" in label.lower():
                node_collateral["masternode"]["assessment"] = label
                node_collateral["masternode"]["confidence"] = nconf
            if "systemnode" in label.lower():
                node_collateral["systemnode"]["assessment"] = label
                node_collateral["systemnode"]["confidence"] = nconf

        entity_rows.append(
            {
                "entity_kind": ek,
                "entity": ent,
                "balance_sat": balance_sat,
                "balance_crw": crw_from_sats(balance_sat),
                "snapshot_share": share_str(balance_sat, expected_total_sat),
                "snapshot_percent": percent_str(balance_sat, expected_total_sat),
                "utxo_count": utxo_count,
                "candidate_10000_utxo_count": c10k,
                "candidate_500_utxo_count": c500,
                "collateral_sized_total_sat": collateral_sat,
                "collateral_sized_total_crw": crw_from_sats(collateral_sat),
                "collateral_percent_of_entity_balance": percent_str(collateral_sat, balance_sat),
                "classification": {
                    "category": category,
                    "confidence": confidence,
                    "evidence": evidence,
                    "unresolved_questions": unresolved_questions,
                    "control_entity_id": override.get("control_entity_id") if override else None,
                    "notes": override.get("notes") if override else None,
                },
                "node_collateral_assessment": node_collateral,
            }
        )

entity_rows.sort(key=lambda x: (-x["balance_sat"], x["entity_kind"], x["entity"]))
entity_lookup = {f"{x['entity_kind']}:{x['entity']}": x for x in entity_rows}

if len(entity_rows) != expected_positive_entities:
    raise SystemExit(f"positive-entity row mismatch: expected={expected_positive_entities} parsed={len(entity_rows)}")

recomputed_total_sat = sum(x["balance_sat"] for x in entity_rows)
if recomputed_total_sat != expected_total_sat:
    raise SystemExit(f"balance sum mismatch: expected={expected_total_sat} parsed={recomputed_total_sat}")

recomputed_500 = sum(x["candidate_500_utxo_count"] for x in entity_rows)
recomputed_10000 = sum(x["candidate_10000_utxo_count"] for x in entity_rows)
if recomputed_500 != expected_500_count:
    raise SystemExit(f"500-count mismatch: expected={expected_500_count} parsed={recomputed_500}")
if recomputed_10000 != expected_10000_count:
    raise SystemExit(f"10000-count mismatch: expected={expected_10000_count} parsed={recomputed_10000}")

category_totals = {}
for row in entity_rows:
    cat = row["classification"]["category"]
    category_totals.setdefault(cat, {"entity_count": 0, "balance_sat": 0})
    category_totals[cat]["entity_count"] += 1
    category_totals[cat]["balance_sat"] += row["balance_sat"]

category_total_sat = sum(v["balance_sat"] for v in category_totals.values())
if category_total_sat != expected_total_sat:
    raise SystemExit("category totals do not reconcile to snapshot total")

classification_registry = {
    "snapshot": {
        "height": expected_height,
        "hash": expected_hash,
        "timestamp_utc": expected_timestamp,
        "total_value_sat": expected_total_sat,
        "total_value_crw": crw_from_sats(expected_total_sat),
        "positive_balance_entities": expected_positive_entities,
    },
    "provenance_verification": {
        "phase2b_input_verified": "YES",
        "expected_archive_sha256": expected_archive_sha256.upper(),
        "expected_raw_export_commit": expected_raw_export_commit,
        "expected_utxo_jsonl_sha256": expected_utxo_jsonl_sha256.upper(),
        "checks": checks,
        "balances_jsonl_sha256": sha256.hexdigest().upper(),
    },
    "category_totals": [
        {
            "category": cat,
            "entity_count": stats["entity_count"],
            "balance_sat": stats["balance_sat"],
            "balance_crw": crw_from_sats(stats["balance_sat"]),
            "snapshot_share": share_str(stats["balance_sat"], expected_total_sat),
            "snapshot_percent": percent_str(stats["balance_sat"], expected_total_sat),
        }
        for cat, stats in sorted(category_totals.items(), key=lambda kv: (-kv[1]["balance_sat"], kv[0]))
    ],
    "entities": entity_rows,
}

collateral_holders = [x for x in entity_rows if x["candidate_500_utxo_count"] > 0 or x["candidate_10000_utxo_count"] > 0]


def collateral_row(row):
    return {
        "entity_kind": row["entity_kind"],
        "entity": row["entity"],
        "total_balance_sat": row["balance_sat"],
        "total_balance_crw": row["balance_crw"],
        "candidate_10000_utxo_count": row["candidate_10000_utxo_count"],
        "candidate_500_utxo_count": row["candidate_500_utxo_count"],
        "collateral_sized_total_sat": row["collateral_sized_total_sat"],
        "collateral_sized_total_crw": row["collateral_sized_total_crw"],
        "collateral_percent_of_total_balance": row["collateral_percent_of_entity_balance"],
        "classification_category": row["classification"]["category"],
        "classification_confidence": row["classification"]["confidence"],
        "evidence": row["classification"]["evidence"],
    }

rank_by_10k = sorted(collateral_holders, key=lambda x: (-x["candidate_10000_utxo_count"], -x["balance_sat"], x["entity"]))
rank_by_500 = sorted(collateral_holders, key=lambda x: (-x["candidate_500_utxo_count"], -x["balance_sat"], x["entity"]))
rank_by_total = sorted(collateral_holders, key=lambda x: (-x["balance_sat"], -x["candidate_10000_utxo_count"], -x["candidate_500_utxo_count"], x["entity"]))

collateral_concentration = {
    "snapshot": classification_registry["snapshot"],
    "summary": {
        "collateral_holding_entity_count": len(collateral_holders),
        "collateral_holding_balance_sat": sum(x["balance_sat"] for x in collateral_holders),
        "collateral_holding_balance_crw": crw_from_sats(sum(x["balance_sat"] for x in collateral_holders)),
        "collateral_holding_balance_snapshot_percent": percent_str(sum(x["balance_sat"] for x in collateral_holders), expected_total_sat),
        "raw_candidate_500_utxo_count": recomputed_500,
        "raw_candidate_10000_utxo_count": recomputed_10000,
    },
    "largest_holders_of_10000_utxos": [collateral_row(x) for x in rank_by_10k if x["candidate_10000_utxo_count"] > 0][:100],
    "largest_holders_of_500_utxos": [collateral_row(x) for x in rank_by_500 if x["candidate_500_utxo_count"] > 0][:100],
    "largest_total_balances_among_collateral_holders": [collateral_row(x) for x in rank_by_total][:100],
}


def top_entity_record(rank, row):
    return {
        "rank": rank,
        "entity_kind": row["entity_kind"],
        "entity": row["entity"],
        "balance_sat": row["balance_sat"],
        "balance_crw": row["balance_crw"],
        "snapshot_percent": row["snapshot_percent"],
        "utxo_count": row["utxo_count"],
        "candidate_10000_utxo_count": row["candidate_10000_utxo_count"],
        "candidate_500_utxo_count": row["candidate_500_utxo_count"],
        "likely_category": row["classification"]["category"],
        "confidence": row["classification"]["confidence"],
        "evidence": row["classification"]["evidence"],
        "unresolved_questions": row["classification"]["unresolved_questions"],
        "collateral_sized_total_crw": row["collateral_sized_total_crw"],
        "collateral_percent_of_total_balance": row["collateral_percent_of_entity_balance"],
    }


top100 = [top_entity_record(i + 1, row) for i, row in enumerate(entity_rows[:100])]

mandatory_largest_entities = []
if len(top100) >= 1:
    mandatory_largest_entities.append(
        {
            "rank": top100[0]["rank"],
            "entity_kind": top100[0]["entity_kind"],
            "entity": top100[0]["entity"],
            "balance_crw": top100[0]["balance_crw"],
            "note": "Mandatory priority entity #1 analyzed in top_20_detailed.",
        }
    )
if len(top100) >= 2:
    mandatory_largest_entities.append(
        {
            "rank": top100[1]["rank"],
            "entity_kind": top100[1]["entity_kind"],
            "entity": top100[1]["entity"],
            "balance_crw": top100[1]["balance_crw"],
            "note": "Mandatory priority entity #2 analyzed in top_20_detailed.",
        }
    )

top_balances_report = {
    "snapshot": classification_registry["snapshot"],
    "top_20_detailed": top100[:20],
    "top_100_entities": top100,
    "mandatory_largest_entities": mandatory_largest_entities,
}

confirmed_or_probable_mn = []
confirmed_or_probable_sn = []
unconfirmed_collateral = []

for row in collateral_holders:
    mn = row["node_collateral_assessment"]["masternode"]
    sn = row["node_collateral_assessment"]["systemnode"]

    if row["candidate_10000_utxo_count"] > 0 and mn["assessment"] != "collateral-sized but unconfirmed" and mn["confidence"] in {"CONFIRMED", "HIGH CONFIDENCE", "PROBABLE"}:
        confirmed_or_probable_mn.append(collateral_row(row))
    if row["candidate_500_utxo_count"] > 0 and sn["assessment"] != "collateral-sized but unconfirmed" and sn["confidence"] in {"CONFIRMED", "HIGH CONFIDENCE", "PROBABLE"}:
        confirmed_or_probable_sn.append(collateral_row(row))

    if (row["candidate_10000_utxo_count"] > 0 and mn["assessment"] == "collateral-sized but unconfirmed") or (
        row["candidate_500_utxo_count"] > 0 and sn["assessment"] == "collateral-sized but unconfirmed"
    ):
        unconfirmed_collateral.append(
            {
                **collateral_row(row),
                "masternode_assessment": mn["assessment"],
                "masternode_confidence": mn["confidence"],
                "systemnode_assessment": sn["assessment"],
                "systemnode_confidence": sn["confidence"],
            }
        )

node_collateral_analysis = {
    "snapshot": classification_registry["snapshot"],
    "summary": {
        "confirmed_or_probable_masternode_entities": len(confirmed_or_probable_mn),
        "confirmed_or_probable_systemnode_entities": len(confirmed_or_probable_sn),
        "collateral_sized_unconfirmed_entities": len(unconfirmed_collateral),
    },
    "confirmed_or_probable_masternode_collateral": confirmed_or_probable_mn,
    "confirmed_or_probable_systemnode_collateral": confirmed_or_probable_sn,
    "collateral_sized_but_unconfirmed": unconfirmed_collateral,
}

exchange_entries = [
    {
        "entity_kind": row["entity_kind"],
        "entity": row["entity"],
        "balance_sat": row["balance_sat"],
        "balance_crw": row["balance_crw"],
        "snapshot_percent": row["snapshot_percent"],
        "confidence": row["classification"]["confidence"],
        "evidence": row["classification"]["evidence"],
        "unresolved_questions": row["classification"]["unresolved_questions"],
    }
    for row in entity_rows
    if row["classification"]["category"] in {"exchange/custody", "Wrapped Crown reserve/custody", "stranded/inaccessible wrapped backing"}
]

exchange_custody_analysis = {
    "snapshot": classification_registry["snapshot"],
    "summary": {
        "classified_exchange_or_wrapped_entities": len(exchange_entries),
        "classified_exchange_or_wrapped_balance_sat": sum(x["balance_sat"] for x in exchange_entries),
        "classified_exchange_or_wrapped_balance_crw": crw_from_sats(sum(x["balance_sat"] for x in exchange_entries)),
    },
    "entities": exchange_entries,
    "notes": [
        "Only evidence-backed overrides are promoted to exchange/custody or wrapped categories.",
        "Absent direct evidence, entities remain category 'unknown'.",
    ],
}

member_to_control = {}
for idx, group in enumerate(control_entities_input):
    gid = group.get("id")
    members = group.get("members") or []
    if not isinstance(gid, str) or gid == "":
        raise SystemExit(f"invalid control_entities[{idx}].id")
    if not isinstance(members, list) or len(members) == 0:
        raise SystemExit(f"control_entities[{idx}] requires non-empty members")
    for m in members:
        mek = m.get("entity_kind")
        ment = m.get("entity")
        if mek not in {"address", "script"} or not isinstance(ment, str) or ment == "":
            raise SystemExit(f"invalid control_entities[{idx}] member")
        key = f"{mek}:{ment}"
        if key in member_to_control:
            raise SystemExit(f"entity listed in multiple control entities: {key}")
        member_to_control[key] = gid

control_groups = []
for group in control_entities_input:
    gid = group["id"]
    glabel = group.get("label") or gid
    gcat = normalize_category(group.get("category", "other identifiable special-purpose"))
    gconf = normalize_confidence(group.get("confidence", "UNKNOWN"))
    gevidence = group.get("evidence") or ["No control evidence supplied."]
    if not isinstance(gevidence, list) or not all(isinstance(x, str) and x.strip() for x in gevidence):
        raise SystemExit(f"invalid evidence on control group {gid}")

    members = []
    total = 0
    total_collateral = 0
    seen_keys = set()
    for m in group.get("members"):
        key = f"{m['entity_kind']}:{m['entity']}"
        if key in seen_keys:
            raise SystemExit(f"duplicate member within control group {gid}: {key}")
        seen_keys.add(key)
        row = entity_lookup.get(key)
        if row is None:
            raise SystemExit(f"control group {gid} references unknown entity {key}")
        members.append({
            "entity_kind": row["entity_kind"],
            "entity": row["entity"],
            "balance_sat": row["balance_sat"],
            "balance_crw": row["balance_crw"],
            "candidate_10000_utxo_count": row["candidate_10000_utxo_count"],
            "candidate_500_utxo_count": row["candidate_500_utxo_count"],
        })
        total += row["balance_sat"]
        total_collateral += row["collateral_sized_total_sat"]

    control_groups.append(
        {
            "id": gid,
            "label": glabel,
            "category": gcat,
            "confidence": gconf,
            "evidence": gevidence,
            "member_count": len(members),
            "total_balance_sat": total,
            "total_balance_crw": crw_from_sats(total),
            "snapshot_percent": percent_str(total, expected_total_sat),
            "total_collateral_sized_sat": total_collateral,
            "total_collateral_sized_crw": crw_from_sats(total_collateral),
            "members": members,
        }
    )

control_entities = {
    "snapshot": classification_registry["snapshot"],
    "group_count": len(control_groups),
    "groups": sorted(control_groups, key=lambda x: (-x["total_balance_sat"], x["id"])),
    "ungrouped_entity_count": len(entity_rows) - len(member_to_control),
}

if wrapped_override is None:
    wrapped_status = "UNKNOWN"
    wrapped_crown_analysis = {
        "snapshot": classification_registry["snapshot"],
        "classification": {
            "status": wrapped_status,
            "confidence": "UNKNOWN",
            "evidence": [
                "No wrapped-Crown reserve mapping, contract provenance, or redemption-key evidence supplied in Phase 2C attribution inputs.",
            ],
        },
        "reserve_entities": [],
        "reported_wrapped_supply": None,
        "reported_native_backing_sat": None,
        "supply_backing_delta_sat": None,
        "potential_double_entitlement_risk": {
            "status": "UNKNOWN",
            "details": "Cannot quantify without verifiable wrapped-supply and reserve-address evidence.",
        },
        "unresolved_questions": [
            "Identify authoritative wrapped contract(s) and mint/burn authority history.",
            "Identify native CRW reserve address set backing wrapped supply.",
            "Determine whether redemption keys remain available.",
        ],
    }
else:
    wrapped_status = wrapped_override.get("status", "UNKNOWN")
    if wrapped_status not in WRAPPED_STATUS:
        raise SystemExit(f"invalid wrapped_crown_analysis.status: {wrapped_status}")
    wrapped_conf = normalize_confidence(wrapped_override.get("confidence", "UNKNOWN"))
    wrapped_evidence = wrapped_override.get("evidence") or ["No wrapped evidence supplied."]
    if not isinstance(wrapped_evidence, list) or not all(isinstance(x, str) and x.strip() for x in wrapped_evidence):
        raise SystemExit("invalid wrapped_crown_analysis.evidence")

    reserve_entities = wrapped_override.get("reserve_entities") or []
    if not isinstance(reserve_entities, list):
        raise SystemExit("wrapped_crown_analysis.reserve_entities must be a list")
    reserve_rows = []
    reserve_total = 0
    for r in reserve_entities:
        rek = r.get("entity_kind")
        re = r.get("entity")
        if rek not in {"address", "script"} or not isinstance(re, str) or re == "":
            raise SystemExit("invalid wrapped reserve entity reference")
        key = f"{rek}:{re}"
        row = entity_lookup.get(key)
        if row is None:
            raise SystemExit(f"wrapped reserve references unknown entity: {key}")
        reserve_rows.append({
            "entity_kind": row["entity_kind"],
            "entity": row["entity"],
            "balance_sat": row["balance_sat"],
            "balance_crw": row["balance_crw"],
            "snapshot_percent": row["snapshot_percent"],
        })
        reserve_total += row["balance_sat"]

    wrapped_supply_sat = wrapped_override.get("wrapped_supply_sat")
    wrapped_supply_sat = int(wrapped_supply_sat) if wrapped_supply_sat is not None else None
    delta_sat = reserve_total - wrapped_supply_sat if wrapped_supply_sat is not None else None

    risk_statement = wrapped_override.get("potential_double_entitlement_risk") or {
        "status": "UNKNOWN",
        "details": "No explicit risk statement supplied in override.",
    }
    if not isinstance(risk_statement, dict):
        raise SystemExit("wrapped_crown_analysis.potential_double_entitlement_risk must be an object")
    risk_status = risk_statement.get("status")
    risk_details = risk_statement.get("details")
    if not isinstance(risk_status, str) or risk_status.strip() == "":
        raise SystemExit("wrapped_crown_analysis.potential_double_entitlement_risk.status must be a non-empty string")
    if not isinstance(risk_details, str) or risk_details.strip() == "":
        raise SystemExit("wrapped_crown_analysis.potential_double_entitlement_risk.details must be a non-empty string")

    unresolved_questions = wrapped_override.get("unresolved_questions") or []
    if not isinstance(unresolved_questions, list) or not all(isinstance(x, str) and x.strip() for x in unresolved_questions):
        raise SystemExit("wrapped_crown_analysis.unresolved_questions must be a list of non-empty strings")

    wrapped_crown_analysis = {
        "snapshot": classification_registry["snapshot"],
        "classification": {
            "status": wrapped_status,
            "confidence": wrapped_conf,
            "evidence": wrapped_evidence,
        },
        "reserve_entities": reserve_rows,
        "reported_wrapped_supply_sat": wrapped_supply_sat,
        "reported_wrapped_supply_crw": crw_from_sats(wrapped_supply_sat) if wrapped_supply_sat is not None else None,
        "reported_native_backing_sat": reserve_total,
        "reported_native_backing_crw": crw_from_sats(reserve_total),
        "supply_backing_delta_sat": delta_sat,
        "supply_backing_delta_crw": crw_from_sats(delta_sat) if delta_sat is not None else None,
        "potential_double_entitlement_risk": {
            "status": risk_status,
            "details": risk_details,
        },
        "unresolved_questions": unresolved_questions,
    }

summary = {
    "status": "pass",
    "PHASE_2B_INPUT_VERIFIED": "YES",
    "TOTAL_SNAPSHOT_CRW": crw_from_sats(expected_total_sat),
    "TOTAL_SNAPSHOT_SAT": expected_total_sat,
    "validation": {
        "phase2b_input_provenance": checks,
        "positive_entities_preserved": len(entity_rows) == expected_positive_entities,
        "category_mutual_exclusion_reconciles_total": category_total_sat == expected_total_sat,
        "raw_collateral_reconciles": {
            "count_500": recomputed_500,
            "count_10000": recomputed_10000,
            "expected_500": expected_500_count,
            "expected_10000": expected_10000_count,
            "ok": recomputed_500 == expected_500_count and recomputed_10000 == expected_10000_count,
        },
        "integer_satoshi_arithmetic": True,
        "consensus_source_changed": False,
    },
    "classification_overview": classification_registry["category_totals"],
    "wrapped_crown_status": wrapped_status,
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
}

outputs = {
    "phase2c-classification-registry.json": classification_registry,
    "phase2c-collateral-concentration.json": collateral_concentration,
    "phase2c-top-balances-report.json": top_balances_report,
    "phase2c-node-collateral-analysis.json": node_collateral_analysis,
    "phase2c-exchange-custody-analysis.json": exchange_custody_analysis,
    "phase2c-wrapped-crown-analysis.json": wrapped_crown_analysis,
    "phase2c-control-entities.json": control_entities,
    "phase2c-summary.json": summary,
}

for filename, payload in outputs.items():
    with open(os.path.join(outdir, filename), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

print("[phase2c] Phase 2C classification complete.", file=sys.stderr)
for name in outputs:
    print(f"[phase2c] Wrote: {os.path.join(outdir, name)}", file=sys.stderr)
PY
