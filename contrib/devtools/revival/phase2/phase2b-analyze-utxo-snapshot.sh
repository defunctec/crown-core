#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

usage() {
  cat <<USAGE
Usage:
  $0 --input <phase2b-utxos.jsonl> --evidence-dir <phase2b_evidence_dir> [--outdir <output_dir>] [--archive-name <name>] [--archive-sha256 <hex>]

Notes:
  - Post-processing only. Does not start crownd, does not mutate chainstate, and does not call RPC.
  - Streams JSONL line-by-line and aggregates using integer satoshi arithmetic.
USAGE
}

INPUT_JSONL=""
EVIDENCE_DIR=""
OUTDIR=""
ARCHIVE_NAME="crown-old-chain.7z"
ARCHIVE_SHA256="56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0"
SNAPSHOT_HEIGHT="5420279"
SNAPSHOT_HASH="8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed"
SNAPSHOT_TIMESTAMP_UTC="2025-07-01T23:59:24Z"
SNAPSHOT_CHAINWORK="00000000000000000000000000000000000000000055f92a16848adbe0b66cbe"
EXPECTED_UTXO_COUNT="5116236"
EXPECTED_TOTAL_CRW="34010803.11042473"

while [ $# -gt 0 ]; do
  case "$1" in
    --input)
      INPUT_JSONL="${2:-}"; shift 2 ;;
    --evidence-dir)
      EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --outdir)
      OUTDIR="${2:-}"; shift 2 ;;
    --archive-name)
      ARCHIVE_NAME="${2:-}"; shift 2 ;;
    --archive-sha256)
      ARCHIVE_SHA256="${2:-}"; shift 2 ;;
    --expected-utxo-count)
      EXPECTED_UTXO_COUNT="${2:-}"; shift 2 ;;
    --expected-total-crw)
      EXPECTED_TOTAL_CRW="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[phase2][error] Unknown argument: $1" >&2
      exit 1 ;;
  esac
done

[ -n "$INPUT_JSONL" ] || { usage; echo "[phase2][error] --input is required" >&2; exit 1; }
[ -n "$EVIDENCE_DIR" ] || { usage; echo "[phase2][error] --evidence-dir is required" >&2; exit 1; }

INPUT_JSONL="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$INPUT_JSONL")"
EVIDENCE_DIR="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$EVIDENCE_DIR")"
[ -f "$INPUT_JSONL" ] || { echo "[phase2][error] Input JSONL not found: $INPUT_JSONL" >&2; exit 1; }
[ -d "$EVIDENCE_DIR" ] || { echo "[phase2][error] Evidence directory not found: $EVIDENCE_DIR" >&2; exit 1; }

if [ -z "$OUTDIR" ]; then
  OUTDIR="$EVIDENCE_DIR"
fi
OUTDIR="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTDIR")"
mkdir -p "$OUTDIR"

EXPORT_RPC_RESULT_JSON="$EVIDENCE_DIR/exportutxosnapshot-result.json"
TXOUTSETINFO_JSON="$EVIDENCE_DIR/txoutsetinfo-after-reconstruction.json"
[ -f "$EXPORT_RPC_RESULT_JSON" ] || { echo "[phase2][error] Missing evidence file: $EXPORT_RPC_RESULT_JSON" >&2; exit 1; }
[ -f "$TXOUTSETINFO_JSON" ] || { echo "[phase2][error] Missing evidence file: $TXOUTSETINFO_JSON" >&2; exit 1; }

METADATA_JSON="$OUTDIR/phase2b-snapshot-metadata.json"
RECONSTRUCTION_AUDIT_JSON="$OUTDIR/phase2b-reconstruction-audit.json"
BALANCES_CSV="$OUTDIR/phase2b-address-script-balances.csv"
BALANCES_JSONL="$OUTDIR/phase2b-address-script-balances.jsonl"
DISTRIBUTION_JSON="$OUTDIR/phase2b-distribution-summary.json"

TOOLING_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"

python3 - "$INPUT_JSONL" "$EVIDENCE_DIR" "$OUTDIR" "$EXPORT_RPC_RESULT_JSON" "$TXOUTSETINFO_JSON" "$METADATA_JSON" "$RECONSTRUCTION_AUDIT_JSON" "$BALANCES_CSV" "$BALANCES_JSONL" "$DISTRIBUTION_JSON" "$ARCHIVE_NAME" "$ARCHIVE_SHA256" "$SNAPSHOT_HEIGHT" "$SNAPSHOT_HASH" "$SNAPSHOT_TIMESTAMP_UTC" "$SNAPSHOT_CHAINWORK" "$EXPECTED_UTXO_COUNT" "$EXPECTED_TOTAL_CRW" "$TOOLING_COMMIT" <<'PY'
import csv
import datetime
import hashlib
import json
import math
import os
import sqlite3
import sys
from decimal import Decimal, ROUND_DOWN, getcontext

getcontext().prec = 50

(
    input_jsonl_path,
    evidence_dir,
    outdir,
    export_result_path,
    txoutsetinfo_path,
    metadata_path,
    audit_path,
    balances_csv_path,
    balances_jsonl_path,
    distribution_path,
    archive_name,
    archive_sha256,
    snapshot_height,
    snapshot_hash,
    snapshot_timestamp_utc,
    snapshot_chainwork,
    expected_utxo_count,
    expected_total_crw,
    tooling_commit,
) = sys.argv[1:20]

COIN = 100_000_000
snapshot_height = int(snapshot_height)
expected_utxo_count = int(expected_utxo_count)
expected_total_sat = int((Decimal(expected_total_crw) * COIN).to_integral_value(rounding=ROUND_DOWN))


def to_sats(amount_value):
    if isinstance(amount_value, int):
        return amount_value
    return int((Decimal(str(amount_value)) * COIN).to_integral_value(rounding=ROUND_DOWN))


def crw_from_sats(sats: int) -> str:
    whole = sats // COIN
    frac = sats % COIN
    return f"{whole}.{frac:08d}"


def pct(num: int, den: int) -> str:
    if den == 0:
        return "0"
    return format((Decimal(num) * Decimal(100)) / Decimal(den), "f")


def share(num: int, den: int) -> str:
    if den == 0:
        return "0"
    return format(Decimal(num) / Decimal(den), "f")


export_result = json.load(open(export_result_path, encoding="utf-8"))
txoutsetinfo = json.load(open(txoutsetinfo_path, encoding="utf-8"))
snapshot_block = None
snapshot_block_path = os.path.join(evidence_dir, "snapshot-block.json")
if os.path.isfile(snapshot_block_path):
    snapshot_block = json.load(open(snapshot_block_path, encoding="utf-8"))

export_count = int(export_result.get("utxos_exported", -1))
export_total_sat = to_sats(export_result.get("exported_total_amount", "0"))
export_chainstate_count = int(export_result.get("chainstate_txouts", -1))
export_chainstate_total_sat = to_sats(export_result.get("chainstate_total_amount", "0"))
txoutset_count = int(txoutsetinfo.get("txouts", -1))
txoutset_total_sat = to_sats(txoutsetinfo.get("total_amount", "0"))

if expected_utxo_count != export_count:
    raise SystemExit(f"expected utxo count mismatch with export evidence: expected={expected_utxo_count} evidence={export_count}")
if expected_utxo_count != txoutset_count:
    raise SystemExit(f"expected utxo count mismatch with txoutset evidence: expected={expected_utxo_count} evidence={txoutset_count}")
if expected_total_sat != export_total_sat:
    raise SystemExit(f"expected total mismatch with export evidence: expected={expected_total_sat} evidence={export_total_sat}")
if expected_total_sat != txoutset_total_sat:
    raise SystemExit(f"expected total mismatch with txoutset evidence: expected={expected_total_sat} evidence={txoutset_total_sat}")

tmp_db_path = os.path.join(outdir, "phase2b-aggregation.tmp.sqlite")
if os.path.exists(tmp_db_path):
    os.remove(tmp_db_path)
conn = sqlite3.connect(tmp_db_path)
cur = conn.cursor()
cur.execute("PRAGMA journal_mode = WAL")
cur.execute("PRAGMA synchronous = NORMAL")
cur.execute("PRAGMA temp_store = FILE")
cur.execute(
    """
    CREATE TABLE entities (
        entity_key TEXT PRIMARY KEY,
        entity_kind TEXT NOT NULL,
        entity TEXT NOT NULL,
        script_identifier TEXT,
        script_pub_key_hex TEXT,
        script_type TEXT NOT NULL,
        utxo_count INTEGER NOT NULL,
        balance_sat INTEGER NOT NULL,
        candidate_500_utxo_count INTEGER NOT NULL,
        candidate_10000_utxo_count INTEGER NOT NULL
    )
    """
)

script_type_stats = {}
utxo_count = 0
utxo_total_sat = 0
zero_value_utxo_count = 0
zero_value_total_sat = 0
positive_value_utxo_count = 0
positive_value_total_sat = 0
address_bearing_outputs = 0
without_single_standard_address = 0
candidate_500_utxo_count = 0
candidate_500_total_sat = 0
candidate_10000_utxo_count = 0
candidate_10000_total_sat = 0
malformed_lines = 0
first_malformed = []

sha256 = hashlib.sha256()

insert_sql = """
INSERT INTO entities (
    entity_key, entity_kind, entity, script_identifier, script_pub_key_hex, script_type,
    utxo_count, balance_sat, candidate_500_utxo_count, candidate_10000_utxo_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(entity_key) DO UPDATE SET
    utxo_count = entities.utxo_count + 1,
    balance_sat = entities.balance_sat + excluded.balance_sat,
    candidate_500_utxo_count = entities.candidate_500_utxo_count + excluded.candidate_500_utxo_count,
    candidate_10000_utxo_count = entities.candidate_10000_utxo_count + excluded.candidate_10000_utxo_count
"""

conn.execute("BEGIN")
with open(input_jsonl_path, "rb") as f:
    for line_no, raw in enumerate(f, 1):
        sha256.update(raw)
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            malformed_lines += 1
            if len(first_malformed) < 20:
                first_malformed.append({"line": line_no, "error": f"utf8_decode_error: {e}"})
            continue

        payload = line.strip()
        if payload == "":
            malformed_lines += 1
            if len(first_malformed) < 20:
                first_malformed.append({"line": line_no, "error": "blank_line"})
            continue

        try:
            record = json.loads(payload)
            txid = record["txid"]
            vout = int(record["vout"])
            value_sat = int(record["value_sats"])
            script_type = record.get("script_type") or "nonstandard"
            script_hex = record.get("script_pub_key_hex") or ""
            addresses = record.get("addresses") or []
            address_count = int(record.get("address_count", len(addresses)))
            single_standard_address = bool(record.get("single_standard_address", False))
            _ = int(record.get("creation_height", 0))
            if not isinstance(txid, str) or len(txid) == 0:
                raise ValueError("txid missing/invalid")
            if not isinstance(addresses, list):
                raise ValueError("addresses not list")
            for addr in addresses:
                if not isinstance(addr, str):
                    raise ValueError("addresses[] item not string")
            if script_hex:
                _ = bytes.fromhex(script_hex)
            if value_sat < 0:
                raise ValueError("negative value_sats")
            if address_count < 0:
                raise ValueError("negative address_count")
        except Exception as e:
            malformed_lines += 1
            if len(first_malformed) < 20:
                first_malformed.append({"line": line_no, "error": str(e)})
            continue

        utxo_count += 1
        utxo_total_sat += value_sat

        if value_sat == 0:
            zero_value_utxo_count += 1
            zero_value_total_sat += value_sat
        else:
            positive_value_utxo_count += 1
            positive_value_total_sat += value_sat

        if value_sat == 500 * COIN:
            candidate_500_utxo_count += 1
            candidate_500_total_sat += value_sat
        if value_sat == 10_000 * COIN:
            candidate_10000_utxo_count += 1
            candidate_10000_total_sat += value_sat

        if address_count > 0:
            address_bearing_outputs += 1

        resolved_single = single_standard_address and address_count == 1 and len(addresses) == 1 and addresses[0] != ""
        if not resolved_single:
            without_single_standard_address += 1

        st = script_type_stats.setdefault(script_type, {"count": 0, "value_sat": 0})
        st["count"] += 1
        st["value_sat"] += value_sat

        if resolved_single:
            entity_key = f"addr:{addresses[0]}"
            entity_kind = "address"
            entity = addresses[0]
            script_identifier = None
            script_pub_key_hex = None
        else:
            script_bytes = bytes.fromhex(script_hex) if script_hex else b""
            script_identifier = hashlib.sha256(script_bytes).hexdigest()
            entity_key = f"script:{script_identifier}"
            entity_kind = "script"
            entity = script_identifier
            script_pub_key_hex = script_hex

        cur.execute(
            insert_sql,
            (
                entity_key,
                entity_kind,
                entity,
                script_identifier,
                script_pub_key_hex,
                script_type,
                1,
                value_sat,
                1 if value_sat == 500 * COIN else 0,
                1 if value_sat == 10_000 * COIN else 0,
            ),
        )

        if utxo_count % 50000 == 0:
            conn.commit()
            conn.execute("BEGIN")

conn.commit()

input_sha256 = sha256.hexdigest().upper()
input_size_bytes = os.path.getsize(input_jsonl_path)

checks = {
    "malformed_lines_zero": malformed_lines == 0,
    "utxo_count_matches_expected_constant": utxo_count == expected_utxo_count,
    "utxo_total_sat_matches_expected_constant": utxo_total_sat == expected_total_sat,
    "utxo_count_matches_export_result": utxo_count == export_count,
    "utxo_count_matches_txoutsetinfo": utxo_count == txoutset_count,
    "utxo_total_sat_matches_export_result": utxo_total_sat == export_total_sat,
    "utxo_total_sat_matches_export_chainstate_total": utxo_total_sat == export_chainstate_total_sat,
    "utxo_total_sat_matches_txoutsetinfo": utxo_total_sat == txoutset_total_sat,
}

if not all(checks.values()):
    fail_payload = {
        "status": "fail",
        "checks": checks,
        "malformed_lines": malformed_lines,
        "first_malformed_lines": first_malformed,
        "recomputed": {
            "utxo_count": utxo_count,
            "utxo_total_sat": utxo_total_sat,
            "utxo_total_crw": crw_from_sats(utxo_total_sat),
        },
        "input_utxo_jsonl_sha256": input_sha256,
    }
    json.dump(fail_payload, open(audit_path, "w", encoding="utf-8"), indent=2)
    raise SystemExit(f"Phase2B post-processing validation failed; see {audit_path}")

cur.execute("SELECT COUNT(*) FROM entities")
total_entity_count = int(cur.fetchone()[0])
cur.execute("SELECT COUNT(*) FROM entities WHERE balance_sat > 0")
positive_entity_count = int(cur.fetchone()[0])

with open(balances_csv_path, "w", newline="", encoding="utf-8") as f_csv, open(balances_jsonl_path, "w", encoding="utf-8") as f_jsonl:
    csv_writer = csv.writer(f_csv)
    csv_writer.writerow([
        "entity_kind",
        "entity",
        "script_identifier",
        "script_pub_key_hex",
        "script_type",
        "utxo_count",
        "balance_sat",
        "balance_crw",
        "candidate_500_utxo_count",
        "candidate_10000_utxo_count",
    ])

    for row in cur.execute(
        """
        SELECT entity_kind, entity, COALESCE(script_identifier,''), COALESCE(script_pub_key_hex,''), script_type,
               utxo_count, balance_sat, candidate_500_utxo_count, candidate_10000_utxo_count
          FROM entities
         WHERE balance_sat > 0
         ORDER BY balance_sat DESC, entity ASC
        """
    ):
        balance_sat = int(row[6])
        out = {
            "entity_kind": row[0],
            "entity": row[1],
            "script_identifier": row[2] or None,
            "script_pub_key_hex": row[3] or None,
            "script_type": row[4],
            "utxo_count": int(row[5]),
            "balance_sat": balance_sat,
            "balance_crw": crw_from_sats(balance_sat),
            "candidate_500_utxo_count": int(row[7]),
            "candidate_10000_utxo_count": int(row[8]),
        }
        csv_writer.writerow([
            out["entity_kind"],
            out["entity"],
            out["script_identifier"] or "",
            out["script_pub_key_hex"] or "",
            out["script_type"],
            out["utxo_count"],
            out["balance_sat"],
            out["balance_crw"],
            out["candidate_500_utxo_count"],
            out["candidate_10000_utxo_count"],
        ])
        f_jsonl.write(json.dumps(out, separators=(",", ":")) + "\n")

def query_int(sql):
    cur.execute(sql)
    value = cur.fetchone()[0]
    return int(value or 0)

def query_optional_int(sql):
    cur.execute(sql)
    value = cur.fetchone()[0]
    return None if value is None else int(value)

positive_total_from_entities = query_int("SELECT SUM(balance_sat) FROM entities WHERE balance_sat > 0")
if positive_total_from_entities != positive_value_total_sat:
    raise SystemExit("positive total mismatch between entity aggregation and UTXO scan")

mean_balance_sat_floor = positive_value_total_sat // positive_entity_count if positive_entity_count else 0
mean_remainder_sat = positive_value_total_sat % positive_entity_count if positive_entity_count else 0

if positive_entity_count:
    lower_mid_offset = (positive_entity_count - 1) // 2
    cur.execute(
        f"""
        SELECT balance_sat
          FROM entities
         WHERE balance_sat > 0
         ORDER BY balance_sat ASC, entity ASC
         LIMIT 1 OFFSET {lower_mid_offset}
        """
    )
    median_balance_sat = int(cur.fetchone()[0])
else:
    median_balance_sat = 0

def top_share(limit_n):
    cur.execute(
        f"""
        SELECT COALESCE(SUM(balance_sat), 0)
          FROM (
                SELECT balance_sat
                  FROM entities
                 WHERE balance_sat > 0
                 ORDER BY balance_sat DESC, entity ASC
                 LIMIT {int(limit_n)}
               )
        """
    )
    bal = int(cur.fetchone()[0] or 0)
    return {
        "entity_count": min(int(limit_n), positive_entity_count),
        "balance_sat": bal,
        "balance_crw": crw_from_sats(bal),
        "share_of_positive_balance": share(bal, positive_value_total_sat),
        "share_of_snapshot_balance": share(bal, utxo_total_sat),
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

balance_bands = []
for label, low, high in band_defs:
    if high is None:
        cur.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(balance_sat),0)
              FROM entities
             WHERE balance_sat >= ? AND balance_sat > 0
            """,
            (low,),
        )
    else:
        cur.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(balance_sat),0)
              FROM entities
             WHERE balance_sat >= ? AND balance_sat < ? AND balance_sat > 0
            """,
            (low, high),
        )
    c, s = cur.fetchone()
    c = int(c or 0)
    s = int(s or 0)
    balance_bands.append(
        {
            "band": label,
            "entity_count": c,
            "total_value_sat": s,
            "total_value_crw": crw_from_sats(s),
            "percent_of_positive_balance_entities": pct(c, positive_entity_count),
            "percent_of_snapshot_crw": pct(s, utxo_total_sat),
        }
    )

largest_balances = []
cur.execute(
    """
    SELECT entity_kind, entity, balance_sat
      FROM entities
     WHERE balance_sat > 0
     ORDER BY balance_sat DESC, entity ASC
     LIMIT 100
    """
)
for rank, row in enumerate(cur.fetchall(), 1):
    bal = int(row[2])
    largest_balances.append(
        {
            "rank": rank,
            "entity_kind": row[0],
            "entity": row[1],
            "balance_sat": bal,
            "balance_crw": crw_from_sats(bal),
            "share_of_snapshot_crw": share(bal, utxo_total_sat),
        }
    )

milestones = {1, 10, 100, 1000, positive_entity_count}
for p in (0.001, 0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 1.0):
    if positive_entity_count > 0:
        milestones.add(max(1, int(math.ceil(positive_entity_count * p))))
milestones = sorted(m for m in milestones if m > 0)

curve = []
running = 0
rank = 0
for row in cur.execute(
    """
    SELECT balance_sat
      FROM entities
     WHERE balance_sat > 0
     ORDER BY balance_sat DESC, entity ASC
    """
):
    rank += 1
    running += int(row[0])
    if rank in milestones:
        curve.append(
            {
                "rank": rank,
                "cumulative_balance_sat": running,
                "cumulative_balance_crw": crw_from_sats(running),
                "cumulative_share_of_snapshot_crw": share(running, utxo_total_sat),
            }
        )

script_type_summary = []
for script_type in sorted(script_type_stats):
    stat = script_type_stats[script_type]
    script_type_summary.append(
        {
            "script_type": script_type,
            "utxo_count": int(stat["count"]),
            "total_value_sat": int(stat["value_sat"]),
            "total_value_crw": crw_from_sats(int(stat["value_sat"])),
        }
    )

distribution = {
    "snapshot": {
        "selection_rule": "last active-chain block at or before 2025-07-01T23:59:59Z",
        "height": snapshot_height,
        "hash": snapshot_hash,
        "timestamp_utc": snapshot_timestamp_utc,
        "chainwork": snapshot_chainwork,
    },
    "validation": {
        "status": "pass",
        "checks": checks,
        "malformed_line_count": malformed_lines,
        "first_malformed_lines": first_malformed,
    },
    "utxo_totals": {
        "utxo_count": utxo_count,
        "total_value_sat": utxo_total_sat,
        "total_value_crw": crw_from_sats(utxo_total_sat),
        "zero_value_utxo_count": zero_value_utxo_count,
        "zero_value_total_sat": zero_value_total_sat,
        "zero_value_total_crw": crw_from_sats(zero_value_total_sat),
        "positive_value_utxo_count": positive_value_utxo_count,
        "positive_value_total_sat": positive_value_total_sat,
        "positive_value_total_crw": crw_from_sats(positive_value_total_sat),
        "standard_address_bearing_outputs": address_bearing_outputs,
        "outputs_without_single_standard_address": without_single_standard_address,
    },
    "collateral_sized_raw_utxos": {
        "500_crw": {
            "utxo_count": candidate_500_utxo_count,
            "total_value_sat": candidate_500_total_sat,
            "total_value_crw": crw_from_sats(candidate_500_total_sat),
            "note": "numerical candidate only; not ownership/systemnode classification",
        },
        "10000_crw": {
            "utxo_count": candidate_10000_utxo_count,
            "total_value_sat": candidate_10000_total_sat,
            "total_value_crw": crw_from_sats(candidate_10000_total_sat),
            "note": "numerical candidate only; not ownership/masternode classification",
        },
    },
    "entity_summary": {
        "unique_entities_including_zero_balance": total_entity_count,
        "unique_positive_balance_entities": positive_entity_count,
        "median_balance_sat_lower_median": median_balance_sat,
        "median_balance_crw_lower_median": crw_from_sats(median_balance_sat),
        "mean_balance_sat_floor": mean_balance_sat_floor,
        "mean_balance_crw_floor": crw_from_sats(mean_balance_sat_floor),
        "mean_balance_sat_remainder": mean_remainder_sat,
        "top_10_share": top_share(10),
        "top_100_share": top_share(100),
        "top_1000_share": top_share(1000),
    },
    "balance_bands": balance_bands,
    "largest_balances": largest_balances,
    "cumulative_concentration_curve": curve,
    "script_type_summary": script_type_summary,
}
json.dump(distribution, open(distribution_path, "w", encoding="utf-8"), indent=2)

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()

reconciliation = {
    "expected_constants": {
        "utxo_count": expected_utxo_count,
        "total_value_sat": expected_total_sat,
        "total_value_crw": crw_from_sats(expected_total_sat),
    },
    "recomputed_from_jsonl": {
        "utxo_count": utxo_count,
        "total_value_sat": utxo_total_sat,
        "total_value_crw": crw_from_sats(utxo_total_sat),
    },
    "recorded_export_result": {
        "utxo_count": export_count,
        "chainstate_txouts": export_chainstate_count,
        "exported_total_sat": export_total_sat,
        "chainstate_total_sat": export_chainstate_total_sat,
        "bestblock": export_result.get("bestblock"),
        "height": export_result.get("height"),
    },
    "recorded_txoutsetinfo": {
        "utxo_count": txoutset_count,
        "total_value_sat": txoutset_total_sat,
        "bestblock": txoutsetinfo.get("bestblock"),
        "height": txoutsetinfo.get("height"),
    },
}

audit = {
    "snapshot": distribution["snapshot"],
    "status": "pass",
    "input_utxo_jsonl": {
        "path": input_jsonl_path,
        "sha256": input_sha256,
        "size_bytes": input_size_bytes,
    },
    "parsing": {
        "malformed_line_count": malformed_lines,
        "first_malformed_lines": first_malformed,
    },
    "reconciliation": reconciliation,
    "checks": checks,
    "artifacts": {
        "phase2b-snapshot-metadata.json": {"path": metadata_path},
        "phase2b-reconstruction-audit.json": {"path": audit_path},
        "phase2b-address-script-balances.csv": {"path": balances_csv_path},
        "phase2b-address-script-balances.jsonl": {"path": balances_jsonl_path},
        "phase2b-distribution-summary.json": {"path": distribution_path},
    },
}
json.dump(audit, open(audit_path, "w", encoding="utf-8"), indent=2)

artifact_paths = [
    metadata_path,
    audit_path,
    balances_csv_path,
    balances_jsonl_path,
    distribution_path,
]

metadata = {
    "snapshot": distribution["snapshot"],
    "archive_provenance": {
        "archive_name": archive_name,
        "archive_sha256": archive_sha256.upper(),
    },
    "code_provenance": {
        "tooling_git_commit": tooling_commit,
    },
    "generation": {
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "method": "phase2b post-processing from existing JSONL/evidence only",
        "daemon_required": False,
        "chainstate_mutation": False,
        "input_utxo_jsonl_sha256": input_sha256,
    },
    "validation": {
        "status": "pass",
        "checks": checks,
    },
    "artifacts": [],
}

for path in artifact_paths:
    if os.path.isfile(path):
        metadata["artifacts"].append(
            {
                "path": path,
                "size_bytes": os.path.getsize(path),
                "sha256": file_sha256(path),
            }
        )

json.dump(metadata, open(metadata_path, "w", encoding="utf-8"), indent=2)

if os.path.exists(tmp_db_path):
    os.remove(tmp_db_path)
PY

echo "[phase2] Phase 2B post-processing complete." >&2
echo "[phase2] Wrote: $METADATA_JSON" >&2
echo "[phase2] Wrote: $RECONSTRUCTION_AUDIT_JSON" >&2
echo "[phase2] Wrote: $BALANCES_CSV" >&2
echo "[phase2] Wrote: $BALANCES_JSONL" >&2
echo "[phase2] Wrote: $DISTRIBUTION_JSON" >&2
