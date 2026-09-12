#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/devtools/revival/phase2/phase2-common.sh
source "$SCRIPT_DIR/phase2-common.sh"

usage() {
  cat <<USAGE
Usage:
  $0 --source-dir <preserved_extracted_chain_dir> --offline-dir <offline_work_copy> --sync-dir <sync_work_copy> [--archive-file <path_to_crown-old-chain.7z>] [--expected-archive-sha256 <hex>]

Notes:
  - --source-dir must be an extracted chain directory containing blocks/ and chainstate/.
  - --offline-dir and --sync-dir are disposable destinations that will be (re)populated.
  - This script never modifies the archive; it only verifies hash (optional) and copies extracted data.
USAGE
}

SOURCE_DIR=""
OFFLINE_DIR=""
SYNC_DIR=""
ARCHIVE_FILE=""
EXPECTED_ARCHIVE_SHA256="56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0"

while [ $# -gt 0 ]; do
  case "$1" in
    --source-dir)
      SOURCE_DIR="${2:-}"; shift 2 ;;
    --offline-dir)
      OFFLINE_DIR="${2:-}"; shift 2 ;;
    --sync-dir)
      SYNC_DIR="${2:-}"; shift 2 ;;
    --archive-file)
      ARCHIVE_FILE="${2:-}"; shift 2 ;;
    --expected-archive-sha256)
      EXPECTED_ARCHIVE_SHA256="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

[ -n "$SOURCE_DIR" ] || { usage; die "--source-dir is required"; }
[ -n "$OFFLINE_DIR" ] || { usage; die "--offline-dir is required"; }
[ -n "$SYNC_DIR" ] || { usage; die "--sync-dir is required"; }

require_cmd python3
SOURCE_DIR="$(abs_path "$SOURCE_DIR")"
OFFLINE_DIR="$(abs_path "$OFFLINE_DIR")"
SYNC_DIR="$(abs_path "$SYNC_DIR")"
SOURCE_CANONICAL="$(canonical_path "$SOURCE_DIR")"
OFFLINE_CANONICAL="$(canonical_path "$OFFLINE_DIR")"
SYNC_CANONICAL="$(canonical_path "$SYNC_DIR")"

is_archive_path "$SOURCE_DIR" && die "--source-dir points to an archive path; provide extracted directory"
ensure_disposable_chaincopy_dir "$SOURCE_DIR"

[ "$SOURCE_CANONICAL" != "$OFFLINE_CANONICAL" ] || die "--offline-dir must differ from --source-dir"
[ "$SOURCE_CANONICAL" != "$SYNC_CANONICAL" ] || die "--sync-dir must differ from --source-dir"
[ "$OFFLINE_CANONICAL" != "$SYNC_CANONICAL" ] || die "--offline-dir and --sync-dir must be different"

if [ -n "$ARCHIVE_FILE" ]; then
  ARCHIVE_FILE="$(abs_path "$ARCHIVE_FILE")"
  [ -f "$ARCHIVE_FILE" ] || die "Archive file does not exist: $ARCHIVE_FILE"
  is_archive_path "$ARCHIVE_FILE" || die "--archive-file must be archive extension (.7z/.zip/.tar/.tar.gz/.tgz)"

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(sha256sum "$ARCHIVE_FILE" | awk '{print $1}' | tr '[:lower:]' '[:upper:]')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE_FILE" | awk '{print $1}' | tr '[:lower:]' '[:upper:]')"
  else
    die "Cannot verify archive SHA256; install sha256sum or shasum"
  fi

  EXPECTED_UPPER="$(printf '%s' "$EXPECTED_ARCHIVE_SHA256" | tr '[:lower:]' '[:upper:]')"
  [ "$ACTUAL_SHA256" = "$EXPECTED_UPPER" ] || die "Archive SHA256 mismatch. expected=$EXPECTED_UPPER actual=$ACTUAL_SHA256"
  log "Archive SHA256 verified: $ACTUAL_SHA256"
fi

copy_chain_dirs() {
  local src="$1" dst="$2" label="$3"
  assert_safe_disposable_destination "$dst"
  rm -rf "$dst"
  mkdir -p "$dst"
  cp -a "$src/blocks" "$dst/blocks"
  cp -a "$src/chainstate" "$dst/chainstate"

  python3 - "$src" "$dst" "$label" <<'PY'
import datetime, json, os, sys
src, dst, label = sys.argv[1:4]
out = {
  "generated_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
  "role": label,
  "source_dir": src,
  "working_copy_dir": dst,
  "archive_modified": False,
  "contains": ["blocks", "chainstate"],
}

assert_safe_disposable_destination() {
  local dst="$1"
  local canonical_dst
  canonical_dst="$(canonical_path "$dst")"
  [ -n "$canonical_dst" ] || die "Empty destination path is not allowed"
  [ "$canonical_dst" != "/" ] || die "Refusing to operate on root directory"

  if [ -d "$dst" ]; then
    if [ -f "$dst/phase2-working-copy.json" ]; then
      return 0
    fi
    if [ -n "$(find "$dst" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)" ]; then
      die "Destination is non-empty and not a prior phase2 disposable copy: $dst"
    fi
  fi
}
with open(os.path.join(dst, "phase2-working-copy.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
PY
}

log "Preparing OFFLINE disposable copy at: $OFFLINE_DIR"
copy_chain_dirs "$SOURCE_DIR" "$OFFLINE_DIR" "offline"

log "Preparing SYNC disposable copy at: $SYNC_DIR"
copy_chain_dirs "$SOURCE_DIR" "$SYNC_DIR" "sync"

log "Done. Use offline copy with phase2-offline-baseline.sh and sync copy with phase2-controlled-sync-check.sh"
