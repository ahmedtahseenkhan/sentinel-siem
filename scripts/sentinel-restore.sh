#!/usr/bin/env bash
# sentinel-restore.sh — Restore a backup produced by sentinel-backup.sh.
#
# Usage:
#   scripts/sentinel-restore.sh <archive.tar.gz>
#   scripts/sentinel-restore.sh <archive.tar.gz> --dry-run   # list contents only
#   scripts/sentinel-restore.sh <archive.tar.gz> --no-backup # skip pre-restore safety snapshot
#
# Default behavior:
#   1. Take a safety snapshot of the current configuration into ./backups
#      so you can roll back if the restore is wrong.
#   2. Stop the docker stack (if it's up) so files aren't being read.
#   3. Untar the archive over the project root.
#   4. Start the stack back up.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <archive.tar.gz> [--dry-run] [--no-backup]" >&2
  exit 64
fi

ARCHIVE="$1"; shift || true
DRY_RUN=0
NO_BACKUP=0
for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=1 ;;
    --no-backup) NO_BACKUP=1 ;;
    *) echo "Unknown flag: $arg" >&2; exit 64 ;;
  esac
done

if [ ! -f "$ARCHIVE" ]; then
  echo "ERROR: archive not found: $ARCHIVE" >&2
  exit 66
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "Archive contents (dry run — nothing changed):"
  tar -tzf "$ARCHIVE" | head -200
  exit 0
fi

if [ "$NO_BACKUP" -eq 0 ]; then
  echo "→ Taking safety snapshot of current configuration before restore…"
  "$ROOT/scripts/sentinel-backup.sh" "$ROOT/backups" || {
    echo "  (safety snapshot failed; pass --no-backup to restore anyway)" >&2
    exit 70
  }
fi

# Stop the stack if compose is available and the file exists.
COMPOSED=0
if [ -f "$ROOT/docker-compose.full.yaml" ] && command -v docker-compose >/dev/null 2>&1; then
  echo "→ Stopping docker stack…"
  docker-compose -f "$ROOT/docker-compose.full.yaml" stop || true
  COMPOSED=1
fi

# Strip the top-level "sentinel-<ts>/" prefix so files land in the project root.
echo "→ Extracting archive over project root…"
TMPDIR_R="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_R"' EXIT
tar -xzf "$ARCHIVE" -C "$TMPDIR_R"
TOP="$(ls "$TMPDIR_R" | head -1)"
if [ -z "$TOP" ]; then
  echo "ERROR: archive looks empty" >&2
  exit 75
fi
# Use rsync if available for an atomic-ish merge; fall back to cp -a.
if command -v rsync >/dev/null 2>&1; then
  rsync -a "$TMPDIR_R/$TOP/" "$ROOT/"
else
  cp -a "$TMPDIR_R/$TOP/." "$ROOT/"
fi

# Restart the stack.
if [ "$COMPOSED" -eq 1 ]; then
  echo "→ Starting docker stack…"
  docker-compose -f "$ROOT/docker-compose.full.yaml" up -d
fi

echo "✅ Restore complete from $ARCHIVE"
echo "   Safety snapshot (rollback) is in $ROOT/backups"
