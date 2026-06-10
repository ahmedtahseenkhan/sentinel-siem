#!/usr/bin/env bash
# sentinel-backup.sh — Snapshot every configuration artifact the SIEM needs to
# rebuild on a fresh machine: detection rules, decoders, custom dashboards,
# audit log, log-filter rules, and the manager / indexer / agent YAMLs.
#
# Usage:
#   scripts/sentinel-backup.sh                       # writes to ./backups/sentinel-<ts>.tar.gz
#   scripts/sentinel-backup.sh /var/backups/sentinel # writes to that dir
#
# Restore: scripts/sentinel-restore.sh <archive.tar.gz>
#
# This script does NOT snapshot OpenSearch indices — for that use OpenSearch's
# native snapshot API into S3/disk. Indexed events are recreatable from the
# raw payloads if you have agent-side disk queues; configs are not.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-${ROOT}/backups}"
mkdir -p "$OUT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname -s 2>/dev/null || echo sentinel)"
ARCHIVE="${OUT_DIR}/sentinel-${HOST}-${TS}.tar.gz"

# Build the include list — silently skip pieces that don't exist on this box,
# so the same script works for partial installs.
INCLUDES=()
add_if_exists() { [ -e "$1" ] && INCLUDES+=("$1") || true; }

# Detection content
add_if_exists "${ROOT}/WatchTower/rules"
add_if_exists "${ROOT}/WatchTower/decoders"

# Service configs
add_if_exists "${ROOT}/WatchTower/configs"
add_if_exists "${ROOT}/WatchVault/configs"
add_if_exists "${ROOT}/WatchNode/configs"
add_if_exists "${ROOT}/docker-compose.full.yaml"

# Dashboard state — custom viz, custom dashboards, audit log, log filters
add_if_exists "${ROOT}/corenestDashboard/custom_dashboards.db"
add_if_exists "${ROOT}/corenestDashboard/audit_log.db"
add_if_exists "${ROOT}/corenestDashboard/log_filters.db"

# Optional: TLS material so a restore comes up immediately on the same fleet.
# Comment out if you'd rather re-issue certs on the new host.
add_if_exists "${ROOT}/WatchNode/scripts/certs"

if [ "${#INCLUDES[@]}" -eq 0 ]; then
  echo "ERROR: nothing to back up (no rules, decoders, configs, or DBs found under ${ROOT})" >&2
  exit 1
fi

# Stage everything under sentinel-<ts>/ so the archive unpacks into a single
# top-level directory. Uses a temp dir + symlinks so it works with both GNU
# and BSD tar (macOS) — no reliance on `--transform`.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
TOP="${STAGE}/sentinel-${TS}"
mkdir -p "$TOP"

# Manifest first.
{
  echo "Sentinel SIEM configuration backup"
  echo "Host:    ${HOST}"
  echo "Created: ${TS}"
  echo "Source:  ${ROOT}"
  echo ""
  echo "Contents:"
  for p in "${INCLUDES[@]}"; do echo "  - ${p#${ROOT}/}"; done
} > "${TOP}/MANIFEST.txt"

# Copy each include preserving its relative path under TOP/.
for src in "${INCLUDES[@]}"; do
  rel="${src#${ROOT}/}"
  dest="${TOP}/${rel}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$src" "$dest"
done

tar -czf "$ARCHIVE" -C "$STAGE" "sentinel-${TS}"

SIZE="$(du -h "$ARCHIVE" | cut -f1)"
echo "✅ Backup written: ${ARCHIVE} (${SIZE})"
echo ""
echo "Restore on another machine with:"
echo "    scripts/sentinel-restore.sh ${ARCHIVE}"
