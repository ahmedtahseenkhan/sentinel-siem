#!/usr/bin/env bash
#
# build-agent-package.sh — rebuild the downloadable WatchNode agent package.
#
# Produces the artifacts the dashboard /deploy page hands out:
#   WatchNode/SentinelAgent.zip        (Windows: fresh watchnode.exe + installer)
#   WatchNode/cmd/agent/watchnode-linux (Linux binary)
#
# It cross-compiles fresh binaries from the current source so the dashboard
# always serves an up-to-date agent — no manual sharing. Re-run it whenever the
# agent code changes.
#
# Build toolchain: uses the host `go` if present, otherwise a throwaway
# golang:1.23 Docker container (matches the server images). No Go install needed.
#
# Usage:
#   scripts/build-agent-package.sh                # lab mode (plaintext + enroll token)
#   scripts/build-agent-package.sh --mode prod    # production mode (mTLS via bundled certs)
#
# After running, the dashboard serves the new package immediately if WatchNode is
# mounted into the dashboard container (see docker-compose.local.yaml). No rebuild
# of the dashboard image is required.
set -euo pipefail

MODE="lab"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
if [[ "$MODE" != "lab" && "$MODE" != "prod" ]]; then
  echo "--mode must be 'lab' or 'prod'" >&2; exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WN="$ROOT/WatchNode"
PKG="$WN/SentinelAgent"
[[ -d "$PKG" ]] || { echo "package dir not found: $PKG" >&2; exit 1; }

# --- pick a build runner: host go, else docker ------------------------------
gobuild() {  # gobuild <GOOS> <GOARCH> <output-relative-to-WatchNode> <pkg>
  local goos="$1" goarch="$2" out="$3" pkg="$4"
  if command -v go >/dev/null 2>&1; then
    ( cd "$WN" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -o "$out" "$pkg" )
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$WN":/src -w /src \
      --user "$(id -u):$(id -g)" \
      -e GOOS="$goos" -e GOARCH="$goarch" -e CGO_ENABLED=0 \
      -e GOCACHE=/tmp/.gocache -e GOPATH=/tmp/go \
      golang:1.23 go build -o "$out" "$pkg"
  else
    echo "neither 'go' nor 'docker' found — cannot build" >&2; exit 1
  fi
}

echo "[*] Building fresh agent binaries (mode=$MODE)..."
gobuild windows amd64 "SentinelAgent/watchnode.exe"   "./cmd/agent"
gobuild linux   amd64 "cmd/agent/watchnode-linux"     "./cmd/agent"

# --- set TLS mode in the bundled install.bat --------------------------------
# Lab  => installer passes -NoTLS (plaintext + enrollment token).
# Prod => installer uses mTLS via the bundled certs (no -NoTLS).
if [[ "$MODE" == "lab" ]]; then
  TLS_LINE='set "TLS_ARGS=-NoTLS"'
else
  TLS_LINE='set "TLS_ARGS="'
fi
# Replace the managed line in place (portable sed for both GNU and BSD).
tmp="$(mktemp)"
sed 's|^set "TLS_ARGS=.*|'"$TLS_LINE"'|' "$PKG/install.bat" > "$tmp" && mv "$tmp" "$PKG/install.bat"

# NOTE: do NOT rewrite line endings here. install.ps1 parses correctly with its
# committed (LF) endings; an awk CRLF pass corrupted here-string parsing on the
# target and produced bogus "Missing closing '}'" errors. Leave endings as-is.

# --- repackage SentinelAgent.zip --------------------------------------------
echo "[*] Repackaging SentinelAgent.zip..."
( cd "$WN" && rm -f SentinelAgent.zip
  if command -v zip >/dev/null 2>&1; then
    zip -r -q SentinelAgent.zip SentinelAgent
  else
    python3 -m zipfile -c SentinelAgent.zip SentinelAgent
  fi )

echo "[+] Done."
echo "    Windows package : $WN/SentinelAgent.zip"
echo "    Linux binary    : $WN/cmd/agent/watchnode-linux"
echo "    Install mode    : $MODE  ($( [[ $MODE == lab ]] && echo 'plaintext + enroll token' || echo 'mTLS' ))"
echo
echo "The dashboard /deploy page now serves these (if WatchNode is mounted into the dashboard container)."
