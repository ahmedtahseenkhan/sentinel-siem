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

# Force LF endings on the installer scripts. install.ps1 parses correctly as LF;
# a stray CRLF (e.g. left in the working tree by an older build) breaks
# here-string parsing and yields bogus "Missing closing '}'" errors. tr is
# portable across GNU/BSD and strips every CR, normalising to clean LF.
strip_cr() { tr -d '\r' < "$1" > "$1.lf" && mv "$1.lf" "$1"; }
strip_cr "$PKG/install.ps1"
strip_cr "$PKG/install.bat"

# Force a UTF-8 BOM on install.ps1. Windows PowerShell 5.1 reads a BOM-less file
# as the ANSI codepage, mangling the script's non-ASCII characters (banner box
# drawing, em-dashes) into garbage bytes that derail the parser -> bogus
# "Missing closing '}'" errors. A UTF-8 BOM forces 5.1 to read it as UTF-8.
# (PowerShell 7 defaults to UTF-8, which is why this only bites on 5.1.)
ensure_bom() {
  if [ "$(head -c3 "$1" | od -An -tx1 | tr -d ' \n')" != "efbbbf" ]; then
    printf '\357\273\277' | cat - "$1" > "$1.bom" && mv "$1.bom" "$1"
  fi
}
ensure_bom "$PKG/install.ps1"

# --- VALIDATE the installer before packaging --------------------------------
# Catches the classes of bug that bit us in the field (missing BOM; invalid
# YAML escape like "configs\sca" in the generated config; PS parse errors).
# Fail the build rather than ship a broken installer to a client.
echo "[*] Validating installer..."
[ "$(head -c3 "$PKG/install.ps1" | od -An -tx1 | tr -d ' \n')" = "efbbbf" ] \
  || { echo "    ✗ install.ps1 missing UTF-8 BOM"; exit 1; }

python3 - "$PKG/install.ps1" <<'PY' || exit 1
import re, sys
src = open(sys.argv[1], encoding='utf-8-sig').read()
m = re.search(r'\$configContent\s*=\s*@"\r?\n(.*?)\r?\n"@', src, re.S)
if not m:
    print("    ✗ could not find generated config block to validate"); sys.exit(1)
cfg = re.sub(r'\$\w+|\$\{\w+\}', 'X', m.group(1))
valid = set('ntr0abvfeNLP_xuU/ \\"')
bad = []
for i, line in enumerate(cfg.splitlines(), 1):
    for q in re.findall(r'"(?:[^"\\]|\\.)*"', line):
        body = q[1:-1]; j = 0
        while j < len(body):
            if body[j] == '\\':
                nxt = body[j+1] if j+1 < len(body) else ''
                if nxt not in valid: bad.append((i, q, '\\'+nxt))
                j += 2
            else: j += 1
if bad:
    print("    ✗ invalid YAML escape(s) in generated config:")
    for i,q,e in bad: print(f"        line {i}: {e} in {q}")
    sys.exit(1)
print("    ✓ config YAML escapes valid, BOM present")
PY

# Optional: real PowerShell parse check if pwsh is on PATH (CI/dev with pwsh).
if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -Command "\$e=\$null;\$t=\$null;[System.Management.Automation.Language.Parser]::ParseFile('$PKG/install.ps1',[ref]\$t,[ref]\$e)|Out-Null; if(\$e){Write-Error \$e[0].Message; exit 1} else {'    ✓ install.ps1 parses'}" || exit 1
fi

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
