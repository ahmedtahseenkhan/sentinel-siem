#!/usr/bin/env bash
# Push a partial config update to ALL agents (online OR offline) in a single API call.
# Offline agents have the config queued and delivered automatically on reconnect.
#
# Usage:
#   ./push-config-all.sh [WATCHTOWER_URL] [API_KEY] [OPTIONS]
#
# Options (passed as query string filters):
#   --os windows         only target Windows agents
#   --os linux           only target Linux agents
#   --status running     only target currently-connected agents
#   --label team=hr      only target agents with this label
#
# Example:
#   ./push-config-all.sh http://localhost:9400 sentinel-dev-api-key --os windows

set -euo pipefail

WATCHTOWER="${1:-http://localhost:9400}"
API_KEY="${2:-}"
shift 2 2>/dev/null || true

# Build filter query string from remaining args
QUERY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --os)     QUERY="${QUERY}&os=$2";     shift 2 ;;
        --status) QUERY="${QUERY}&status=$2"; shift 2 ;;
        --label)  QUERY="${QUERY}&label=$2";  shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done
QUERY="${QUERY#&}"

# Resolve API key from .env if not passed
if [[ -z "$API_KEY" ]]; then
    for path in "$(dirname "$0")/.env" "$(dirname "$0")/sentinel-siem/.env" "$HOME/sentinel-siem/.env"; do
        if [[ -f "$path" ]]; then
            API_KEY=$(grep '^WATCHTOWER_API_KEY=' "$path" 2>/dev/null | cut -d= -f2-)
            [[ -n "$API_KEY" ]] && break
        fi
    done
fi

if [[ -z "$API_KEY" ]]; then
    echo "ERROR: API key not provided and not found in .env"
    echo "Usage: $0 http://localhost:9400 <API_KEY> [filters]"
    exit 1
fi

# ---- Config patch ----
CONFIG_PATCH='{
  "performance": {
    "max_cpu_percent": 25,
    "max_memory_bytes": 268435456,
    "batch_size": 500,
    "flush_interval": "30s",
    "queue_size": 10000
  }
}'
# ----------------------

URL="$WATCHTOWER/api/v1/agents/config"
[[ -n "$QUERY" ]] && URL="$URL?$QUERY"

echo "Pushing config to $URL"
echo "Filters: ${QUERY:-<none — targeting all agents>}"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "$URL" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$CONFIG_PATCH")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" != "200" ]]; then
    echo "ERROR: HTTP $HTTP_CODE"
    echo "$BODY"
    exit 1
fi

echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
echo ""
echo "Online agents received the update immediately."
echo "Offline agents will receive it automatically on next reconnect."
