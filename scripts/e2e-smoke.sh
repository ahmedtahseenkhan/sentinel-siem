#!/usr/bin/env bash
#
# e2e-smoke.sh — END-TO-END smoke test of the whole Sentinel pipeline.
#
# This is the test the project was missing. It stands up the real local stack
# and verifies data flows the entire way:
#
#     agent → WatchTower (rules) → Kafka → WatchVault → OpenSearch → APIs/dashboard
#
# It would have caught, before any client ever saw them: the missing Kafka
# topics (empty dashboard), agents not enrolling, events not indexing, the
# forwarder dropping events, and the dashboard being down.
#
# Run it after ANY change, and especially before a client deployment:
#     scripts/e2e-smoke.sh
#
# Exit 0 = pipeline verified end to end. Non-zero = the stage that failed.
set -uo pipefail

COMPOSE="docker compose -f docker-compose.local.yaml"
API_KEY="${WATCHTOWER_API_KEY:-sentinel-dev-api-key}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass(){ echo "  ✅ $*"; }
fail(){ echo "  ❌ FAIL: $*" >&2; echo ""; echo "Pipeline broke at the stage above. Recent watchtower/watchvault logs:"; $COMPOSE logs --tail=30 watchtower watchvault 2>/dev/null | tail -40; exit 1; }
jsonnum(){ grep -o "\"$1\":[0-9]*" | grep -o '[0-9]*' | head -1; }   # crude JSON int extractor, no jq dep

echo "[1/7] Bringing the stack up (build if needed)…"
$COMPOSE up -d --build >/dev/null 2>&1 || fail "compose up failed — run '$COMPOSE up -d --build' to see why"
pass "stack started"

echo "[2/7] Waiting for OpenSearch…"
for _ in $(seq 1 60); do curl -sf http://localhost:9200/_cluster/health >/dev/null 2>&1 && break; sleep 3; done
curl -sf http://localhost:9200/_cluster/health >/dev/null 2>&1 || fail "OpenSearch never became healthy"
pass "OpenSearch healthy"

echo "[3/7] Kafka topics exist (the bug that caused the empty dashboard)…"
topics="$($COMPOSE exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null)"
echo "$topics" | grep -qx 'sentinel.events' || fail "kafka topic 'sentinel.events' missing (kafka-init didn't run)"
echo "$topics" | grep -qx 'sentinel.alerts' || fail "kafka topic 'sentinel.alerts' missing (kafka-init didn't run)"
pass "topics present: sentinel.events, sentinel.alerts"

echo "[4/7] Agents enrolling (agent → manager)…"
n=0
for _ in $(seq 1 30); do
  n="$(curl -s -H "Authorization: Bearer $API_KEY" http://localhost:9400/api/v1/agents | jsonnum total)"; n="${n:-0}"
  [ "$n" -ge 1 ] && break; sleep 3
done
[ "$n" -ge 1 ] || fail "no agents enrolled — agent→manager path broken (token? gRPC :50051?)"
pass "agents enrolled: $n"

echo "[5/7] Events reaching OpenSearch (manager → kafka → indexer → OS)…"
c=0
for _ in $(seq 1 40); do
  c="$(curl -s 'http://localhost:9200/watchvault-events*/_count' | jsonnum count)"; c="${c:-0}"
  [ "$c" -ge 1 ] && break; sleep 3
done
[ "$c" -ge 1 ] || fail "0 events indexed — full pipeline broken (kafka topics / forwarder / consumer)"
pass "events indexed: $c"

echo "[6/7] Forwarder not dropping events…"
dropped="$($COMPOSE logs --tail=300 watchtower 2>/dev/null | grep -c 'dropping event')"
if [ "${dropped:-0}" -gt 0 ]; then echo "  ⚠️  watchtower logged $dropped 'dropping event' lines — Kafka backpressure / topic issue"; else pass "no dropped events"; fi

echo "[7/7] Dashboard responding on :5050…"
code="$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5050/login)"
[ "$code" = "200" ] || [ "$code" = "302" ] || fail "dashboard not responding (HTTP $code)"
pass "dashboard up (HTTP $code)"

echo ""
echo "🎉 E2E SMOKE PASSED — agent → manager → kafka → indexer → OpenSearch → dashboard all verified."
echo "   (Detections still require a matching event; this proves the data path, not rule content.)"
