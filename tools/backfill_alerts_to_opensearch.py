#!/usr/bin/env python3
"""
backfill_alerts_to_opensearch.py
================================

One-shot recovery script for the case where WatchTower has alerts in its
Postgres store that never reached OpenSearch via the Kafka pipeline (typically
because kafka-init raced WatchTower startup, the topics were missing, and
every batch hit the DLQ).

Reads alerts from the WatchTower Postgres `alerts` table, joins agents to
get agent_name, and bulk-indexes each into `watchvault-alerts-YYYY.MM.DD`
where the date is the alert's own timestamp day (not "now") — so historical
data lands in the right per-day partition that ISM lifecycles expect.

Idempotent: the OpenSearch document `_id` is set to the Postgres `alerts.id`,
so re-running the script with the same range overwrites rather than
duplicating.

Usage (run from anywhere; defaults match the docker-compose.full.yaml /
docker-compose.local.yaml local stack):

  python3 tools/backfill_alerts_to_opensearch.py
  python3 tools/backfill_alerts_to_opensearch.py --since 2026-05-01
  python3 tools/backfill_alerts_to_opensearch.py --dry-run

Connection params can be overridden via env (SENTINEL_PG_URL, SENTINEL_OS_URL)
or flags. No extra dependencies — stdlib only (psycopg2-binary required;
install with `pip install psycopg2-binary` if missing).

Exit codes: 0 success, 1 connection/setup error, 2 indexing error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    import psycopg2
    import psycopg2.extras
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "psycopg2 not installed. Install with:\n"
        "  pip install psycopg2-binary\n"
    )
    sys.exit(1)


# ---- defaults ---------------------------------------------------------------

DEFAULT_PG_URL = os.environ.get(
    "SENTINEL_PG_URL",
    "postgres://watchtower:watchtower_dev_pass@localhost:5432/watchtower",
)
DEFAULT_OS_URL = os.environ.get("SENTINEL_OS_URL", "http://localhost:9200").rstrip("/")
DEFAULT_BATCH = 500


# ---- helpers ----------------------------------------------------------------

def parse_when(value: str | None) -> int | None:
    """Accept an ISO date (YYYY-MM-DD), full ISO datetime, or epoch (sec/ms).
    Returns epoch milliseconds, or None when value is empty/None."""
    if not value:
        return None
    s = value.strip()
    if s.isdigit():
        n = int(s)
        # treat short ints as seconds, long as ms
        return n * 1000 if n < 10**12 else n
    try:
        # Accept "2026-05-01" or "2026-05-01T12:34:56Z"
        if "T" not in s:
            s = s + "T00:00:00+00:00"
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError as exc:
        sys.stderr.write(f"invalid date {value!r}: {exc}\n")
        sys.exit(1)


def index_name_for(ts_ms: int) -> str:
    """watchvault-alerts-YYYY.MM.DD using the alert's OWN timestamp."""
    d = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return f"watchvault-alerts-{d.strftime('%Y.%m.%d')}"


def row_to_doc(row: psycopg2.extras.DictRow) -> dict:
    """Map a Postgres row to the watchvault-alerts document shape (matches
    WatchVault/internal/index/templates/watchvault-alerts.json)."""
    try:
        event_data = json.loads(row["event_data"]) if row["event_data"] else {}
    except (ValueError, TypeError):
        event_data = {"raw": row["event_data"]}
    try:
        rule_groups = json.loads(row["rule_groups"]) if row["rule_groups"] else []
    except (ValueError, TypeError):
        rule_groups = []

    # Pull event_type from event_data when present — agents tag their data
    # points with .Type (e.g. process.new) and WatchTower stores the full
    # event as JSON in event_data.
    event_type = ""
    if isinstance(event_data, dict):
        event_type = event_data.get("type", "") or event_data.get("event_type", "")

    return {
        "timestamp": int(row["timestamp"]),
        "rule_id": int(row["rule_id"]),
        "rule_level": int(row["level"]),
        "rule_description": row.get("description") or "",
        "rule_groups": rule_groups if isinstance(rule_groups, list) else [],
        "agent_id": row["agent_id"] or "",
        "agent_name": row.get("agent_name") or "",
        "title": row["title"] or "",
        "event_type": event_type,
        "event_data": event_data if isinstance(event_data, dict) else {"raw": event_data},
        "tags": {},
    }


def post_bulk(os_url: str, body: str) -> tuple[int, int, list[str]]:
    """Send one _bulk request. Returns (indexed_count, error_count, errors)."""
    req = urllib.request.Request(
        f"{os_url}/_bulk",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        return 0, 1, [f"HTTP {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}"]
    except (urllib.error.URLError, TimeoutError) as exc:
        return 0, 1, [f"connect error: {exc}"]

    if not payload.get("errors"):
        return len(payload.get("items", [])), 0, []

    errors = []
    ok = 0
    for item in payload.get("items", []):
        op = next(iter(item.values()))
        status = op.get("status", 0)
        if 200 <= status < 300:
            ok += 1
        else:
            errors.append(f"id={op.get('_id')} status={status} reason={(op.get('error') or {}).get('reason', '')}")
    return ok, len(errors), errors[:10]


# ---- main -------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[2], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pg-url", default=DEFAULT_PG_URL,
                    help=f"Postgres connection URL (env SENTINEL_PG_URL). Default: {DEFAULT_PG_URL}")
    ap.add_argument("--os-url", default=DEFAULT_OS_URL,
                    help=f"OpenSearch base URL (env SENTINEL_OS_URL). Default: {DEFAULT_OS_URL}")
    ap.add_argument("--since", default=None,
                    help="Backfill only alerts at or after this point. Accepts YYYY-MM-DD, ISO datetime, or epoch sec/ms.")
    ap.add_argument("--until", default=None,
                    help="Backfill only alerts at or before this point. Same formats as --since.")
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH,
                    help=f"Rows per bulk request. Default: {DEFAULT_BATCH}")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show what would be indexed without writing to OpenSearch.")
    args = ap.parse_args()

    since_ms = parse_when(args.since)
    until_ms = parse_when(args.until)

    # ---- Postgres ----
    try:
        conn = psycopg2.connect(args.pg_url)
    except psycopg2.Error as exc:
        sys.stderr.write(f"postgres connect failed: {exc}\n")
        return 1

    where = []
    params: list = []
    if since_ms is not None:
        where.append("a.timestamp >= %s")
        params.append(since_ms)
    if until_ms is not None:
        where.append("a.timestamp <= %s")
        params.append(until_ms)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    count_sql = f"SELECT COUNT(*) FROM alerts a {where_sql}"
    with conn.cursor() as cur:
        cur.execute(count_sql, params)
        total = cur.fetchone()[0]
    print(f"[backfill] {total:,} alerts to backfill"
          f"{' (since ' + str(args.since) + ')' if args.since else ''}"
          f"{' (until ' + str(args.until) + ')' if args.until else ''}")
    if total == 0:
        print("[backfill] nothing to do.")
        return 0

    # ---- OpenSearch reachability (skip in dry-run) ----
    if not args.dry_run:
        try:
            urllib.request.urlopen(f"{args.os_url}/", timeout=5).read()
        except (urllib.error.URLError, TimeoutError) as exc:
            sys.stderr.write(f"opensearch unreachable at {args.os_url}: {exc}\n")
            return 1

    # ---- Stream + bulk ----
    fetch_sql = f"""
        SELECT a.id, a.rule_id, a.level, a.agent_id, a.timestamp,
               a.title, a.description, a.event_data, a.rule_groups,
               COALESCE(g.hostname, '') AS agent_name
        FROM alerts a
        LEFT JOIN agents g ON g.id = a.agent_id
        {where_sql}
        ORDER BY a.id ASC
    """
    cur = conn.cursor("backfill_cursor", cursor_factory=psycopg2.extras.DictCursor)
    cur.itersize = args.batch
    cur.execute(fetch_sql, params)

    indexed = 0
    errored = 0
    bulk_lines: list[str] = []
    batch_count = 0

    def flush() -> bool:
        nonlocal indexed, errored, bulk_lines, batch_count
        if not bulk_lines:
            return True
        if args.dry_run:
            indexed += batch_count
            bulk_lines = []
            batch_count = 0
            return True
        ok, errs, sample = post_bulk(args.os_url, "".join(bulk_lines))
        indexed += ok
        errored += errs
        if sample:
            sys.stderr.write(f"[backfill] {errs} errors in batch; first few:\n")
            for s in sample:
                sys.stderr.write(f"   {s}\n")
        bulk_lines = []
        batch_count = 0
        return errs == 0

    for row in cur:
        doc = row_to_doc(row)
        index = index_name_for(doc["timestamp"])
        action = {"index": {"_index": index, "_id": str(row["id"])}}
        bulk_lines.append(json.dumps(action, separators=(",", ":")) + "\n")
        bulk_lines.append(json.dumps(doc, separators=(",", ":"), default=str) + "\n")
        batch_count += 1
        if batch_count >= args.batch:
            flush()
            print(f"[backfill] indexed {indexed:,}/{total:,} ({errored} errors)")

    flush()
    cur.close()
    conn.close()

    print(f"[backfill] done. indexed={indexed:,} errors={errored:,}"
          + (" (dry-run, nothing written)" if args.dry_run else ""))
    return 0 if errored == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
