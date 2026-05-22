"""
correlations.py — Stateful detection rules that Sigma can't express.

Sigma rules evaluate a single event in isolation. Some attacks (impossible
travel, parallel sessions, brute-force fan-out) are only visible when you
join *multiple* events for the same entity inside a time window. This module
runs those joins as scheduled OpenSearch aggregations and writes incidents
into a local SQLite table.

Current detectors:
    multi_location_logon
        For each TargetUserName with ≥2 distinct IpAddress (or distinct
        WorkstationName) inside the last N minutes, open an incident.
        The classic "AD user logs in from two places" question.

New detectors slot in by adding a function and wiring it into run_all().
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Callable

DB_PATH = os.path.join(os.path.dirname(__file__), "correlations.db")
_LOCK = threading.Lock()

# Defaults — operators override via /api/correlations/config (future) or env.
WINDOW_MINUTES = int(os.getenv("CORR_WINDOW_MIN", "10"))
MIN_DISTINCT_IPS = int(os.getenv("CORR_MIN_IPS", "2"))


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS correlation_incidents (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                detector      TEXT    NOT NULL,
                entity        TEXT    NOT NULL,
                severity      TEXT    NOT NULL DEFAULT 'high',
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                evidence      TEXT    NOT NULL DEFAULT '{}',
                resolved_at_ms INTEGER,
                notified      INTEGER NOT NULL DEFAULT 0,
                UNIQUE(detector, entity, first_seen_ms)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS ix_corr_open ON correlation_incidents(resolved_at_ms, detector)"
        )


def _row(r) -> dict:
    return {
        "id": r["id"],
        "detector": r["detector"],
        "entity": r["entity"],
        "severity": r["severity"],
        "first_seen_ms": r["first_seen_ms"],
        "last_seen_ms": r["last_seen_ms"],
        "evidence": json.loads(r["evidence"] or "{}"),
        "resolved_at_ms": r["resolved_at_ms"],
        "notified": bool(r["notified"]),
        "status": "resolved" if r["resolved_at_ms"] else "open",
    }


def list_incidents(*, status: str = "open", detector: str | None = None,
                   size: int = 200) -> list[dict]:
    where, args = [], []
    if status == "open":
        where.append("resolved_at_ms IS NULL")
    elif status == "resolved":
        where.append("resolved_at_ms IS NOT NULL")
    if detector:
        where.append("detector = ?")
        args.append(detector)
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""
    with _LOCK, _conn() as c:
        rows = c.execute(
            f"SELECT * FROM correlation_incidents {sql_where} "
            f"ORDER BY last_seen_ms DESC LIMIT ?",
            [*args, int(size)],
        ).fetchall()
    return [_row(r) for r in rows]


def stats() -> dict:
    with _LOCK, _conn() as c:
        opens = c.execute(
            "SELECT COUNT(*) AS n FROM correlation_incidents WHERE resolved_at_ms IS NULL"
        ).fetchone()["n"]
        by_det = c.execute(
            """SELECT detector, COUNT(*) AS n FROM correlation_incidents
               WHERE resolved_at_ms IS NULL GROUP BY detector"""
        ).fetchall()
    return {
        "open_count": opens,
        "by_detector": {r["detector"]: r["n"] for r in by_det},
    }


def _record_incident(*, detector: str, entity: str, severity: str,
                     first_seen_ms: int, last_seen_ms: int,
                     evidence: dict) -> dict | None:
    """Insert or update an open incident keyed by (detector, entity).

    Returns the row as dict if newly opened (caller should notify); returns
    None if it was a no-op update or the entity already had an open incident
    that was just refreshed."""
    ev_json = json.dumps(evidence, default=str)
    with _LOCK, _conn() as c:
        # Already open for this entity in this detector? Just refresh.
        existing = c.execute(
            """SELECT id, notified FROM correlation_incidents
               WHERE detector = ? AND entity = ? AND resolved_at_ms IS NULL
               ORDER BY id DESC LIMIT 1""",
            (detector, entity),
        ).fetchone()
        if existing:
            c.execute(
                """UPDATE correlation_incidents
                   SET last_seen_ms = ?, evidence = ?
                   WHERE id = ?""",
                (int(last_seen_ms), ev_json, existing["id"]),
            )
            return None
        cur = c.execute(
            """INSERT INTO correlation_incidents
               (detector, entity, severity, first_seen_ms, last_seen_ms,
                evidence, resolved_at_ms, notified)
               VALUES (?,?,?,?,?,?,NULL,0)""",
            (detector, entity, severity, int(first_seen_ms),
             int(last_seen_ms), ev_json),
        )
        new_id = cur.lastrowid
        r = c.execute(
            "SELECT * FROM correlation_incidents WHERE id = ?", (new_id,)
        ).fetchone()
    return _row(r)


def mark_notified(incident_id: int) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE correlation_incidents SET notified = 1 WHERE id = ?",
            (incident_id,),
        )


def resolve_incident(incident_id: int) -> bool:
    """Manually mark an incident as resolved (analyst acknowledged)."""
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        cur = c.execute(
            """UPDATE correlation_incidents
               SET resolved_at_ms = ? WHERE id = ? AND resolved_at_ms IS NULL""",
            (now, incident_id),
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Detector: multi-location logon
# ---------------------------------------------------------------------------

def detect_multi_location_logon(
    *, os_search: Callable[[str, dict], dict],
    index_pattern: str,
    window_min: int = WINDOW_MINUTES,
    min_distinct_ips: int = MIN_DISTINCT_IPS,
    now_ms: int | None = None,
) -> list[dict]:
    """Run the aggregation and persist incidents.

    Args:
        os_search: callable matching ``_os_search(index, body) -> dict``.
        index_pattern: e.g. "watchvault-events-*".
        window_min: look-back window in minutes.
        min_distinct_ips: incident threshold for unique IPs+workstations.
        now_ms: override "now" (for tests). Defaults to wall clock.

    Returns the list of NEWLY opened incidents (so callers can notify).
    """
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    start_ms = now_ms - window_min * 60 * 1000

    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start_ms, "lte": now_ms}}},
                    {"bool": {"should": [
                        {"term": {"win_event_id": 4624}},
                        {"term": {"event_id": "4624"}},
                    ], "minimum_should_match": 1}},
                ],
                # Filter out machine/anonymous accounts that legitimately
                # appear from many sources — noise reduction.
                "must_not": [
                    {"wildcard": {"TargetUserName": "*$"}},
                    {"term": {"TargetUserName": "ANONYMOUS LOGON"}},
                    {"term": {"TargetUserName": "SYSTEM"}},
                ],
            }
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "TargetUserName", "size": 500, "missing": "(none)"},
                "aggs": {
                    "ips":   {"terms": {"field": "IpAddress",       "size": 50}},
                    "hosts": {"terms": {"field": "WorkstationName", "size": 50}},
                    "first": {"min":   {"field": "timestamp"}},
                    "last":  {"max":   {"field": "timestamp"}},
                },
            }
        },
    }

    try:
        res = os_search(index_pattern, body) or {}
    except Exception:
        return []

    new_incidents: list[dict] = []
    for bucket in ((res.get("aggregations") or {}).get("by_user") or {}).get("buckets") or []:
        user = bucket.get("key") or ""
        if not user or user == "(none)":
            continue
        ip_buckets = ((bucket.get("ips") or {}).get("buckets") or [])
        host_buckets = ((bucket.get("hosts") or {}).get("buckets") or [])
        # Drop empty / link-local addresses before counting.
        ips = [b["key"] for b in ip_buckets
               if b.get("key") and b["key"] not in ("-", "::1", "127.0.0.1", "0.0.0.0")]
        hosts = [b["key"] for b in host_buckets if b.get("key")]
        if len(set(ips)) < min_distinct_ips and len(set(hosts)) < min_distinct_ips:
            continue
        first_ms = int(((bucket.get("first") or {}).get("value") or start_ms))
        last_ms  = int(((bucket.get("last")  or {}).get("value") or now_ms))
        # Severity: more sources → higher severity.
        distinct = max(len(set(ips)), len(set(hosts)))
        severity = "critical" if distinct >= 4 else "high" if distinct >= 3 else "medium"
        evidence = {
            "window_minutes": window_min,
            "distinct_ips":   sorted(set(ips))[:20],
            "distinct_hosts": sorted(set(hosts))[:20],
            "logon_count":    int(bucket.get("doc_count") or 0),
            "first_seen_ms":  first_ms,
            "last_seen_ms":   last_ms,
        }
        opened = _record_incident(
            detector="multi_location_logon",
            entity=user,
            severity=severity,
            first_seen_ms=first_ms,
            last_seen_ms=last_ms,
            evidence=evidence,
        )
        if opened:
            new_incidents.append(opened)
    return new_incidents


def run_all(*, os_search: Callable[[str, dict], dict], index_pattern: str,
            now_ms: int | None = None) -> list[dict]:
    """Execute every registered detector. Returns newly opened incidents
    across all detectors so the caller can fan them out to notifications."""
    incidents: list[dict] = []
    incidents.extend(
        detect_multi_location_logon(
            os_search=os_search, index_pattern=index_pattern, now_ms=now_ms,
        )
    )
    return incidents
