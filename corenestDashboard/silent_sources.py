"""
silent_sources.py — Detect log sources that have gone quiet.

A "source" is anything that should be sending events to WatchVault:
  - a WatchNode agent (Windows/Linux endpoint)
  - a syslog-integrated device (firewall, switch, router)
  - any other producer that lands docs in watchvault-events-*.

For each source we track the most recent event timestamp in OpenSearch.
If the gap exceeds a configurable threshold, we record an "incident" and
emit a notification (via the existing notifier module). Incidents auto-
resolve when the source starts sending again.

Two tables:
  thresholds   — operator-defined "expected" silence threshold per source
                 pattern. Falls back to a global default when no pattern
                 matches.
  incidents    — append-only history of silent-source detections, used
                 by the UI to show "Source X has been silent for Yh".
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

DB_PATH = os.path.join(os.path.dirname(__file__), "silent_sources.db")
_LOCK = threading.Lock()

# Built-in defaults; overridden by env or operator UI.
DEFAULT_THRESHOLD_MINUTES = int(os.getenv("SILENT_DEFAULT_MIN", "15"))


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS thresholds (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                source_pattern TEXT   NOT NULL,
                kind          TEXT    NOT NULL DEFAULT 'agent',
                minutes       INTEGER NOT NULL DEFAULT 15,
                severity      TEXT    NOT NULL DEFAULT 'medium',
                enabled       INTEGER NOT NULL DEFAULT 1,
                notify        INTEGER NOT NULL DEFAULT 1,
                reason        TEXT    NOT NULL DEFAULT '',
                created_by    TEXT    NOT NULL DEFAULT '',
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                source        TEXT    NOT NULL,
                kind          TEXT    NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                gap_minutes   INTEGER NOT NULL,
                threshold_min INTEGER NOT NULL,
                severity      TEXT    NOT NULL,
                first_seen_silent_ms INTEGER NOT NULL,
                resolved_at_ms INTEGER,
                notified      INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS ix_inc_open ON incidents(resolved_at_ms, source)")


# ── Threshold CRUD ──────────────────────────────────────────────────────────
def _row_to_threshold(r) -> dict:
    return {
        "id": r["id"],
        "source_pattern": r["source_pattern"],
        "kind": r["kind"],
        "minutes": r["minutes"],
        "severity": r["severity"],
        "enabled": bool(r["enabled"]),
        "notify": bool(r["notify"]),
        "reason": r["reason"],
        "created_by": r["created_by"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def list_thresholds() -> list[dict]:
    with _LOCK, _conn() as c:
        rows = c.execute("SELECT * FROM thresholds ORDER BY id DESC").fetchall()
    return [_row_to_threshold(r) for r in rows]


def create_threshold(*, source_pattern: str, kind: str = "agent", minutes: int,
                     severity: str = "medium", enabled: bool = True,
                     notify: bool = True, reason: str = "",
                     created_by: str = "") -> dict:
    if not source_pattern.strip():
        raise ValueError("source_pattern required")
    if kind not in ("agent", "syslog", "any"):
        raise ValueError("kind must be agent|syslog|any")
    minutes = int(minutes)
    if minutes < 1:
        raise ValueError("minutes must be ≥ 1")
    if severity not in ("low", "medium", "high", "critical"):
        raise ValueError("severity must be low|medium|high|critical")
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        cur = c.execute(
            """INSERT INTO thresholds
               (source_pattern, kind, minutes, severity, enabled, notify,
                reason, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                source_pattern.strip(), kind, minutes, severity,
                1 if enabled else 0, 1 if notify else 0,
                reason or "", created_by or "", now, now,
            ),
        )
        new_id = cur.lastrowid
    return get_threshold(new_id)  # type: ignore[return-value]


def get_threshold(threshold_id: int) -> dict | None:
    with _LOCK, _conn() as c:
        r = c.execute("SELECT * FROM thresholds WHERE id = ?", (threshold_id,)).fetchone()
    return _row_to_threshold(r) if r else None


def update_threshold(threshold_id: int, **changes) -> dict | None:
    cur = get_threshold(threshold_id)
    if cur is None:
        return None
    merged = {**cur, **{k: v for k, v in changes.items() if v is not None}}
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        c.execute(
            """UPDATE thresholds
               SET source_pattern=?, kind=?, minutes=?, severity=?, enabled=?,
                   notify=?, reason=?, updated_at=?
               WHERE id=?""",
            (
                merged["source_pattern"], merged["kind"], int(merged["minutes"]),
                merged["severity"], 1 if merged["enabled"] else 0,
                1 if merged["notify"] else 0, merged["reason"], now,
                threshold_id,
            ),
        )
    return get_threshold(threshold_id)


def delete_threshold(threshold_id: int) -> bool:
    with _LOCK, _conn() as c:
        cur = c.execute("DELETE FROM thresholds WHERE id = ?", (threshold_id,))
        return cur.rowcount > 0


def _pattern_match(pattern: str, source: str) -> bool:
    """Case-insensitive glob match: '*' wildcard, exact otherwise.

    "*"             matches any source
    "win-*"         matches "win-server-01", "WIN-DC"
    "firewall-a"    exact match only
    """
    pattern = (pattern or "").lower()
    source = (source or "").lower()
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == source
    import fnmatch
    return fnmatch.fnmatchcase(source, pattern)


def resolve_threshold(source: str, kind: str) -> tuple[int, str, bool, bool]:
    """Return (minutes, severity, enabled, notify) for the most-specific
    matching threshold. Falls back to DEFAULT_THRESHOLD_MINUTES."""
    matched = None
    matched_score = -1
    for t in list_thresholds():
        if not t["enabled"]:
            continue
        if t["kind"] not in ("any", kind):
            continue
        if not _pattern_match(t["source_pattern"], source):
            continue
        # More specific patterns (no wildcards) win over '*'.
        score = (0 if t["source_pattern"] == "*"
                 else 1 if "*" in t["source_pattern"] else 2)
        if score > matched_score:
            matched_score = score
            matched = t
    if matched is None:
        return DEFAULT_THRESHOLD_MINUTES, "medium", True, True
    return matched["minutes"], matched["severity"], True, matched["notify"]


# ── Incidents ───────────────────────────────────────────────────────────────
def _row_to_incident(r) -> dict:
    return {
        "id": r["id"],
        "source": r["source"],
        "kind": r["kind"],
        "last_seen_ms": r["last_seen_ms"],
        "gap_minutes": r["gap_minutes"],
        "threshold_min": r["threshold_min"],
        "severity": r["severity"],
        "first_seen_silent_ms": r["first_seen_silent_ms"],
        "resolved_at_ms": r["resolved_at_ms"],
        "notified": bool(r["notified"]),
        "status": "resolved" if r["resolved_at_ms"] else "open",
    }


def _open_incident_for(source: str) -> dict | None:
    with _LOCK, _conn() as c:
        r = c.execute(
            """SELECT * FROM incidents
               WHERE source = ? AND resolved_at_ms IS NULL
               ORDER BY id DESC LIMIT 1""",
            (source,),
        ).fetchone()
    return _row_to_incident(r) if r else None


def record_observation(source: str, kind: str, last_seen_ms: int,
                       now_ms: int | None = None) -> dict | None:
    """Update incident state for one source.

    Returns the open incident dict if the source is currently silent past
    its threshold (newly opened or already-open), or None if healthy."""
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    gap_min = (now_ms - last_seen_ms) // 60000 if last_seen_ms > 0 else 10**9
    threshold_min, severity, enabled, notify = resolve_threshold(source, kind)
    if not enabled:
        return None

    open_inc = _open_incident_for(source)
    if gap_min >= threshold_min:
        if open_inc:
            # Update gap/last_seen on existing incident.
            with _LOCK, _conn() as c:
                c.execute(
                    """UPDATE incidents SET gap_minutes=?, last_seen_ms=?
                       WHERE id=?""",
                    (int(gap_min), int(last_seen_ms), open_inc["id"]),
                )
                r = c.execute(
                    "SELECT * FROM incidents WHERE id = ?", (open_inc["id"],)
                ).fetchone()
            return _row_to_incident(r)
        # Open a new incident.
        with _LOCK, _conn() as c:
            cur = c.execute(
                """INSERT INTO incidents
                   (source, kind, last_seen_ms, gap_minutes, threshold_min,
                    severity, first_seen_silent_ms, resolved_at_ms, notified)
                   VALUES (?,?,?,?,?,?,?,NULL,0)""",
                (source, kind, int(last_seen_ms), int(gap_min),
                 int(threshold_min), severity, now_ms),
            )
            new_id = cur.lastrowid
            r = c.execute("SELECT * FROM incidents WHERE id = ?", (new_id,)).fetchone()
        return _row_to_incident(r)

    # Healthy now — resolve any open incident.
    if open_inc:
        with _LOCK, _conn() as c:
            c.execute(
                "UPDATE incidents SET resolved_at_ms = ? WHERE id = ?",
                (now_ms, open_inc["id"]),
            )
    return None


def list_incidents(*, status: str = "open", size: int = 100) -> list[dict]:
    """status: open | resolved | all"""
    where = ""
    if status == "open":
        where = "WHERE resolved_at_ms IS NULL"
    elif status == "resolved":
        where = "WHERE resolved_at_ms IS NOT NULL"
    with _LOCK, _conn() as c:
        rows = c.execute(
            f"SELECT * FROM incidents {where} ORDER BY id DESC LIMIT ?",
            (int(size),),
        ).fetchall()
    return [_row_to_incident(r) for r in rows]


def mark_notified(incident_id: int) -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE incidents SET notified = 1 WHERE id = ?", (incident_id,))


def stats() -> dict:
    with _LOCK, _conn() as c:
        open_count = c.execute(
            "SELECT COUNT(*) AS n FROM incidents WHERE resolved_at_ms IS NULL"
        ).fetchone()["n"]
        by_sev = c.execute(
            """SELECT severity, COUNT(*) AS n FROM incidents
               WHERE resolved_at_ms IS NULL GROUP BY severity"""
        ).fetchall()
    return {
        "open_count": open_count,
        "by_severity": {r["severity"]: r["n"] for r in by_sev},
    }
