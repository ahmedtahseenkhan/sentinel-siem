"""
audit_log.py — Tamper-resistant record of every configuration-changing action
made through the Sentinel dashboard.

Every POST/PUT/PATCH/DELETE on a write-protected path is recorded with:
    timestamp, user, role, method, path, status, client_ip, user_agent,
    target (the resource being mutated, parsed from the path),
    request_payload (sanitized, truncated).

The store is a small SQLite DB next to the dashboard process so it survives
restarts independently of OpenSearch retention. Records are append-only from
the application's side — there is no UPDATE/DELETE API.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Iterable

DB_PATH = os.path.join(os.path.dirname(__file__), "audit_log.db")
_LOCK = threading.Lock()

# Fields scrubbed before persisting a request payload.
_SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "credential", "credentials", "private_key", "bearer", "authorization",
}

# Maximum stored size of a single request payload (JSON-encoded).
_MAX_PAYLOAD_BYTES = 8 * 1024


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    """Create the audit-log table on first run. Safe to call repeatedly."""
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS config_audit (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms        INTEGER NOT NULL,
                user         TEXT    NOT NULL,
                role         TEXT    NOT NULL,
                method       TEXT    NOT NULL,
                path         TEXT    NOT NULL,
                status       INTEGER NOT NULL,
                client_ip    TEXT    NOT NULL DEFAULT '',
                user_agent   TEXT    NOT NULL DEFAULT '',
                target       TEXT    NOT NULL DEFAULT '',
                payload      TEXT    NOT NULL DEFAULT '{}',
                action       TEXT    NOT NULL DEFAULT ''
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS ix_audit_ts ON config_audit(ts_ms DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_audit_user ON config_audit(user, ts_ms DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_audit_path ON config_audit(path)")


def _scrub(obj: Any) -> Any:
    """Recursively replace values whose key looks like a secret with '***'."""
    if isinstance(obj, dict):
        return {
            k: ("***" if k.lower() in _SECRET_KEYS else _scrub(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def _classify(method: str, path: str) -> tuple[str, str]:
    """Derive a human-friendly (target, action) from the method + path.

    Examples:
      ("PUT",    "/api/rules/files/0500-system_rules.yaml") → ("rule:0500-system_rules.yaml", "edit")
      ("DELETE", "/api/decoders/files/syslog-cisco.yaml")    → ("decoder:syslog-cisco.yaml", "delete")
      ("POST",   "/api/custom/visualizations")               → ("visualization:new", "create")
    """
    parts = [p for p in path.split("/") if p]
    target_map = {
        "rules": "rule",
        "decoders": "decoder",
        "playbooks": "playbook",
        "cases": "case",
        "custom": "custom",
        "cdb-lists": "cdb-list",
        "users": "user",
        "reports": "report",
        "logs-policy": "logs-policy",
    }
    target = "config"
    if len(parts) >= 2 and parts[0] == "api":
        kind = target_map.get(parts[1], parts[1])
        name = parts[-1] if len(parts) > 2 else "(root)"
        target = f"{kind}:{name}"

    action = {
        "POST":   "create",
        "PUT":    "edit",
        "PATCH":  "edit",
        "DELETE": "delete",
    }.get(method.upper(), method.lower())
    return target, action


def record(
    *,
    user: str,
    role: str,
    method: str,
    path: str,
    status: int,
    client_ip: str = "",
    user_agent: str = "",
    payload: Any = None,
) -> None:
    """Persist one audit row. Never raises — auditing must not break the API."""
    try:
        target, action = _classify(method, path)
        scrubbed = _scrub(payload) if payload is not None else {}
        try:
            payload_json = json.dumps(scrubbed, default=str)
        except Exception:
            payload_json = json.dumps({"_unserializable": True})
        if len(payload_json) > _MAX_PAYLOAD_BYTES:
            payload_json = payload_json[: _MAX_PAYLOAD_BYTES - 16] + '..."_truncated"}'
        with _LOCK, _conn() as c:
            c.execute(
                """INSERT INTO config_audit
                   (ts_ms, user, role, method, path, status, client_ip,
                    user_agent, target, payload, action)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    int(time.time() * 1000),
                    str(user or "")[:64],
                    str(role or "")[:32],
                    method.upper()[:8],
                    path[:512],
                    int(status or 0),
                    client_ip[:64],
                    user_agent[:256],
                    target[:256],
                    payload_json,
                    action[:32],
                ),
            )
    except Exception:
        # Auditing failures must never break the request path.
        pass


def query(
    *,
    size: int = 100,
    offset: int = 0,
    user: str | None = None,
    target_prefix: str | None = None,
    action: str | None = None,
    time_from_ms: int | None = None,
    time_to_ms: int | None = None,
    only_failures: bool = False,
) -> tuple[list[dict], int]:
    """Return (rows, total_count) for the audit-log viewer."""
    where: list[str] = []
    args: list[Any] = []
    if user:
        where.append("user = ?")
        args.append(user)
    if target_prefix:
        where.append("target LIKE ?")
        args.append(target_prefix + "%")
    if action:
        where.append("action = ?")
        args.append(action)
    if time_from_ms is not None:
        where.append("ts_ms >= ?")
        args.append(int(time_from_ms))
    if time_to_ms is not None:
        where.append("ts_ms <= ?")
        args.append(int(time_to_ms))
    if only_failures:
        where.append("status >= 400")
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""

    with _LOCK, _conn() as c:
        total_row = c.execute(
            f"SELECT COUNT(*) AS n FROM config_audit {sql_where}", args
        ).fetchone()
        total = total_row["n"] if total_row else 0
        rows = c.execute(
            f"""SELECT id, ts_ms, user, role, method, path, status,
                       client_ip, user_agent, target, payload, action
                FROM config_audit
                {sql_where}
                ORDER BY ts_ms DESC
                LIMIT ? OFFSET ?""",
            [*args, int(size), int(offset)],
        ).fetchall()

    out: list[dict] = []
    for r in rows:
        try:
            payload_obj = json.loads(r["payload"])
        except Exception:
            payload_obj = {}
        out.append(
            {
                "id": r["id"],
                "ts_ms": r["ts_ms"],
                "user": r["user"],
                "role": r["role"],
                "method": r["method"],
                "path": r["path"],
                "status": r["status"],
                "client_ip": r["client_ip"],
                "user_agent": r["user_agent"],
                "target": r["target"],
                "action": r["action"],
                "payload": payload_obj,
            }
        )
    return out, total


def stats(*, window_hours: int = 24) -> dict:
    """Summary counters for the audit-log page header."""
    cutoff = int((time.time() - window_hours * 3600) * 1000)
    with _LOCK, _conn() as c:
        total = c.execute(
            "SELECT COUNT(*) AS n FROM config_audit WHERE ts_ms >= ?", (cutoff,)
        ).fetchone()["n"]
        failures = c.execute(
            "SELECT COUNT(*) AS n FROM config_audit WHERE ts_ms >= ? AND status >= 400",
            (cutoff,),
        ).fetchone()["n"]
        by_user = c.execute(
            """SELECT user, COUNT(*) AS n
               FROM config_audit WHERE ts_ms >= ?
               GROUP BY user ORDER BY n DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()
        by_target = c.execute(
            """SELECT target, COUNT(*) AS n
               FROM config_audit WHERE ts_ms >= ?
               GROUP BY target ORDER BY n DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()
    return {
        "window_hours": window_hours,
        "total": total,
        "failures": failures,
        "by_user":   [{"user":   r["user"],   "count": r["n"]} for r in by_user],
        "by_target": [{"target": r["target"], "count": r["n"]} for r in by_target],
    }


# ---------------------------------------------------------------------------
# Flask integration helper. The dashboard's @app.before_request stashes the
# request payload + identity on flask.g; an @app.after_request hook then calls
# record(). Importing this module without Flask installed still works for tests.
# ---------------------------------------------------------------------------
def should_audit(method: str, path: str, write_prefixes: Iterable[str]) -> bool:
    """Return True if a request matches what we want to audit."""
    if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return False
    if not path.startswith("/api/"):
        return False
    # Always audit user-management + system-config edits regardless of prefix.
    if path.startswith(("/api/users", "/api/admin", "/api/notifications/config",
                        "/api/decoders/syslog", "/api/logs-policy")):
        return True
    return any(path.startswith(p) for p in write_prefixes)
