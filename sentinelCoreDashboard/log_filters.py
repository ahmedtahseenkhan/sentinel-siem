"""
log_filters.py — Allow-list / suppress-list engine.

Operators can define filter rules that intentionally drop noisy events from
search results without changing detection rules or agent configs. Rules are
applied as ``must_not`` clauses on OpenSearch queries for the Logs explorer,
Discover, and alert dashboards.

This is *query-side* suppression: the underlying documents are still stored
in OpenSearch (so we can re-enable them by toggling the rule off), but they
are hidden from analysts. For storage savings, the same rules could later be
pushed to WatchTower and applied before indexing — the schema is designed
to forward-port to that without changes.

Rule fields:
    name            free-text label shown to analysts
    enabled         bool — when False the rule is preserved but inert
    scope           "events" | "alerts" | "both"
    match_field     OpenSearch field name (e.g. ``win_event_id``, ``agent_name``)
    match_op        one of: equals, contains, in, regex
    match_value     value the operator matches against (string or
                    comma-separated list when op=in)
    reason          why this filter exists (audit trail / future review)
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

DB_PATH = os.path.join(os.path.dirname(__file__), "log_filters.db")
_LOCK = threading.Lock()

VALID_OPS = {"equals", "contains", "in", "regex"}
VALID_SCOPES = {"events", "alerts", "both"}


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS log_filters (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                enabled       INTEGER NOT NULL DEFAULT 1,
                scope         TEXT    NOT NULL DEFAULT 'both',
                match_field   TEXT    NOT NULL,
                match_op      TEXT    NOT NULL,
                match_value   TEXT    NOT NULL,
                reason        TEXT    NOT NULL DEFAULT '',
                created_by    TEXT    NOT NULL DEFAULT '',
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL,
                match_count   INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS ix_filter_enabled ON log_filters(enabled, scope)")


def _row_to_dict(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "enabled": bool(r["enabled"]),
        "scope": r["scope"],
        "match_field": r["match_field"],
        "match_op": r["match_op"],
        "match_value": r["match_value"],
        "reason": r["reason"],
        "created_by": r["created_by"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
        "match_count": r["match_count"],
    }


def list_rules(*, scope: str | None = None, only_enabled: bool = False) -> list[dict]:
    where, args = [], []
    if scope and scope != "both":
        where.append("(scope = ? OR scope = 'both')")
        args.append(scope)
    if only_enabled:
        where.append("enabled = 1")
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""
    with _LOCK, _conn() as c:
        rows = c.execute(
            f"SELECT * FROM log_filters {sql_where} ORDER BY id DESC", args
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_rule(rule_id: int) -> dict | None:
    with _LOCK, _conn() as c:
        r = c.execute("SELECT * FROM log_filters WHERE id = ?", (rule_id,)).fetchone()
    return _row_to_dict(r) if r else None


def _validate(name, scope, match_field, match_op, match_value) -> None:
    if not name or not str(name).strip():
        raise ValueError("name required")
    if scope not in VALID_SCOPES:
        raise ValueError(f"scope must be one of {sorted(VALID_SCOPES)}")
    if not match_field or not str(match_field).strip():
        raise ValueError("match_field required")
    if match_op not in VALID_OPS:
        raise ValueError(f"match_op must be one of {sorted(VALID_OPS)}")
    if match_value is None or str(match_value) == "":
        raise ValueError("match_value required")


def create(
    *, name: str, scope: str, match_field: str, match_op: str,
    match_value: str, reason: str = "", created_by: str = "",
    enabled: bool = True,
) -> dict:
    _validate(name, scope, match_field, match_op, match_value)
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        cur = c.execute(
            """INSERT INTO log_filters
               (name, enabled, scope, match_field, match_op, match_value,
                reason, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                name.strip(), 1 if enabled else 0, scope, match_field.strip(),
                match_op, str(match_value), reason or "", created_by or "",
                now, now,
            ),
        )
        new_id = cur.lastrowid
    return get_rule(new_id)  # type: ignore[return-value]


def update(rule_id: int, **changes) -> dict | None:
    current = get_rule(rule_id)
    if current is None:
        return None
    merged = {**current, **{k: v for k, v in changes.items() if v is not None}}
    _validate(
        merged["name"], merged["scope"], merged["match_field"],
        merged["match_op"], merged["match_value"],
    )
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        c.execute(
            """UPDATE log_filters
               SET name=?, enabled=?, scope=?, match_field=?, match_op=?,
                   match_value=?, reason=?, updated_at=?
               WHERE id=?""",
            (
                merged["name"], 1 if merged["enabled"] else 0, merged["scope"],
                merged["match_field"], merged["match_op"], str(merged["match_value"]),
                merged["reason"], now, rule_id,
            ),
        )
    return get_rule(rule_id)


def delete(rule_id: int) -> bool:
    with _LOCK, _conn() as c:
        cur = c.execute("DELETE FROM log_filters WHERE id = ?", (rule_id,))
        return cur.rowcount > 0


def toggle(rule_id: int) -> dict | None:
    current = get_rule(rule_id)
    if current is None:
        return None
    return update(rule_id, enabled=not current["enabled"])


def _rule_to_clause(rule: dict) -> dict | None:
    """Convert a single filter rule into an OpenSearch query clause that
    matches the documents we want to *exclude*."""
    field = rule["match_field"]
    op = rule["match_op"]
    val = rule["match_value"]
    try:
        if op == "equals":
            # Try int first so numeric event ids match the keyword mapping.
            try:
                ival = int(val)
                return {"bool": {"should": [
                    {"term": {field: ival}},
                    {"term": {field: str(ival)}},
                ], "minimum_should_match": 1}}
            except (ValueError, TypeError):
                return {"term": {field: val}}
        if op == "contains":
            return {"wildcard": {field: f"*{val}*"}}
        if op == "in":
            parts = [p.strip() for p in str(val).split(",") if p.strip()]
            if not parts:
                return None
            return {"terms": {field: parts}}
        if op == "regex":
            return {"regexp": {field: val}}
    except Exception:
        return None
    return None


def build_excludes(scope: str) -> list[dict]:
    """Return the list of OpenSearch clauses to put in ``must_not`` for the
    given scope. Empty list if no rules apply."""
    clauses: list[dict] = []
    for rule in list_rules(scope=scope, only_enabled=True):
        c = _rule_to_clause(rule)
        if c is not None:
            clauses.append(c)
    return clauses


def apply_to_body(body: dict, scope: str) -> dict:
    """Mutate an OpenSearch query body in place to add must_not clauses for
    the active filter rules under the given scope. Returns the same body for
    chaining. Safe to call with bodies that have no ``query`` block."""
    excludes = build_excludes(scope)
    if not excludes:
        return body
    q = body.get("query") or {}
    if "bool" not in q:
        # Wrap whatever query exists into a bool.must so we can attach must_not.
        body["query"] = {"bool": {"must": [q] if q else [], "must_not": list(excludes)}}
        return body
    bool_q = q["bool"]
    existing = bool_q.get("must_not") or []
    bool_q["must_not"] = existing + excludes
    return body


def export_all() -> list[dict]:
    """Snapshot of every rule (enabled and disabled) — used by the backup tool."""
    return list_rules()


def import_all(rules: list[dict], *, replace: bool = False, created_by: str = "") -> int:
    """Restore rules from a snapshot. With replace=True the table is cleared
    first. Returns the number of rows inserted."""
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")
    inserted = 0
    with _LOCK, _conn() as c:
        if replace:
            c.execute("DELETE FROM log_filters")
        for r in rules:
            try:
                _validate(
                    r.get("name"), r.get("scope"), r.get("match_field"),
                    r.get("match_op"), r.get("match_value"),
                )
            except Exception:
                continue
            now = int(time.time() * 1000)
            c.execute(
                """INSERT INTO log_filters
                   (name, enabled, scope, match_field, match_op, match_value,
                    reason, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    r["name"], 1 if r.get("enabled", True) else 0, r["scope"],
                    r["match_field"], r["match_op"], str(r["match_value"]),
                    r.get("reason", ""), created_by or r.get("created_by", ""),
                    now, now,
                ),
            )
            inserted += 1
    return inserted
