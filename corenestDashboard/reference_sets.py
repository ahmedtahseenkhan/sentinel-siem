"""
reference_sets.py — Named whitelists / reference sets.

A *reference set* is an operator-curated, named list of values of a single
kind — users, devices/hosts, IPs, domains, file hashes, or an arbitrary
custom field. Analysts use them to whitelist known-good entities (service
accounts, jump hosts, scanner IPs) and to keep reusable lists that other
features can consult instead of hard-coding values in individual rules or
filters.

Two tables:
    reference_sets          one row per named set (metadata)
    reference_set_entries   one row per value in a set

A set optionally maps to an OpenSearch ``field`` (e.g. ``TargetUserName``,
``agent_name``, ``src_ip``). When ``field`` is set, :func:`build_excludes`
can turn the whole set into a single ``terms`` clause so log_filters-style
suppression and active-response safelists can reference a set by name rather
than duplicating values.

This is intentionally storage-light and mirrors log_filters.py so the two
behave the same operationally (SQLite, WAL, thread-locked, import/export for
the backup tool).
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "reference_sets.db")
_LOCK = threading.Lock()

# A set's declared kind. "custom" pairs with an arbitrary ``field``.
VALID_TYPES = {"users", "devices", "hosts", "ips", "domains", "hashes", "custom"}

_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,64}$")


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS reference_sets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL UNIQUE,
                set_type    TEXT    NOT NULL DEFAULT 'custom',
                field       TEXT    NOT NULL DEFAULT '',
                description TEXT    NOT NULL DEFAULT '',
                created_by  TEXT    NOT NULL DEFAULT '',
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS reference_set_entries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                set_id      INTEGER NOT NULL REFERENCES reference_sets(id) ON DELETE CASCADE,
                value       TEXT    NOT NULL,
                note        TEXT    NOT NULL DEFAULT '',
                created_by  TEXT    NOT NULL DEFAULT '',
                created_at  INTEGER NOT NULL,
                UNIQUE(set_id, value)
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS ix_refset_entry_set ON reference_set_entries(set_id)")


# ── helpers ──────────────────────────────────────────────────────────────────

def _set_row(r: sqlite3.Row, entry_count: int) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "set_type": r["set_type"],
        "field": r["field"],
        "description": r["description"],
        "created_by": r["created_by"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
        "entry_count": entry_count,
    }


def _entry_row(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "value": r["value"],
        "note": r["note"],
        "created_by": r["created_by"],
        "created_at": r["created_at"],
    }


def _validate_set(name: str, set_type: str, field: str) -> None:
    if not name or not str(name).strip():
        raise ValueError("name required")
    if not _NAME_RE.match(str(name).strip()):
        raise ValueError("name may contain only letters, digits, space, _-. and be ≤ 64 chars")
    if set_type not in VALID_TYPES:
        raise ValueError(f"set_type must be one of {sorted(VALID_TYPES)}")
    if set_type == "custom" and not str(field).strip():
        raise ValueError("a custom set requires a 'field' (the OpenSearch field it maps to)")


def _split_values(raw) -> list[str]:
    """Accept a list, or a comma/newline-separated string, and return a
    de-duplicated, stripped list preserving first-seen order."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        parts = [str(p) for p in raw]
    else:
        parts = re.split(r"[,\n\r]+", str(raw))
    out, seen = [], set()
    for p in parts:
        v = p.strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ── set CRUD ─────────────────────────────────────────────────────────────────

def list_sets() -> list[dict]:
    with _LOCK, _conn() as c:
        rows = c.execute("SELECT * FROM reference_sets ORDER BY name COLLATE NOCASE").fetchall()
        counts = {
            r["set_id"]: r["n"]
            for r in c.execute(
                "SELECT set_id, COUNT(*) AS n FROM reference_set_entries GROUP BY set_id"
            ).fetchall()
        }
    return [_set_row(r, counts.get(r["id"], 0)) for r in rows]


def get_set(set_id: int, *, with_entries: bool = True) -> dict | None:
    with _LOCK, _conn() as c:
        r = c.execute("SELECT * FROM reference_sets WHERE id = ?", (set_id,)).fetchone()
        if r is None:
            return None
        entries = c.execute(
            "SELECT * FROM reference_set_entries WHERE set_id = ? ORDER BY value COLLATE NOCASE",
            (set_id,),
        ).fetchall()
    out = _set_row(r, len(entries))
    if with_entries:
        out["entries"] = [_entry_row(e) for e in entries]
    return out


def create_set(*, name: str, set_type: str = "custom", field: str = "",
               description: str = "", created_by: str = "") -> dict:
    _validate_set(name, set_type, field)
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        try:
            cur = c.execute(
                """INSERT INTO reference_sets
                   (name, set_type, field, description, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (name.strip(), set_type, field.strip(), description or "", created_by or "", now, now),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"a reference set named '{name.strip()}' already exists")
        new_id = cur.lastrowid
    return get_set(new_id)  # type: ignore[return-value]


def update_set(set_id: int, **changes) -> dict | None:
    current = get_set(set_id, with_entries=False)
    if current is None:
        return None
    merged = {**current, **{k: v for k, v in changes.items() if v is not None}}
    _validate_set(merged["name"], merged["set_type"], merged["field"])
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        try:
            c.execute(
                """UPDATE reference_sets
                   SET name=?, set_type=?, field=?, description=?, updated_at=?
                   WHERE id=?""",
                (merged["name"].strip(), merged["set_type"], merged["field"].strip(),
                 merged["description"], now, set_id),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"a reference set named '{merged['name']}' already exists")
    return get_set(set_id)


def delete_set(set_id: int) -> bool:
    with _LOCK, _conn() as c:
        cur = c.execute("DELETE FROM reference_sets WHERE id = ?", (set_id,))
        return cur.rowcount > 0


# ── entry CRUD ───────────────────────────────────────────────────────────────

def add_entries(set_id: int, values, *, note: str = "", created_by: str = "") -> dict:
    """Bulk-add values to a set. Ignores duplicates. Returns
    ``{"added": n, "skipped": m}``. Raises KeyError if the set is missing."""
    if get_set(set_id, with_entries=False) is None:
        raise KeyError("reference set not found")
    vals = _split_values(values)
    if not vals:
        raise ValueError("no values provided")
    now = int(time.time() * 1000)
    added = 0
    with _LOCK, _conn() as c:
        for v in vals:
            try:
                c.execute(
                    """INSERT INTO reference_set_entries (set_id, value, note, created_by, created_at)
                       VALUES (?,?,?,?,?)""",
                    (set_id, v, note or "", created_by or "", now),
                )
                added += 1
            except sqlite3.IntegrityError:
                pass  # duplicate within this set
        c.execute("UPDATE reference_sets SET updated_at=? WHERE id=?", (now, set_id))
    return {"added": added, "skipped": len(vals) - added}


def remove_entry(set_id: int, entry_id: int) -> bool:
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        cur = c.execute(
            "DELETE FROM reference_set_entries WHERE id = ? AND set_id = ?",
            (entry_id, set_id),
        )
        if cur.rowcount:
            c.execute("UPDATE reference_sets SET updated_at=? WHERE id=?", (now, set_id))
        return cur.rowcount > 0


# ── consumers (suppression / safelists) ──────────────────────────────────────

def as_values(name: str) -> list[str]:
    """All values in the named set (case-insensitive name match). Empty list
    if the set does not exist."""
    with _LOCK, _conn() as c:
        r = c.execute(
            "SELECT id FROM reference_sets WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if r is None:
            return []
        rows = c.execute(
            "SELECT value FROM reference_set_entries WHERE set_id = ?", (r["id"],)
        ).fetchall()
    return [x["value"] for x in rows]


def contains(name: str, value: str) -> bool:
    """True if ``value`` is present in the named set."""
    if value is None:
        return False
    return str(value) in set(as_values(name))


def build_excludes() -> list[dict]:
    """Return OpenSearch ``terms`` clauses (one per set that declares a
    ``field`` and has entries) suitable for a ``must_not`` block. Lets
    suppression reference whole sets by field."""
    clauses: list[dict] = []
    for s in list_sets():
        field = (s.get("field") or "").strip()
        if not field or not s.get("entry_count"):
            continue
        vals = as_values(s["name"])
        if vals:
            clauses.append({"terms": {field: vals}})
    return clauses


# ── backup hooks ─────────────────────────────────────────────────────────────

def export_all() -> list[dict]:
    """Full snapshot (sets + their entries) for the backup tool."""
    out = []
    for s in list_sets():
        full = get_set(s["id"])
        if full:
            out.append(full)
    return out


def import_all(sets: list[dict], *, replace: bool = False, created_by: str = "") -> int:
    if not isinstance(sets, list):
        raise ValueError("sets must be a list")
    inserted = 0
    with _LOCK, _conn() as c:
        if replace:
            c.execute("DELETE FROM reference_set_entries")
            c.execute("DELETE FROM reference_sets")
        now = int(time.time() * 1000)
        for s in sets:
            try:
                _validate_set(s.get("name"), s.get("set_type", "custom"), s.get("field", ""))
            except Exception:
                continue
            try:
                cur = c.execute(
                    """INSERT INTO reference_sets
                       (name, set_type, field, description, created_by, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (str(s["name"]).strip(), s.get("set_type", "custom"), s.get("field", ""),
                     s.get("description", ""), created_by or s.get("created_by", ""), now, now),
                )
            except sqlite3.IntegrityError:
                continue
            sid = cur.lastrowid
            for e in (s.get("entries") or []):
                v = str(e.get("value", "")).strip() if isinstance(e, dict) else str(e).strip()
                if not v:
                    continue
                try:
                    c.execute(
                        """INSERT INTO reference_set_entries (set_id, value, note, created_by, created_at)
                           VALUES (?,?,?,?,?)""",
                        (sid, v, e.get("note", "") if isinstance(e, dict) else "",
                         created_by or "", now),
                    )
                except sqlite3.IntegrityError:
                    pass
            inserted += 1
    return inserted
