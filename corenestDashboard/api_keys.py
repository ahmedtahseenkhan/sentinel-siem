"""
api_keys.py — Inbound REST API keys for non-interactive clients.

External tools (a SOAR platform, a script, another SIEM) authenticate to the
dashboard's ``/api/*`` surface with a bearer token instead of a browser
session:

    Authorization: Bearer  st_<prefix>_<secret>

Each key is bound to one of the existing RBAC roles, so the whole permission
machinery (READ_PROTECTED_PREFIXES, write protection, super-admin gating)
applies to API callers automatically — a key is just a principal with a role.

Only a SHA-256 hash of the full token is stored; the plaintext is shown once
at creation time and never again. Keys can be disabled, given an expiry, and
are stamped with a last-used time so stale keys are easy to spot.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "api_keys.db")
_LOCK = threading.Lock()

# Roles a key may be bound to — must be a subset of config.ROLE_HIERARCHY.
VALID_KEY_ROLES = {"viewer", "security_analyst", "admin"}

_PREFIX = "st"  # token looks like  st_<8hex>_<43url>


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT    NOT NULL,
                prefix       TEXT    NOT NULL UNIQUE,
                key_hash     TEXT    NOT NULL,
                role         TEXT    NOT NULL DEFAULT 'viewer',
                enabled      INTEGER NOT NULL DEFAULT 1,
                created_by   TEXT    NOT NULL DEFAULT '',
                created_at   INTEGER NOT NULL,
                last_used_at INTEGER,
                expires_at   INTEGER
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS ix_apikey_prefix ON api_keys(prefix)")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _row(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "prefix": r["prefix"],
        "role": r["role"],
        "enabled": bool(r["enabled"]),
        "created_by": r["created_by"],
        "created_at": r["created_at"],
        "last_used_at": r["last_used_at"],
        "expires_at": r["expires_at"],
        # Masked display form — never the secret.
        "display": f"{_PREFIX}_{r['prefix']}_…",
    }


def list_keys() -> list[dict]:
    with _LOCK, _conn() as c:
        rows = c.execute("SELECT * FROM api_keys ORDER BY id DESC").fetchall()
    return [_row(r) for r in rows]


def create_key(*, name: str, role: str = "viewer", created_by: str = "",
               expires_at: int | None = None) -> dict:
    if not name or not name.strip():
        raise ValueError("name required")
    if role not in VALID_KEY_ROLES:
        raise ValueError(f"role must be one of {sorted(VALID_KEY_ROLES)}")
    prefix = secrets.token_hex(4)            # 8 hex chars, public, unique
    secret = secrets.token_urlsafe(32)       # the secret part
    token = f"{_PREFIX}_{prefix}_{secret}"   # full plaintext, shown once
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        c.execute(
            """INSERT INTO api_keys (name, prefix, key_hash, role, enabled, created_by, created_at, expires_at)
               VALUES (?,?,?,?,1,?,?,?)""",
            (name.strip(), prefix, _hash(token), role, created_by or "", now, expires_at),
        )
        kid = c.execute("SELECT id FROM api_keys WHERE prefix=?", (prefix,)).fetchone()["id"]
        rec = _row(c.execute("SELECT * FROM api_keys WHERE id=?", (kid,)).fetchone())
    # Attach the plaintext exactly once — the caller must surface it now.
    rec["token"] = token
    return rec


def set_enabled(key_id: int, enabled: bool) -> dict | None:
    with _LOCK, _conn() as c:
        cur = c.execute("UPDATE api_keys SET enabled=? WHERE id=?", (1 if enabled else 0, key_id))
        if cur.rowcount == 0:
            return None
        return _row(c.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone())


def delete_key(key_id: int) -> bool:
    with _LOCK, _conn() as c:
        return c.execute("DELETE FROM api_keys WHERE id=?", (key_id,)).rowcount > 0


def authenticate(token: str) -> tuple[str, str] | None:
    """Resolve a bearer token to ``(principal_name, role)`` or None.

    Validates format, hash match, enabled flag and expiry, and stamps
    last-used. The principal name is ``apikey:<name>`` so audit rows make the
    non-interactive caller obvious.
    """
    if not token:
        return None
    token = token.strip()
    parts = token.split("_")
    if len(parts) < 3 or parts[0] != _PREFIX:
        return None
    prefix = parts[1]
    with _LOCK, _conn() as c:
        r = c.execute("SELECT * FROM api_keys WHERE prefix=?", (prefix,)).fetchone()
        if r is None or not r["enabled"]:
            return None
        if not secrets.compare_digest(r["key_hash"], _hash(token)):
            return None
        if r["expires_at"] and int(time.time() * 1000) > r["expires_at"]:
            return None
        c.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (int(time.time() * 1000), r["id"]))
        return f"apikey:{r['name']}", r["role"]
