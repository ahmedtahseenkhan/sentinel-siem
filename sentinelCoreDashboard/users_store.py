"""
users_store.py — SQLite-backed dashboard user accounts.

Adds a runtime-editable layer on top of the existing env-var (DASHBOARD_USERS)
mechanism. Resolution order at login time:

    1. SQLite users (this module) — created/edited from the UI
    2. DASHBOARD_USERS env var
    3. The DASHBOARD_SUPER_ADMIN_* / DASHBOARD_ADMIN_* defaults

That ordering means an admin can lock down env-var defaults without touching
the OS, while keeping the env var available as a break-glass account.

Stored passwords are always bcrypt-hashed; plaintext is rejected.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any

try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
_LOCK = threading.Lock()

VALID_ROLES = {
    "super_admin", "administrator", "admin",
    "security_analyst", "compliance_officer", "viewer",
}


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
            CREATE TABLE IF NOT EXISTS dashboard_users (
                username     TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role         TEXT NOT NULL,
                full_name    TEXT NOT NULL DEFAULT '',
                email        TEXT NOT NULL DEFAULT '',
                enabled      INTEGER NOT NULL DEFAULT 1,
                created_by   TEXT NOT NULL DEFAULT '',
                created_at   INTEGER NOT NULL,
                updated_at   INTEGER NOT NULL,
                last_login_at INTEGER
            )
            """
        )


def _hash_password(plain: str) -> str:
    if not _bcrypt:
        raise RuntimeError(
            "bcrypt package not installed — run `pip install bcrypt` first"
        )
    return _bcrypt.hashpw(plain.encode("utf-8"), _bcrypt.gensalt(rounds=12)).decode("ascii")


MIN_PASSWORD_LEN = int(os.getenv("MIN_PASSWORD_LEN", "10"))


def _validate(username: str, role: str, password: str | None = None) -> None:
    if not username or not username.strip():
        raise ValueError("username required")
    if not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise ValueError("username may only contain letters, digits, _-.")
    if len(username) > 64:
        raise ValueError("username must be ≤ 64 characters")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
    if password is not None:
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
        if len(password) > 128:
            raise ValueError("password must be ≤ 128 characters")


def _row_to_dict(r: sqlite3.Row, *, redact: bool = True) -> dict:
    d = {
        "username": r["username"],
        "role": r["role"],
        "full_name": r["full_name"],
        "email": r["email"],
        "enabled": bool(r["enabled"]),
        "created_by": r["created_by"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
        "last_login_at": r["last_login_at"],
        "source": "db",
    }
    if not redact:
        d["password_hash"] = r["password_hash"]
    return d


def list_users() -> list[dict]:
    with _LOCK, _conn() as c:
        rows = c.execute(
            "SELECT * FROM dashboard_users ORDER BY username COLLATE NOCASE"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_user(username: str, *, redact: bool = True) -> dict | None:
    with _LOCK, _conn() as c:
        r = c.execute(
            "SELECT * FROM dashboard_users WHERE username = ?", (username,)
        ).fetchone()
    return _row_to_dict(r, redact=redact) if r else None


def create_user(
    *, username: str, password: str, role: str,
    full_name: str = "", email: str = "",
    enabled: bool = True, created_by: str = "",
) -> dict:
    _validate(username, role, password)
    if get_user(username) is not None:
        raise ValueError(f"user '{username}' already exists")
    pw_hash = _hash_password(password)
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        c.execute(
            """INSERT INTO dashboard_users
               (username, password_hash, role, full_name, email,
                enabled, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                username.strip(), pw_hash, role,
                full_name or "", email or "",
                1 if enabled else 0, created_by or "", now, now,
            ),
        )
    return get_user(username)  # type: ignore[return-value]


def update_user(
    username: str, *,
    password: str | None = None,
    role: str | None = None,
    full_name: str | None = None,
    email: str | None = None,
    enabled: bool | None = None,
) -> dict | None:
    cur = get_user(username, redact=False)
    if cur is None:
        return None
    if role is not None and role not in VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
    if password is not None and len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    new_role = role if role is not None else cur["role"]
    new_full = full_name if full_name is not None else cur["full_name"]
    new_mail = email if email is not None else cur["email"]
    new_en   = enabled if enabled is not None else cur["enabled"]
    new_hash = _hash_password(password) if password is not None else cur["password_hash"]
    now = int(time.time() * 1000)
    with _LOCK, _conn() as c:
        c.execute(
            """UPDATE dashboard_users
               SET password_hash=?, role=?, full_name=?, email=?,
                   enabled=?, updated_at=?
               WHERE username=?""",
            (new_hash, new_role, new_full, new_mail, 1 if new_en else 0, now, username),
        )
    return get_user(username)


def delete_user(username: str) -> bool:
    with _LOCK, _conn() as c:
        cur = c.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))
        return cur.rowcount > 0


def record_login(username: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE dashboard_users SET last_login_at = ? WHERE username = ?",
            (int(time.time() * 1000), username),
        )


def authenticate(username: str, password: str) -> str | None:
    """Returns the user's role if creds are valid AND the account is enabled,
    else None. Records the login timestamp on success."""
    if not _bcrypt:
        return None
    u = get_user(username, redact=False)
    if u is None or not u["enabled"]:
        return None
    try:
        ok = _bcrypt.checkpw(password.encode("utf-8"), u["password_hash"].encode("utf-8"))
    except Exception:
        return None
    if not ok:
        return None
    record_login(username)
    return u["role"]


def count() -> int:
    with _LOCK, _conn() as c:
        return c.execute("SELECT COUNT(*) AS n FROM dashboard_users").fetchone()["n"]
