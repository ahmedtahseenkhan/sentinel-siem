"""
entities.py — cross-domain entity normalization for XDR correlation.

Endpoint, cloud, identity and network telemetry each name the same real-world
entity differently:

    user :  TargetUserName="CORP\\alice"  ·  userPrincipalName="alice@corp.com"
            ·  UserId="alice"  ·  actor="alice@corp.com"
    host :  WorkstationName="WS01"  ·  host="ws01.corp.local"  ·  computer="WS01"
    ip   :  IpAddress  ·  src_ip  ·  sourceIPAddress

Correlation only works if those all collapse onto ONE canonical key. This module
is the single place that knows the per-source field aliases and the canonical
form, so detectors never hard-code one source's schema.

It also resolves an entity to the assets a response would act on
(hosts_for_user / agent_for_host) using the WatchTower inventory APIs.
"""
from __future__ import annotations

import threading
import time
from typing import Any

# ── Per-source field aliases ────────────────────────────────────────────────────
# Ordered by preference; the first present, non-empty value wins. Used both to
# read a value out of an OpenSearch _source doc and to know which fields a
# detector may aggregate on.
FIELD_ALIASES: dict[str, list[str]] = {
    "user": ["TargetUserName", "userPrincipalName", "UserId", "user",
             "actor", "user_name", "Account", "subject_user"],
    "host": ["WorkstationName", "computer", "ComputerName", "host",
             "hostname", "agent_name", "dest_host", "TargetHostName"],
    "ip":   ["IpAddress", "src_ip", "sourceIPAddress", "source_ip",
             "client_ip", "srcip", "remote_ip"],
}

# Usernames that legitimately appear from many sources — never correlate on them.
_NOISE_USERS = {"", "-", "(none)", "system", "anonymous logon", "local service",
                "network service", "n/a", "null"}


def normalize(kind: str, raw: Any) -> str:
    """Return the canonical key for an entity value, or "" if it should be
    skipped (empty, machine account, or known noise)."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    if kind == "user":
        return _normalize_user(s)
    if kind == "host":
        return _normalize_host(s)
    if kind == "ip":
        return s.lower()
    return s.lower()


def _normalize_user(s: str) -> str:
    # Down-level domain form: CORP\alice → alice
    if "\\" in s:
        s = s.rsplit("\\", 1)[-1]
    # UPN / email form: alice@corp.com → alice
    if "@" in s:
        s = s.split("@", 1)[0]
    s = s.strip().lower()
    # Machine accounts (WS01$) and noise are not real identities.
    if s.endswith("$") or s in _NOISE_USERS:
        return ""
    return s


def _normalize_host(s: str) -> str:
    s = s.strip().lower()
    # FQDN → short name: ws01.corp.local → ws01
    if "." in s and not _looks_like_ip(s):
        s = s.split(".", 1)[0]
    return s


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def field_value(source: dict, kind: str) -> str:
    """Pull the canonical entity value of `kind` out of an OpenSearch _source
    doc, trying each alias in preference order."""
    if not isinstance(source, dict):
        return ""
    for f in FIELD_ALIASES.get(kind, []):
        if f in source and source[f] not in (None, ""):
            v = normalize(kind, source[f])
            if v:
                return v
    return ""


def alias_fields(kind: str) -> list[str]:
    """Field names a detector may aggregate/query on for an entity kind."""
    return list(FIELD_ALIASES.get(kind, []))


# ── Inventory lookups (entity → assets) ─────────────────────────────────────────
# Used by the response orchestrator to turn "user alice" into the agent IDs a
# contain action must target. Best-effort + TTL-cached; never raises.

_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, Any]] = {}
_TTL = 60.0


def _cached(key: str, fn):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < _TTL:
            return hit[1]
    try:
        val = fn()
    except Exception:
        val = None
    with _cache_lock:
        _cache[key] = (now, val)
    return val


def _agents() -> list[dict]:
    """All agents from WatchTower, shaped {id, hostname, ...}. Cached."""
    def _fetch():
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/agents", method="GET", params={"limit": 1000})
        return (res or {}).get("data") or (res or {}).get("agents") or []
    return _cached("agents", _fetch) or []


def agent_for_host(host: str) -> str | None:
    """Resolve a (normalized) hostname to its agent ID, or None."""
    h = normalize("host", host)
    if not h:
        return None
    for a in _agents():
        name = normalize("host", a.get("hostname") or a.get("name") or "")
        if name and name == h:
            return a.get("id") or a.get("agent_id")
    return None


def hosts_for_user(user: str, *, os_search=None, index_pattern: str = "watchvault-events-*",
                   window_min: int = 1440) -> list[str]:
    """Best-effort set of agent IDs a user has recently been active on, so a
    contain action can isolate every host the identity touched.

    Derives host→user activity from recent events (logon/process), maps each
    host to its agent via the inventory. Returns agent IDs (de-duplicated)."""
    u = normalize("user", user)
    if not u or os_search is None:
        return []

    def _fetch():
        now_ms = int(time.time() * 1000)
        start_ms = now_ms - window_min * 60 * 1000
        # Match the user across any of its alias fields, bucket by host fields.
        should = [{"term": {f: user}} for f in alias_fields("user")]
        body = {
            "size": 0,
            "query": {"bool": {
                "must": [{"range": {"timestamp": {"gte": start_ms, "lte": now_ms}}}],
                "should": should, "minimum_should_match": 1,
            }},
            "aggs": {"by_host": {"terms": {"field": "agent_name", "size": 100}}},
        }
        res = os_search(index_pattern, body) or {}
        buckets = ((res.get("aggregations") or {}).get("by_host") or {}).get("buckets") or []
        agents: list[str] = []
        for b in buckets:
            aid = agent_for_host(b.get("key") or "")
            if aid and aid not in agents:
                agents.append(aid)
        return agents

    return _cached(f"hosts_for_user:{u}", _fetch) or []
