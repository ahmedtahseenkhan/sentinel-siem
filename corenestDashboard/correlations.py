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

from entities import normalize, alias_fields

# Severity ranking helper (string severities → orderable int).
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_from_count(n: int) -> str:
    return "critical" if n >= 4 else "high" if n >= 3 else "medium" if n >= 2 else "low"

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
        _ensure_columns(c)


# XDR enrichment columns added on top of the original incident table. SQLite has
# no ADD COLUMN IF NOT EXISTS, so add only what's missing (idempotent migration).
_XDR_COLUMNS = {
    "entity_type":  "TEXT NOT NULL DEFAULT 'user'",
    "mitre":        "TEXT NOT NULL DEFAULT '[]'",      # [{tactic, technique}]
    "domains":      "TEXT NOT NULL DEFAULT '[]'",      # ["endpoint","cloud",...]
    "contributing": "TEXT NOT NULL DEFAULT '[]'",      # [{domain,index,doc_id,ts,summary}]
    "risk":         "INTEGER NOT NULL DEFAULT 0",
    "case_id":      "INTEGER",                          # linked WatchTower case
}


def _ensure_columns(c) -> None:
    have = {r["name"] for r in c.execute("PRAGMA table_info(correlation_incidents)").fetchall()}
    for col, ddl in _XDR_COLUMNS.items():
        if col not in have:
            c.execute(f"ALTER TABLE correlation_incidents ADD COLUMN {col} {ddl}")


def _jload(v, default):
    try:
        return json.loads(v) if v else default
    except (TypeError, ValueError):
        return default


def _row(r) -> dict:
    keys = r.keys()
    return {
        "id": r["id"],
        "detector": r["detector"],
        "entity": r["entity"],
        "entity_type": r["entity_type"] if "entity_type" in keys else "user",
        "severity": r["severity"],
        "first_seen_ms": r["first_seen_ms"],
        "last_seen_ms": r["last_seen_ms"],
        "evidence": _jload(r["evidence"], {}),
        "mitre": _jload(r["mitre"], []) if "mitre" in keys else [],
        "domains": _jload(r["domains"], []) if "domains" in keys else [],
        "contributing": _jload(r["contributing"], []) if "contributing" in keys else [],
        "risk": (r["risk"] if "risk" in keys else 0) or 0,
        "case_id": (r["case_id"] if "case_id" in keys else None),
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
                     evidence: dict, entity_type: str = "user",
                     mitre: list | None = None, domains: list | None = None,
                     contributing: list | None = None, risk: int = 0) -> dict | None:
    """Insert or update an open incident keyed by (detector, entity).

    Returns the row as dict if newly opened (caller should notify + auto-create
    a case); returns None if an open incident already existed and was refreshed."""
    ev_json   = json.dumps(evidence, default=str)
    mitre_j   = json.dumps(mitre or [], default=str)
    domains_j = json.dumps(sorted(set(domains or [])), default=str)
    contrib_j = json.dumps(contributing or [], default=str)
    with _LOCK, _conn() as c:
        # Already open for this entity in this detector? Refresh in place.
        existing = c.execute(
            """SELECT id, notified FROM correlation_incidents
               WHERE detector = ? AND entity = ? AND resolved_at_ms IS NULL
               ORDER BY id DESC LIMIT 1""",
            (detector, entity),
        ).fetchone()
        if existing:
            c.execute(
                """UPDATE correlation_incidents
                   SET last_seen_ms = ?, evidence = ?, severity = ?,
                       mitre = ?, domains = ?, contributing = ?, risk = ?
                   WHERE id = ?""",
                (int(last_seen_ms), ev_json, severity, mitre_j, domains_j,
                 contrib_j, int(risk), existing["id"]),
            )
            return None
        cur = c.execute(
            """INSERT INTO correlation_incidents
               (detector, entity, entity_type, severity, first_seen_ms, last_seen_ms,
                evidence, mitre, domains, contributing, risk, resolved_at_ms, notified)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,0)""",
            (detector, entity, entity_type, severity, int(first_seen_ms),
             int(last_seen_ms), ev_json, mitre_j, domains_j, contrib_j, int(risk)),
        )
        new_id = cur.lastrowid
        r = c.execute(
            "SELECT * FROM correlation_incidents WHERE id = ?", (new_id,)
        ).fetchone()
    return _row(r)


def set_case_id(incident_id: int, case_id: int) -> None:
    """Link an incident to its auto-created WatchTower case."""
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE correlation_incidents SET case_id = ? WHERE id = ?",
            (int(case_id), int(incident_id)),
        )


def get_incident(incident_id: int) -> dict | None:
    with _LOCK, _conn() as c:
        r = c.execute(
            "SELECT * FROM correlation_incidents WHERE id = ?", (int(incident_id),)
        ).fetchone()
    return _row(r) if r else None


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
        entity = normalize("user", bucket.get("key") or "")
        if not entity:
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
        # Geo-resolve public IPs → distinct countries (impossible travel signal).
        countries = _distinct_countries(ips)
        # Severity scales with distinct sources; 2+ countries is impossible travel.
        distinct = max(len(set(ips)), len(set(hosts)), len(countries))
        severity = "critical" if (len(countries) >= 2 or distinct >= 4) \
            else "high" if distinct >= 3 else "medium"
        evidence = {
            "window_minutes":   window_min,
            "distinct_ips":     sorted(set(ips))[:20],
            "distinct_hosts":   sorted(set(hosts))[:20],
            "distinct_countries": sorted(countries),
            "logon_count":      int(bucket.get("doc_count") or 0),
            "first_seen_ms":    first_ms,
            "last_seen_ms":     last_ms,
        }
        contributing = [{"domain": "identity", "index": index_pattern,
                         "summary": f"logon from {len(set(ips))} IPs / {len(set(hosts))} hosts"
                                    + (f" / {len(countries)} countries" if countries else ""),
                         "ts": last_ms}]
        opened = _record_incident(
            detector="multi_location_logon",
            entity=entity,
            entity_type="user",
            severity=severity,
            first_seen_ms=first_ms,
            last_seen_ms=last_ms,
            evidence=evidence,
            mitre=[{"tactic": "Initial Access", "technique": "T1078"}],
            domains=["identity"],
            contributing=contributing,
            risk=distinct * 25,
        )
        if opened:
            new_incidents.append(opened)
    return new_incidents


def _distinct_countries(ips: list[str]) -> list[str]:
    """Best-effort distinct country codes for public IPs (cached via geo.py).
    Disabled with XDR_GEO_ENRICH=false; never raises."""
    if os.getenv("XDR_GEO_ENRICH", "true").lower() not in ("true", "1", "yes"):
        return []
    pub = list({ip for ip in ips if ip})
    if len(pub) < 2:
        return []
    try:
        import geo
        out: set[str] = set()
        for ip in pub[:20]:
            if geo.is_private(ip):
                continue
            info = geo.lookup(ip) or {}
            cc = info.get("country_code") or ""
            if cc:
                out.add(cc)
        return sorted(out)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Shared helper: bucket an index by the canonical entity within a window
# ---------------------------------------------------------------------------

def _bucket_entity(*, os_search, index: str, must: list, entity_kind: str,
                   start_ms: int, now_ms: int, sub_aggs: dict | None = None,
                   size: int = 500) -> dict[str, dict]:
    """Aggregate `index` by the entity (trying each alias field) within the
    window and return {canonical_entity: {count, first_ms, last_ms, raw, sub}}.

    Runs one terms agg per alias field and merges normalized keys, so the same
    identity collapses regardless of which field a given source populates."""
    out: dict[str, dict] = {}
    base_must = [{"range": {"timestamp": {"gte": start_ms, "lte": now_ms}}}] + list(must)
    for field in alias_fields(entity_kind):
        aggs: dict = {"first": {"min": {"field": "timestamp"}},
                      "last": {"max": {"field": "timestamp"}}}
        if sub_aggs:
            aggs.update(sub_aggs)
        body = {"size": 0, "query": {"bool": {"must": base_must}},
                "aggs": {"by_entity": {"terms": {"field": field, "size": size}, "aggs": aggs}}}
        try:
            res = os_search(index, body) or {}
        except Exception:
            continue
        for b in ((res.get("aggregations") or {}).get("by_entity") or {}).get("buckets") or []:
            ent = normalize(entity_kind, b.get("key"))
            if not ent:
                continue
            rec = out.setdefault(ent, {"count": 0, "first_ms": now_ms, "last_ms": start_ms,
                                       "raw": b.get("key"), "sub": {}})
            rec["count"] += int(b.get("doc_count") or 0)
            rec["first_ms"] = min(rec["first_ms"], int((b.get("first") or {}).get("value") or now_ms))
            rec["last_ms"] = max(rec["last_ms"], int((b.get("last") or {}).get("value") or start_ms))
            # carry sub-agg buckets (e.g. distinct dest hosts) for the caller
            for k in (sub_aggs or {}):
                rec["sub"].setdefault(k, [])
                rec["sub"][k].extend(
                    bb.get("key") for bb in ((b.get(k) or {}).get("buckets") or []) if bb.get("key")
                )
    return out


# ---------------------------------------------------------------------------
# Detector: compromised identity (signals span ≥2 domains for one user)
# ---------------------------------------------------------------------------

def detect_compromised_identity(*, os_search, events_idx: str, alerts_idx: str,
                                cloud_idx: str, window_min: int | None = None,
                                min_level: int = 10, now_ms: int | None = None) -> list[dict]:
    window_min = window_min or int(os.getenv("XDR_CI_WINDOW_MIN", "60"))
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    start_ms = now_ms - window_min * 60 * 1000

    # endpoint domain: high-severity EDR detections
    endpoint = _bucket_entity(os_search=os_search, index=alerts_idx, entity_kind="user",
                              must=[{"range": {"level": {"gte": min_level}}}],
                              start_ms=start_ms, now_ms=now_ms)
    # identity domain: AD auth failures / lockouts
    identity = _bucket_entity(os_search=os_search, index=events_idx, entity_kind="user",
                              must=[{"bool": {"should": [
                                  {"term": {"win_event_id": 4625}}, {"term": {"event_id": "4625"}},
                                  {"term": {"win_event_id": 4740}}, {"term": {"event_id": "4740"}},
                              ], "minimum_should_match": 1}}],
                              start_ms=start_ms, now_ms=now_ms)
    # cloud domain: any cloud activity for the principal
    cloud = _bucket_entity(os_search=os_search, index=cloud_idx, entity_kind="user",
                           must=[{"match_all": {}}], start_ms=start_ms, now_ms=now_ms)

    new_incidents: list[dict] = []
    all_entities = set(endpoint) | set(identity) | set(cloud)
    for ent in all_entities:
        present = []
        contributing = []
        for domain, data, idx in (("endpoint", endpoint, alerts_idx),
                                   ("identity", identity, events_idx),
                                   ("cloud", cloud, cloud_idx)):
            if ent in data:
                present.append(domain)
                d = data[ent]
                contributing.append({"domain": domain, "index": idx, "ts": d["last_ms"],
                                     "summary": f"{d['count']} {domain} event(s)"})
        if len(present) < 2:
            continue   # the whole point of XDR: cross-domain, not single-source
        first_ms = min(data[ent]["first_ms"] for _, data, _ in
                       (("e", endpoint, ""), ("i", identity, ""), ("c", cloud, "")) if ent in data)
        last_ms = max(data[ent]["last_ms"] for _, data, _ in
                      (("e", endpoint, ""), ("i", identity, ""), ("c", cloud, "")) if ent in data)
        severity = "critical" if len(present) >= 3 else "high"
        opened = _record_incident(
            detector="compromised_identity", entity=ent, entity_type="user",
            severity=severity, first_seen_ms=first_ms, last_seen_ms=last_ms,
            evidence={"domains": present, "window_minutes": window_min,
                      "contributing": contributing},
            mitre=[{"tactic": "Initial Access", "technique": "T1078"},
                   {"tactic": "Credential Access", "technique": "T1110"}],
            domains=present, contributing=contributing, risk=len(present) * 40,
        )
        if opened:
            new_incidents.append(opened)
    return new_incidents


# ---------------------------------------------------------------------------
# Detector: lateral movement (one entity authenticating to many hosts)
# ---------------------------------------------------------------------------

def detect_lateral_movement(*, os_search, events_idx: str, window_min: int | None = None,
                            min_hosts: int | None = None, now_ms: int | None = None,
                            **_ignore) -> list[dict]:
    window_min = window_min or int(os.getenv("XDR_LM_WINDOW_MIN", "30"))
    min_hosts = min_hosts or int(os.getenv("XDR_LM_MIN_HOSTS", "5"))
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    start_ms = now_ms - window_min * 60 * 1000

    users = _bucket_entity(
        os_search=os_search, index=events_idx, entity_kind="user",
        must=[{"bool": {"should": [
            {"term": {"win_event_id": 4624}}, {"term": {"event_id": "4624"}},
            {"term": {"win_event_id": 4648}}, {"term": {"event_id": "4648"}},
        ], "minimum_should_match": 1}}],
        start_ms=start_ms, now_ms=now_ms,
        sub_aggs={"dest_hosts": {"terms": {"field": "WorkstationName", "size": 100}}},
    )
    new_incidents: list[dict] = []
    for ent, d in users.items():
        dest = sorted({normalize("host", h) for h in d["sub"].get("dest_hosts", []) if h})
        dest = [h for h in dest if h]
        if len(dest) < min_hosts:
            continue
        severity = "critical" if len(dest) >= min_hosts * 2 else "high"
        contributing = [{"domain": "endpoint", "index": events_idx, "ts": d["last_ms"],
                         "summary": f"authenticated to {len(dest)} hosts"}]
        opened = _record_incident(
            detector="lateral_movement", entity=ent, entity_type="user",
            severity=severity, first_seen_ms=d["first_ms"], last_seen_ms=d["last_ms"],
            evidence={"distinct_hosts": dest[:30], "host_count": len(dest),
                      "window_minutes": window_min},
            mitre=[{"tactic": "Lateral Movement", "technique": "T1021"}],
            domains=["endpoint"], contributing=contributing, risk=len(dest) * 10,
        )
        if opened:
            new_incidents.append(opened)
    return new_incidents


# ---------------------------------------------------------------------------
# Detector: data exfiltration (endpoint mass-read + cloud egress, same user)
# ---------------------------------------------------------------------------

def detect_data_exfiltration(*, os_search, events_idx: str, cloud_idx: str,
                             window_min: int | None = None, min_endpoint: int | None = None,
                             min_cloud: int | None = None, now_ms: int | None = None,
                             **_ignore) -> list[dict]:
    window_min = window_min or int(os.getenv("XDR_EXFIL_WINDOW_MIN", "60"))
    min_endpoint = min_endpoint or int(os.getenv("XDR_EXFIL_MIN_ENDPOINT", "100"))
    min_cloud = min_cloud or int(os.getenv("XDR_EXFIL_MIN_CLOUD", "50"))
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    start_ms = now_ms - window_min * 60 * 1000

    endpoint = _bucket_entity(os_search=os_search, index=events_idx, entity_kind="user",
                              must=[{"bool": {"should": [
                                  {"match": {"category": "file"}},
                                  {"term": {"event_type": "file_read"}},
                                  {"match": {"action": "removable"}},
                              ], "minimum_should_match": 1}}],
                              start_ms=start_ms, now_ms=now_ms)
    cloud = _bucket_entity(os_search=os_search, index=cloud_idx, entity_kind="user",
                           must=[{"bool": {"should": [
                               {"wildcard": {"eventName": "*Get*"}},
                               {"wildcard": {"eventName": "*Download*"}},
                               {"wildcard": {"eventName": "*List*"}},
                           ], "minimum_should_match": 1}}],
                           start_ms=start_ms, now_ms=now_ms)

    new_incidents: list[dict] = []
    for ent in set(endpoint) & set(cloud):   # cross-domain: must appear in BOTH
        ep, cl = endpoint[ent], cloud[ent]
        if ep["count"] < min_endpoint and cl["count"] < min_cloud:
            continue
        first_ms = min(ep["first_ms"], cl["first_ms"])
        last_ms = max(ep["last_ms"], cl["last_ms"])
        contributing = [
            {"domain": "endpoint", "index": events_idx, "ts": ep["last_ms"],
             "summary": f"{ep['count']} file/USB events"},
            {"domain": "cloud", "index": cloud_idx, "ts": cl["last_ms"],
             "summary": f"{cl['count']} cloud egress events"},
        ]
        opened = _record_incident(
            detector="data_exfiltration", entity=ent, entity_type="user",
            severity="critical", first_seen_ms=first_ms, last_seen_ms=last_ms,
            evidence={"endpoint_events": ep["count"], "cloud_events": cl["count"],
                      "window_minutes": window_min, "contributing": contributing},
            mitre=[{"tactic": "Collection", "technique": "T1119"},
                   {"tactic": "Exfiltration", "technique": "T1567"}],
            domains=["endpoint", "cloud"], contributing=contributing, risk=120,
        )
        if opened:
            new_incidents.append(opened)
    return new_incidents


def _sibling_index(index_pattern: str, kind: str) -> str:
    """Derive a sibling index pattern, e.g. watchvault-events-* → watchvault-<kind>-*."""
    prefix = index_pattern.split("-events", 1)[0] if "-events" in index_pattern else \
        index_pattern.rsplit("-", 2)[0] if index_pattern.count("-") >= 2 else "watchvault"
    return f"{prefix}-{kind}-*"


def run_all(*, os_search: Callable[[str, dict], dict], index_pattern: str,
            now_ms: int | None = None) -> list[dict]:
    """Execute every registered detector. Returns newly opened incidents across
    all detectors so the caller can fan them out to notifications + cases."""
    events_idx = index_pattern
    alerts_idx = _sibling_index(index_pattern, "alerts")
    cloud_idx = _sibling_index(index_pattern, "cloud")

    incidents: list[dict] = []
    for detector in (
        lambda: detect_multi_location_logon(os_search=os_search, index_pattern=events_idx, now_ms=now_ms),
        lambda: detect_compromised_identity(os_search=os_search, events_idx=events_idx,
                                            alerts_idx=alerts_idx, cloud_idx=cloud_idx, now_ms=now_ms),
        lambda: detect_lateral_movement(os_search=os_search, events_idx=events_idx, now_ms=now_ms),
        lambda: detect_data_exfiltration(os_search=os_search, events_idx=events_idx,
                                         cloud_idx=cloud_idx, now_ms=now_ms),
    ):
        try:
            incidents.extend(detector())
        except Exception:
            continue
    return incidents
