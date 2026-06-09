"""WatchTower (Manager) and WatchVault (Indexer) API clients.

Replaces the legacy wazuh_client.py. All Wazuh-specific API calls, index
patterns and field paths are translated to the WatchTower / WatchVault
equivalents while preserving the same function signatures so that app.py
requires minimal changes.
"""
import requests
from requests.auth import HTTPBasicAuth
from config import (
    WATCHTOWER_URL,
    WATCHTOWER_API_KEY,
    WATCHVAULT_URL,
    WATCHVAULT_API_KEY,
    OPENSEARCH_URL,
    OPENSEARCH_USER,
    OPENSEARCH_PASSWORD,
    VERIFY_SSL,
    REQUEST_TIMEOUT,
    INDEX_PREFIX,
)

if not VERIFY_SSL:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Simple TTL cache — avoids re-fetching health / field-mapping metadata on
# every dashboard page load. Default TTL is 60 seconds.
# ---------------------------------------------------------------------------
import time as _time
import threading as _threading
from typing import Any, Callable, Tuple

_cache_lock = _threading.Lock()
_cache: dict[str, Tuple[float, Any]] = {}
_DEFAULT_CACHE_TTL = 60.0  # seconds


def _cached(key: str, ttl: float, fn: Callable[[], Any]) -> Any:
    """Return fn() result, using a cached value when still within TTL."""
    now = _time.monotonic()
    with _cache_lock:
        entry = _cache.get(key)
        if entry is not None:
            ts, value = entry
            if now - ts < ttl:
                return value
    # Compute outside the lock so slow calls don't block other readers.
    value = fn()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


def _invalidate_cache(key: str | None = None) -> None:
    """Remove one cache entry (or clear all if key is None)."""
    with _cache_lock:
        if key is None:
            _cache.clear()
        else:
            _cache.pop(key, None)


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def watchtower_request(path, method="GET", params=None, json_body=None, data=None, content_type=None):
    """Call WatchTower REST API.  Bearer API-key auth."""
    url = f"{WATCHTOWER_URL.rstrip('/')}{path}"
    headers = {}
    if WATCHTOWER_API_KEY:
        headers["Authorization"] = f"Bearer {WATCHTOWER_API_KEY}"
    if content_type:
        headers["Content-Type"] = content_type
    kwargs = {
        "method": method,
        "url": url,
        "headers": headers,
        "params": params or {},
        "verify": VERIFY_SSL,
        "timeout": REQUEST_TIMEOUT,
    }
    if json_body is not None:
        kwargs["json"] = json_body
    if data is not None:
        kwargs["data"] = data
    r = requests.request(**kwargs)
    r.raise_for_status()
    if not r.content:
        return {}
    try:
        return r.json()
    except Exception:
        return {"raw": r.text}


def watchvault_request(path, method="GET", json_body=None):
    """Call WatchVault REST API (search / indices / health)."""
    url = f"{WATCHVAULT_URL.rstrip('/')}{path}"
    headers = {}
    if WATCHVAULT_API_KEY:
        headers["Authorization"] = f"Bearer {WATCHVAULT_API_KEY}"
    kwargs = {"verify": VERIFY_SSL, "timeout": REQUEST_TIMEOUT, "headers": headers}
    if json_body is not None:
        kwargs["json"] = json_body
        headers["Content-Type"] = "application/json"
    r = requests.request(method, url, **kwargs)
    r.raise_for_status()
    return r.json()


def opensearch_request(path, method="GET", json_body=None):
    """Direct OpenSearch call (for queries WatchVault doesn't proxy)."""
    url = f"{OPENSEARCH_URL.rstrip('/')}{path}"
    auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
    kwargs = {"auth": auth, "verify": VERIFY_SSL, "timeout": REQUEST_TIMEOUT}
    if json_body is not None:
        kwargs["json"] = json_body
        kwargs["headers"] = {"Content-Type": "application/json"}
    r = requests.request(method, url, **kwargs)
    r.raise_for_status()
    return r.json()


def _vault_search(index_pattern, body):
    """Search via WatchVault /api/v1/search endpoint."""
    payload = {
        "index": index_pattern,
        "query": body.get("query", {"match_all": {}}),
        "from": body.get("from", 0),
        "size": body.get("size", 20),
    }
    if "sort" in body:
        payload["sort"] = body["sort"]
    res = watchvault_request("/api/v1/search", method="POST", json_body=payload)
    # Normalise to OpenSearch-like response so existing parsing code works
    hits_list = res.get("hits", [])
    total = res.get("total", len(hits_list))
    return {
        "hits": {
            "total": {"value": total, "relation": "eq"},
            "hits": [{"_source": h, "_id": h.get("_id", ""), "_index": h.get("_index", "")} for h in hits_list],
        },
        "aggregations": res.get("aggregations", {}),
        "took": res.get("took_ms", 0),
    }


def _os_search(index_pattern, body):
    """Search via OpenSearch directly — needed for aggregations which
    WatchVault's /api/v1/search passes through as raw query DSL anyway."""
    # Keep searches resilient when a pattern has no backing indices yet.
    path = f"/{index_pattern}/_search?ignore_unavailable=true&allow_no_indices=true"
    return opensearch_request(path, method="POST", json_body=body)


def _to_epoch_ms(ts):
    """Normalise any timestamp to integer epoch-milliseconds.
    Accepts int/float epoch ms or epoch seconds, ISO-8601 string (UTC), or None."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return int(ts) if ts >= 1e12 else int(ts * 1000)
    if isinstance(ts, str):
        try:
            return _to_epoch_ms(float(ts.strip()))
        except ValueError:
            pass
        from datetime import datetime, timezone
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S.000Z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return int(datetime.strptime(ts.strip(), fmt).replace(tzinfo=timezone.utc).timestamp() * 1000)
            except ValueError:
                continue
    return None


# Prefer OpenSearch for complex agg queries; WatchVault search is simpler
indexer_search = _os_search


# ---------------------------------------------------------------------------
# WatchTower direct alert queries (supplements OpenSearch when index is thin)
# ---------------------------------------------------------------------------

def get_watchtower_alerts(limit=500, offset=0, min_level=None, agent_id=None):
    """Fetch alerts from WatchTower's SQLite store via REST API."""
    try:
        params = {"limit": limit, "offset": offset}
        if min_level:
            params["min_level"] = min_level
        if agent_id:
            params["agent_id"] = agent_id
        res = watchtower_request("/api/v1/alerts", method="GET", params=params)
        return res.get("data") or [] if isinstance(res, dict) else []
    except Exception:
        return []


def get_watchtower_agents(limit=200):
    """Fetch agents from WatchTower REST API."""
    try:
        res = watchtower_request("/api/v1/agents", method="GET", params={"limit": limit})
        return res.get("data") or [] if isinstance(res, dict) else []
    except Exception:
        return []


def build_alerts_dashboard_from_wt(alerts, agents=None):
    """Build dashboard stats from WatchTower alert list (used when OpenSearch is behind)."""
    from datetime import datetime, timezone, timedelta
    agent_map = {a["id"]: a.get("hostname") or a.get("name") or a["id"] for a in (agents or []) if a.get("id")}

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_agent = {}
    by_group = {}
    timeline = {}

    for a in alerts:
        lvl = int(a.get("level", 0))
        if lvl >= 12:
            sev["critical"] += 1
        elif lvl >= 8:
            sev["high"] += 1
        elif lvl >= 4:
            sev["medium"] += 1
        else:
            sev["low"] += 1

        aid = a.get("agent_id", "")
        aname = agent_map.get(aid, aid[:8] + "…" if len(aid) > 8 else aid)
        if aname:
            by_agent[aname] = by_agent.get(aname, 0) + 1

        groups = a.get("groups") or []
        if not groups:
            title = a.get("title", "")
            # Extract group from title prefix (e.g. "Network: ..." -> "network")
            prefix = title.split(":")[0].strip().lower().replace(" ", "_") if ":" in title else "general"
            groups = [prefix]
        for g in groups:
            by_group[g] = by_group.get(g, 0) + 1

        ts_ms = a.get("timestamp", 0)
        if ts_ms:
            dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            hour_key = dt.strftime("%Y-%m-%dT%H:00:00Z")
            if hour_key not in timeline:
                timeline[hour_key] = {"key": hour_key, "critical": 0, "high": 0, "medium": 0, "low": 0}
            if lvl >= 12:
                timeline[hour_key]["critical"] += 1
            elif lvl >= 8:
                timeline[hour_key]["high"] += 1
            elif lvl >= 4:
                timeline[hour_key]["medium"] += 1
            else:
                timeline[hour_key]["low"] += 1

    top_agents = sorted([{"key": k, "count": v} for k, v in by_agent.items()], key=lambda x: -x["count"])[:10]
    top_cats = sorted([{"key": k, "count": v} for k, v in by_group.items()], key=lambda x: -x["count"])[:10]
    tl = sorted(timeline.values(), key=lambda x: x["key"])

    incidents = [a for a in alerts if int(a.get("level", 0)) >= 8][:10]
    inc_out = [{"timestamp": a.get("timestamp"), "rule_level": a.get("level"), "rule_description": a.get("description") or a.get("title"), "agent_id": a.get("agent_id"), "agent_name": agent_map.get(a.get("agent_id", ""), "")} for a in incidents]

    return {
        "total_24h": len(alerts),
        "severity_24h": sev,
        "timeline_24h_by_severity": tl,
        "top_categories": top_cats,
        "top_agents": top_agents,
        "incidents": inc_out,
    }


# ---------------------------------------------------------------------------
# Index pattern helpers
# ---------------------------------------------------------------------------

ALERTS_INDEX = f"{INDEX_PREFIX}-alerts-*"
EVENTS_INDEX = f"{INDEX_PREFIX}-events-*"
FIM_INDEX = f"{INDEX_PREFIX}-fim-*"
# Vulnerability events are emitted by the WatchNode vulnerability collector
# and indexed in watchvault-events-* with event_type="vulnerability"
VULN_INDEX = f"{INDEX_PREFIX}-events-*"
VULN_FILTER = {"term": {"event_type": "vulnerability"}}
SYSTEM_INDEX = f"{INDEX_PREFIX}-system-*"


# ---------------------------------------------------------------------------
# Agent management  (WatchTower /api/v1/agents)
# ---------------------------------------------------------------------------

def get_agents_summary():
    """Agent status summary — computed from agent list."""
    try:
        res = watchtower_request("/api/v1/agents", params={"status": ""})
        agents = res.get("data") or []
        total = res.get("total", len(agents))
        counts = {"active": 0, "disconnected": 0, "pending": 0, "never_connected": 0}
        for a in agents:
            s = (a.get("status") or "").lower()
            # streaming / running / active all mean the agent is connected
            if s in ("streaming", "running", "active"):
                s = "active"
            if s in counts:
                counts[s] += 1
        return {
            "connection": {"total": total, **counts},
            "configuration": {"synced": total, "total": total, "not_synced": 0},
        }
    except Exception:
        return {
            "connection": {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "never_connected": 0},
            "configuration": {"synced": 0, "total": 0, "not_synced": 0},
        }


def get_agents_list(limit=50, offset=0):
    """Paginated agent list — wraps WatchTower response in Wazuh-compatible envelope."""
    res = watchtower_request("/api/v1/agents")
    agents = res.get("data") or []
    total = res.get("total", len(agents))
    # Apply pagination
    page = agents[offset:offset + limit]
    items = []
    for a in page:
        # Map WatchTower agent fields → legacy field names used by app.py
        ts_heartbeat = a.get("last_heartbeat", 0)
        ts_registered = a.get("registered_at", 0)
        from datetime import datetime, timezone
        hb_iso = datetime.fromtimestamp(ts_heartbeat / 1000, tz=timezone.utc).isoformat() if ts_heartbeat else None
        reg_iso = datetime.fromtimestamp(ts_registered / 1000, tz=timezone.utc).isoformat() if ts_registered else None
        status = (a.get("status") or "pending").lower()
        if status in ("streaming", "running", "connected", "online"):
            status = "active"
        # Override with heartbeat-based status — if last heartbeat > 2 min ago, agent is offline
        if ts_heartbeat:
            age_seconds = (datetime.now(timezone.utc).timestamp() * 1000 - ts_heartbeat) / 1000
            if age_seconds > 120:
                status = "disconnected"
        elif not ts_heartbeat and ts_registered:
            status = "never_connected"
        items.append({
            "id": a.get("id", ""),
            "name": a.get("hostname") or a.get("id", ""),
            "hostname": a.get("hostname", ""),
            "ip": a.get("ip_address") or "any",
            "status": status,
            "os": {
                "name": a.get("os", ""),
                "platform": a.get("platform", ""),
                "version": "",
            },
            "version": a.get("version", ""),
            "group": [a["group_id"]] if a.get("group_id") else [],
            "groups": [a["group_id"]] if a.get("group_id") else [],
            "node_name": "WatchTower",
            "manager": "WatchTower",
            "lastKeepAlive": hb_iso,
            "last_keep_alive": hb_iso,
            "dateAdd": reg_iso,
            "date_add": reg_iso,
            "labels": a.get("labels", {}),
        })
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": total,
            "total": total,
        }
    }


def get_agent_by_id(agent_id):
    """Single agent detail."""
    try:
        res = watchtower_request(f"/api/v1/agents/{agent_id}")
        a = res.get("data") if isinstance(res.get("data"), dict) else res
        if not a or not a.get("id"):
            # Try list and filter
            res2 = watchtower_request("/api/v1/agents")
            for ag in res2.get("data", []):
                if str(ag.get("id")) == str(agent_id):
                    a = ag
                    break
            else:
                return None
        from datetime import datetime, timezone
        ts_hb = a.get("last_heartbeat", 0)
        ts_reg = a.get("registered_at", 0)
        hb_iso = datetime.fromtimestamp(ts_hb / 1000, tz=timezone.utc).isoformat() if ts_hb else None
        reg_iso = datetime.fromtimestamp(ts_reg / 1000, tz=timezone.utc).isoformat() if ts_reg else None
        status = (a.get("status") or "pending").lower()
        if status in ("streaming", "running", "connected", "online"):
            status = "active"
        if ts_hb:
            age_seconds = (datetime.now(timezone.utc).timestamp() * 1000 - ts_hb) / 1000
            if age_seconds > 120:
                status = "disconnected"
        elif not ts_hb and ts_reg:
            status = "never_connected"
        return {
            "id": a.get("id", ""),
            "name": a.get("hostname") or a.get("id", ""),
            "hostname": a.get("hostname", ""),
            "ip": a.get("ip_address") or "any",
            "status": status,
            "os": {
                "name": a.get("os", ""),
                "platform": a.get("platform", ""),
                "version": "",
            },
            "version": a.get("version", ""),
            "group": [a["group_id"]] if a.get("group_id") else [],
            "groups": [a["group_id"]] if a.get("group_id") else [],
            "node_name": "WatchTower",
            "manager": "WatchTower",
            "lastKeepAlive": hb_iso,
            "last_keep_alive": hb_iso,
            "dateAdd": reg_iso,
            "date_add": reg_iso,
            "labels": a.get("labels", {}),
        }
    except Exception:
        return None


def get_manager_status():
    """WatchTower daemon status — cached for 30 s."""
    def _fetch():
        try:
            res = watchtower_request("/api/v1/status")
            return {"data": {"affected_items": [res]}} if isinstance(res, dict) else res
        except Exception as e:
            return {"data": {"affected_items": []}, "error": str(e)}
    return _cached("manager_status", 30.0, _fetch)


# ---------------------------------------------------------------------------
# Indexer / WatchVault health
# ---------------------------------------------------------------------------

def get_indexer_health():
    """Cluster health from WatchVault — cached for 30 s."""
    def _fetch():
        try:
            res = watchvault_request("/api/v1/cluster/health")
            return res.get("data", res)
        except Exception:
            return opensearch_request("/_cluster/health")
    return _cached("indexer_health", 30.0, _fetch)


def get_indexer_info():
    """Get WatchVault / OpenSearch version info — cached for 60 s."""
    def _fetch():
        try:
            res = watchvault_request("/health")
            return {
                "ok": True,
                "name": "WatchVault",
                "cluster_name": "watchvault",
                "cluster_uuid": "",
                "version_number": res.get("version", ""),
                "version_distribution": "WatchVault",
                "tagline": "Security Event Indexer",
                "opensearch_status": res.get("opensearch_status", ""),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return _cached("indexer_info", 60.0, _fetch)


def get_indexer_indices():
    """List indices from WatchVault."""
    try:
        res = watchvault_request("/api/v1/indices")
        return res.get("data", []) if isinstance(res, dict) else res
    except Exception:
        return opensearch_request(f"/_cat/indices/{INDEX_PREFIX}-*?format=json")


def get_index_management_list(pattern="*", bytes_=None):
    """List all indices for Index Management."""
    import urllib.parse
    safe_pattern = urllib.parse.quote((pattern or "*").strip(), safe="*")
    path = f"/_cat/indices/{safe_pattern}?format=json"
    if bytes_:
        path += f"&bytes={bytes_}"
    return opensearch_request(path)


def get_manager_info():
    """WatchTower version / info — cached for 60 s."""
    def _fetch():
        try:
            res = watchtower_request("/api/v1/status")
            return {"ok": True, "info": res if isinstance(res, dict) else {}}
        except Exception:
            try:
                res = watchtower_request("/api/v1/health")
                return {"ok": True, "info": res if isinstance(res, dict) else {}}
            except Exception:
                return {"ok": False, "info": {}}
    return _cached("manager_info", 60.0, _fetch)


# ---------------------------------------------------------------------------
# Alert queries  (OpenSearch — watchvault-alerts-*)
# ---------------------------------------------------------------------------

def get_recent_alerts(size=50):
    """Recent alerts from watchvault-alerts-*."""
    body = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    return indexer_search(ALERTS_INDEX, body)


def get_alerts_by_severity():
    body = {
        "size": 0,
        "aggs": {
            "by_level": {
                "terms": {"field": "rule_level", "size": 20, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_search(ALERTS_INDEX, body)


def get_alerts_by_rule(size=10):
    body = {
        "size": 0,
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule_description.keyword", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_search(ALERTS_INDEX, body)


def get_alerts_by_user(size=10):
    """Top users by alert count — extracted from event_data.fields.user in source docs."""
    # event_data.fields.user is 'text' with no .keyword sub-field so we can't use a
    # terms aggregation. Fetch recent high-value alerts and aggregate in Python instead.
    try:
        body = {
            "size": 200,
            "sort": [{"rule_level": {"order": "desc"}}],
            "_source": ["event_data.fields.user"],
        }
        res = indexer_search(ALERTS_INDEX, body)
        from collections import Counter
        counts = Counter()
        for h in (res.get("hits") or {}).get("hits", []):
            user = ((h.get("_source") or {}).get("event_data") or {}).get("fields", {}).get("user") or ""
            if user and user not in ("", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                counts[user] += 1
        buckets = [{"key": u, "doc_count": c} for u, c in counts.most_common(size)]
        return {"aggregations": {"by_user": {"buckets": buckets}}}
    except Exception:
        return {"aggregations": {"by_user": {"buckets": []}}}


def get_alerts_timeline_24h():
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start_ms = int((now - timedelta(hours=24)).timestamp() * 1000)
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": start_ms}}},
        "aggs": {
            "by_hour": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "1h", "min_doc_count": 0},
            }
        },
    }
    return indexer_search(ALERTS_INDEX, body)


def get_alerts_severity_24h():
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start_ms = int((now - timedelta(hours=24)).timestamp() * 1000)
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": start_ms}}},
        "aggs": {
            "by_level": {
                "terms": {"field": "rule_level", "size": 20, "order": {"_count": "desc"}},
            }
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_level", {}).get("buckets", [])
        critical = high = medium = low = 0
        for b in buckets:
            level = int(b.get("key", 0))
            count = b.get("doc_count", 0)
            # Thresholds match build_alerts_dashboard_from_wt and the Alerts page KPIs:
            # Critical 12+, High 8-11, Medium 4-7, Low 0-3
            if level >= 12:
                critical += count
            elif level >= 8:
                high += count
            elif level >= 4:
                medium += count
            else:
                low += count
        return {"critical": critical, "high": high, "medium": medium, "low": low}
    except Exception:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}


def get_top_source_ips(size=20):
    """Top source IPs from alert event data — extracted in Python since IP fields are 'text'."""
    try:
        body = {
            "size": 300,
            "sort": [{"rule_level": {"order": "desc"}}],
            "_source": ["event_data.fields"],
        }
        res = indexer_search(ALERTS_INDEX, body)
        from collections import Counter
        counts = Counter()
        for h in (res.get("hits") or {}).get("hits", []):
            fields = (((h.get("_source") or {}).get("event_data") or {}).get("fields") or {})
            for ip_key in ("win_IpAddress", "src_ip", "source_ip", "raddr"):
                ip = fields.get(ip_key) or ""
                if ip and ip not in ("", "-", "0.0.0.0", "::", "::1", "127.0.0.1"):
                    counts[ip] += 1
                    break
        buckets = [{"key": ip, "doc_count": c} for ip, c in counts.most_common(size)]
        return {"aggregations": {"by_ip": {"buckets": buckets}}}
    except Exception:
        return {"aggregations": {"by_ip": {"buckets": []}}}


def get_alerts_high_level_count():
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start_ms = int((now - timedelta(hours=24)).timestamp() * 1000)
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start_ms}}},
                    {"range": {"rule_level": {"gte": 10}}},
                ]
            }
        },
    }
    return indexer_search(ALERTS_INDEX, body)


def get_mitre_techniques(size=15):
    """Synthesize MITRE technique+tactic counts from rule_groups.

    Alerts in this stack carry no native rule.mitre.* fields, so we derive the
    ATT&CK mapping from each alert's rule_groups (a keyword field, so the terms
    agg works). Each group maps to a real ATT&CK technique AND tactic so both the
    technique matrix and the tactic-coverage KPIs populate correctly.

    Returns enriched buckets: key, technique_id, technique_name, tactic
    (tactic_id, e.g. TA0011), tactic_name, doc_count.
    """
    # rule_group → (technique_id, technique_name, tactic_id, tactic_name)
    MITRE_GROUPS = {
        "credential_dumping":   ("T1003", "OS Credential Dumping",                "TA0006", "Credential Access"),
        "lateral_movement":     ("T1021", "Remote Services",                      "TA0008", "Lateral Movement"),
        "privilege_escalation": ("T1068", "Exploitation for Privilege Escalation","TA0004", "Privilege Escalation"),
        "persistence":          ("T1543", "Create or Modify System Process",      "TA0003", "Persistence"),
        "discovery":            ("T1082", "System Information Discovery",          "TA0007", "Discovery"),
        "execution":            ("T1059", "Command and Scripting Interpreter",    "TA0002", "Execution"),
        "exfiltration":         ("T1041", "Exfiltration Over C2 Channel",         "TA0010", "Exfiltration"),
        "defense_evasion":      ("T1070", "Indicator Removal",                    "TA0005", "Defense Evasion"),
        "initial_access":       ("T1190", "Exploit Public-Facing Application",    "TA0001", "Initial Access"),
        "malware":              ("T1204", "User Execution",                       "TA0002", "Execution"),
        "brute_force":          ("T1110", "Brute Force",                          "TA0006", "Credential Access"),
        "attack":               ("T1190", "Exploit Public-Facing Application",    "TA0001", "Initial Access"),
        "authentication":       ("T1078", "Valid Accounts",                       "TA0005", "Defense Evasion"),
        "ransomware":           ("T1486", "Data Encrypted for Impact",            "TA0040", "Impact"),
        "network":              ("T1071", "Application Layer Protocol",           "TA0011", "Command and Control"),
        "fim":                  ("T1565", "Data Manipulation",                    "TA0040", "Impact"),
    }
    body = {
        "size": 0,
        "aggs": {
            "by_group": {
                "terms": {"field": "rule_groups", "size": 50, "order": {"_count": "desc"}},
            }
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets_raw = (res.get("aggregations") or {}).get("by_group", {}).get("buckets", [])
        # Collapse raw groups into ATT&CK techniques (multiple groups can fold
        # into the same technique — sum their counts).
        seen = {}
        for b in buckets_raw:
            grp = (b.get("key") or "").lower()
            m = MITRE_GROUPS.get(grp)
            if not m:
                continue
            tid, tname, tac, tac_name = m
            if tid not in seen:
                seen[tid] = {
                    "key": f"{tid} {tname}",
                    "technique_id": tid,
                    "technique_name": tname,
                    "tactic": tac,
                    "tactic_name": tac_name,
                    "doc_count": 0,
                }
            seen[tid]["doc_count"] += b.get("doc_count", 0)
        buckets = sorted(seen.values(), key=lambda x: x["doc_count"], reverse=True)[:size]
        return {"aggregations": {"by_technique": {"buckets": buckets}}}
    except Exception:
        return {"aggregations": {"by_technique": {"buckets": []}}}


# ---------------------------------------------------------------------------
# Alert filters (shared)
# ---------------------------------------------------------------------------

def _alerts_filter(min_level=None, time_from=None, time_to=None, agent_name=None,
                   agent_id=None, rule_groups=None, exclude_rule_ids=None):
    must = []
    if time_from or time_to:
        r = {"range": {"timestamp": {}}}
        if time_from:
            r["range"]["timestamp"]["gte"] = _to_epoch_ms(time_from)
        if time_to:
            r["range"]["timestamp"]["lte"] = _to_epoch_ms(time_to)
        must.append(r)
    if min_level is not None:
        must.append({"range": {"rule_level": {"gte": int(min_level)}}})
    if agent_name:
        must.append({"term": {"agent_name": agent_name}})
    if agent_id is not None:
        must.append({"term": {"agent_id": str(agent_id)}})
    if rule_groups:
        groups = rule_groups if isinstance(rule_groups, (list, tuple)) else [rule_groups]
        groups = [str(g).strip() for g in groups if g]
        if groups:
            must.append({"terms": {"rule_groups": groups}})
    must_not = []
    if exclude_rule_ids:
        raw = exclude_rule_ids if isinstance(exclude_rule_ids, (list, tuple)) else [exclude_rule_ids]
        ids = [str(x).strip() for part in raw
               for x in (part.split(",") if isinstance(part, str) else [part])
               if str(x).strip()]
        if ids:
            must_not.append({"terms": {"rule_id": ids}})
    return must, must_not


def get_alerts_by_agent(size=15, min_level=None, time_from=None, time_to=None,
                        agent_name=None, agent_id=None, rule_groups=None, exclude_rule_ids=None):
    body = {
        "size": 0,
        "aggs": {
            "by_agent": {
                # agent_id is keyword — agent_name is often empty so aggregate on id
                "terms": {"field": "agent_id", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    must, must_not = _alerts_filter(min_level, time_from, time_to, agent_name, agent_id, rule_groups, exclude_rule_ids)
    if must or must_not:
        body["query"] = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    return indexer_search(ALERTS_INDEX, body)


def get_alerts_severity_over_time(days=7, interval="1d", min_level=None, time_from=None,
                                  time_to=None, agent_name=None, agent_id=None,
                                  rule_groups=None, exclude_rule_ids=None):
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(days=days)).timestamp() * 1000)
    end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
    must = [{"range": {"timestamp": {"gte": start, "lte": end}}}]
    if min_level is not None:
        must.append({"range": {"rule_level": {"gte": int(min_level)}}})
    if agent_name:
        must.append({"term": {"agent_name": agent_name}})
    if agent_id is not None:
        must.append({"term": {"agent_id": str(agent_id)}})
    if rule_groups:
        groups = rule_groups if isinstance(rule_groups, (list, tuple)) else [rule_groups]
        groups = [g for g in groups if g]
        if groups:
            must.append({"terms": {"rule_groups": groups}})
    must_not = []
    if exclude_rule_ids:
        ids = [x.strip() for x in (exclude_rule_ids if isinstance(exclude_rule_ids, (list, tuple)) else [exclude_rule_ids]) if x]
        if ids:
            must_not.append({"terms": {"rule_id": ids}})
    query = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "by_date": {
                "date_histogram": {"field": "timestamp", "calendar_interval": interval, "min_doc_count": 0},
                "aggs": {
                    "by_level": {"terms": {"field": "rule_level", "size": 15, "order": {"_count": "desc"}}},
                },
            }
        },
    }
    return indexer_search(ALERTS_INDEX, body)


def get_alerts_by_tactic(size=15, min_level=None, time_from=None, time_to=None,
                         agent_name=None, agent_id=None, rule_groups=None, exclude_rule_ids=None):
    body = {
        "size": 0,
        "aggs": {
            "by_tactic": {
                "terms": {"field": "event_data.mitre.tactic_name", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    must, must_not = _alerts_filter(min_level, time_from, time_to, agent_name, agent_id, rule_groups, exclude_rule_ids)
    if must or must_not:
        body["query"] = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    try:
        return indexer_search(ALERTS_INDEX, body)
    except Exception:
        return {"aggregations": {"by_tactic": {"buckets": []}}}


def get_alerts_cardinality(time_from=None, time_to=None, min_level=None, exclude_rule_ids=None):
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(days=7)).timestamp() * 1000)
    end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
    must = [{"range": {"timestamp": {"gte": start, "lte": end}}}]
    if min_level is not None:
        must.append({"range": {"rule_level": {"gte": int(min_level)}}})
    must_not = []
    if exclude_rule_ids:
        raw = exclude_rule_ids if isinstance(exclude_rule_ids, (list, tuple)) else [exclude_rule_ids]
        ids = [str(x).strip() for part in raw for x in (part.split(",") if isinstance(part, str) else [part]) if str(x).strip()]
        if ids:
            must_not.append({"terms": {"rule_id": ids}})
    query = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "unique_srcip": {"cardinality": {"field": "event_data.srcip"}},
            "unique_agents": {"cardinality": {"field": "agent_id"}},
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        aggs = res.get("aggregations") or {}
        return {
            "unique_src_ips": (aggs.get("unique_srcip") or {}).get("value", 0),
            "unique_agents": (aggs.get("unique_agents") or {}).get("value", 0),
            "total_events": total_val,
        }
    except Exception:
        return {"unique_src_ips": 0, "unique_agents": 0, "total_events": 0}


def get_rule_groups(size=50):
    body = {
        "size": 0,
        "aggs": {
            "by_group": {"terms": {"field": "rule_groups", "size": size, "order": {"_count": "desc"}}},
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        return [b.get("key") for b in (res.get("aggregations") or {}).get("by_group", {}).get("buckets", []) if b.get("key")]
    except Exception:
        return []


def get_alerts_by_rule_groups(size=10, time_from=None, time_to=None):
    from datetime import datetime, timezone, timedelta
    body = {"size": 0, "aggs": {"by_group": {"terms": {"field": "rule_groups", "size": size, "order": {"_count": "desc"}}}}}
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        body["query"] = {"range": {"timestamp": {"gte": start, "lte": end}}}
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_group", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_alerts_list(size=25, offset=0, time_from=None, time_to=None, min_level=None,
                    agent_name=None, rule_group=None, search=None, dsl_query=None, source_fields=None,
                    index_pattern=None):
    if dsl_query is not None and isinstance(dsl_query, dict):
        return get_alerts_list_with_dsl(size=size, offset=offset, dsl_query=dsl_query, source_fields=source_fields, index_pattern=index_pattern)
    from datetime import datetime, timezone, timedelta
    must = []
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    if min_level is not None:
        must.append({"range": {"rule_level": {"gte": int(min_level)}}})
    if agent_name:
        must.append({"bool": {"should": [
            {"term": {"agent_name.keyword": agent_name}},
            {"term": {"agent_name": agent_name}},
        ], "minimum_should_match": 1}})
    if rule_group:
        must.append({"bool": {"should": [
            {"term": {"rule_groups.keyword": rule_group}},
            {"term": {"rule_groups": rule_group}},
            {"match": {"rule_groups": rule_group}},
        ], "minimum_should_match": 1}})
    if search and search.strip():
        must.append({
            "multi_match": {
                "query": search.strip(),
                "fields": [
                    "rule_description^3",
                    "rule_groups^2",
                    "agent_name^2",
                    "agent_id",
                    "event_data.srcip",
                    "event_data.dstuser",
                    "title",
                ],
                "type": "best_fields",
                "operator": "or",
            },
        })
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {
        "size": min(size, 100),
        "from": offset,
        "query": query,
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    if source_fields:
        body["_source"] = source_fields
    res = indexer_search(ALERTS_INDEX, body)
    hits = (res.get("hits") or {}).get("hits", [])
    total = (res.get("hits") or {}).get("total") or {}
    total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
    return {"hits": hits, "total": total_val}


def _normalize_query_timestamps(node):
    """Recursively walk a query DSL node and convert any string timestamp
    range values to epoch-millisecond integers (required by epoch_millis mapping)."""
    if not isinstance(node, (dict, list)):
        return node
    if isinstance(node, list):
        return [_normalize_query_timestamps(item) for item in node]
    out = {}
    for k, v in node.items():
        if k == "range" and isinstance(v, dict):
            new_range = {}
            for field, bounds in v.items():
                if field == "timestamp" and isinstance(bounds, dict):
                    new_range[field] = {
                        bk: _to_epoch_ms(bv) if isinstance(bv, str) else bv
                        for bk, bv in bounds.items()
                    }
                else:
                    new_range[field] = bounds
            out[k] = new_range
        else:
            out[k] = _normalize_query_timestamps(v)
    return out


def get_alerts_list_with_dsl(size=25, offset=0, dsl_query=None, source_fields=None, index_pattern=None):
    idx = index_pattern or ALERTS_INDEX
    raw_query = (dsl_query or {}).get("query", {"match_all": {}})
    query = _normalize_query_timestamps(raw_query)
    sort = (dsl_query or {}).get("sort", [{"timestamp": {"order": "desc"}}])
    body = {
        "size": min(size, 100),
        "from": offset,
        "query": query,
        "sort": sort,
        "aggs": {
            "histogram": {
                "auto_date_histogram": {
                    "field": "timestamp",
                    "buckets": 50,
                    "format": "epoch_millis",
                }
            }
        },
    }
    if source_fields:
        body["_source"] = source_fields
    res = indexer_search(idx, body)
    hits = (res.get("hits") or {}).get("hits", [])
    total = (res.get("hits") or {}).get("total") or {}
    total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
    # Extract histogram buckets for the Discover frequency chart
    hist_buckets = (res.get("aggregations") or {}).get("histogram", {}).get("buckets", [])
    histogram = [{"ts": b.get("key"), "count": b.get("doc_count", 0)} for b in hist_buckets]
    return {"hits": hits, "total": total_val, "histogram": histogram}


# ---------------------------------------------------------------------------
# Discover fields
# ---------------------------------------------------------------------------

def _flatten_mapping(mapping, prefix=""):
    out = []
    if not isinstance(mapping, dict):
        return out
    props = mapping.get("properties", mapping)
    for key, val in props.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(val, dict) and "properties" in val:
            out.extend(_flatten_mapping(val, path))
        elif isinstance(val, dict) and "type" in val:
            out.append({"name": path, "type": val.get("type", "keyword")})
        elif isinstance(val, dict):
            out.extend(_flatten_mapping(val, path))
    return out


def get_discover_fields(index_pattern=None):
    idx = index_pattern or ALERTS_INDEX
    try:
        res = opensearch_request(f"/{idx}/_mapping", method="GET")
        fields = []
        for index_name, index_body in (res or {}).items():
            if index_name.startswith("."):
                continue
            mappings = (index_body or {}).get("mappings", {})
            props = mappings.get("properties", mappings) if isinstance(mappings, dict) else {}
            for f in _flatten_mapping({"properties": props}):
                if f["name"] not in [x["name"] for x in fields]:
                    fields.append(f)
        seen = set()
        unique = []
        for f in sorted(fields, key=lambda x: x["name"]):
            if f["name"] in seen:
                continue
            seen.add(f["name"])
            unique.append(f)
        return unique
    except Exception:
        return []


def get_discover_field_values(field, size=25, time_from=None, time_to=None, index_pattern=None):
    from datetime import datetime, timezone, timedelta
    idx = index_pattern or ALERTS_INDEX
    must = []
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {"values": {"terms": {"field": field, "size": min(size, 100), "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_search(idx, body)
        buckets = (res.get("aggregations") or {}).get("values", {}).get("buckets", [])
        return [b.get("key") for b in buckets if b.get("key") is not None]
    except Exception:
        return []


def get_discover_field_stats(field, size=15, time_from=None, time_to=None, index_pattern=None):
    """Return top field values with doc counts and percentages for field stats popover."""
    from datetime import datetime, timezone, timedelta
    idx = index_pattern or ALERTS_INDEX
    must = []
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "values": {"terms": {"field": field, "size": min(size, 50), "order": {"_count": "desc"}}},
            "total": {"value_count": {"field": field}},
        },
    }
    try:
        res = indexer_search(idx, body)
        aggs = res.get("aggregations") or {}
        buckets = aggs.get("values", {}).get("buckets", [])
        total_docs = (aggs.get("total", {}).get("value") or 1) or 1
        values = []
        for b in buckets:
            count = b.get("doc_count", 0)
            values.append({
                "value": b.get("key"),
                "count": count,
                "pct": round(count / total_docs * 100, 1) if total_docs > 0 else 0,
            })
        return {"values": values, "total": total_docs}
    except Exception:
        return {"values": [], "total": 0}


def get_discover_correlate(fields, exclude_id=None, time_from=None, time_to=None, index_pattern=None, size=20):
    """Find events related to a given alert by shared field values."""
    from datetime import datetime, timezone, timedelta
    idx = index_pattern or ALERTS_INDEX
    must = []
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    should_clauses = []
    for field, value in (fields or {}).items():
        val = str(value).strip() if value is not None else ""
        if val and val not in ("—", "", "None"):
            should_clauses.append({"term": {field + ".keyword": val}})
            should_clauses.append({"term": {field: val}})
    if should_clauses:
        must.append({"bool": {"should": should_clauses, "minimum_should_match": 1}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    if exclude_id:
        query = {"bool": {"must": must, "must_not": [{"term": {"_id": exclude_id}}]}}
    body = {"size": size, "query": query, "sort": [{"timestamp": {"order": "desc"}}]}
    try:
        res = indexer_search(idx, body)
        hits = (res.get("hits") or {}).get("hits") or []
        total = ((res.get("hits") or {}).get("total") or {})
        total_val = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        return {"hits": hits, "total": total_val}
    except Exception:
        return {"hits": [], "total": 0}


# ---------------------------------------------------------------------------
# Rules (WatchTower /api/v1/rules)
# ---------------------------------------------------------------------------

def get_rules_list(limit=20, offset=0, search=None, rule_ids=None, file_=None, group=None, level=None):
    res = watchtower_request("/api/v1/rules")
    rules = res.get("data", [])
    # Apply filters locally
    filtered = rules
    if search:
        q = search.lower()
        filtered = [r for r in filtered if q in str(r.get("description", "")).lower() or q in str(r.get("id", ""))]
    if rule_ids:
        ids = [int(x) for x in str(rule_ids).split(",") if x.strip().isdigit()]
        if ids:
            filtered = [r for r in filtered if r.get("id") in ids]
    if group:
        filtered = [r for r in filtered if group in (r.get("groups") or [])]
    if level is not None:
        filtered = [r for r in filtered if r.get("level") == int(level)]
    total = len(filtered)
    page = filtered[offset:offset + limit]
    items = []
    for r in page:
        items.append({
            "id": r.get("id"),
            "description": r.get("description", ""),
            "level": r.get("level", 0),
            "groups": r.get("groups", []),
            "filename": "rules.yaml",
            "relative_dirname": "etc/rules",
            "status": "enabled" if r.get("enabled", True) else "disabled",
        })
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": total,
        }
    }


def get_rules_files():
    """WatchTower uses YAML rules, not separate files — return synthetic list."""
    return {
        "data": {
            "affected_items": [
                {"filename": "rules.yaml", "relative_dirname": "etc/rules", "status": "enabled"},
            ],
            "total_affected_items": 1,
        }
    }


def get_rules_file_content(filename, raw=False, relative_dirname=None):
    """Return rules as YAML text (not XML)."""
    import json
    res = watchtower_request("/api/v1/rules")
    rules = res.get("data", [])
    if raw:
        try:
            import yaml
            return yaml.dump(rules, default_flow_style=False)
        except ImportError:
            return json.dumps(rules, indent=2)
    return {"data": {"affected_items": rules}}


def put_rules_file(filename, content, overwrite=True, relative_dirname=None):
    """Create a rule via WatchTower API.  Accepts YAML or JSON."""
    import json
    try:
        import yaml
        rule_data = yaml.safe_load(content) if isinstance(content, str) else content
    except ImportError:
        rule_data = json.loads(content) if isinstance(content, str) else content
    if isinstance(rule_data, list):
        results = []
        for r in rule_data:
            results.append(watchtower_request("/api/v1/rules", method="POST", json_body=r))
        return {"data": {"affected_items": results}}
    return watchtower_request("/api/v1/rules", method="POST", json_body=rule_data)


def delete_rules_file(filename, relative_dirname=None):
    """Rule deletion by file is not supported — return informational message."""
    return {"data": {"affected_items": [], "failed_items": []}, "message": "File-based rule deletion not supported; use rule ID."}


# ---------------------------------------------------------------------------
# Decoders (WatchTower /api/v1/decoders)
# ---------------------------------------------------------------------------

def get_decoders_list(limit=20, offset=0, search=None, filename=None, relative_dirname=None):
    res = watchtower_request("/api/v1/decoders")
    decoders = res.get("data", [])
    if search:
        q = search.lower()
        decoders = [d for d in decoders if q in str(d.get("name", "")).lower() or q in str(d.get("description", "")).lower()]
    total = len(decoders)
    page = decoders[offset:offset + limit]
    items = []
    for d in page:
        items.append({
            "name": d.get("name", ""),
            "description": d.get("description", ""),
            "filename": "decoders.yaml",
            "relative_dirname": "etc/decoders",
            "status": "enabled",
            "details": d,
        })
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": total,
        }
    }


def get_decoders_files():
    return {
        "data": {
            "affected_items": [
                {"filename": "decoders.yaml", "relative_dirname": "etc/decoders", "status": "enabled"},
            ],
            "total_affected_items": 1,
        }
    }


def get_decoders_file_content(filename, raw=False, relative_dirname=None):
    import json
    res = watchtower_request("/api/v1/decoders")
    decoders = res.get("data", [])
    if raw:
        try:
            import yaml
            return yaml.dump(decoders, default_flow_style=False)
        except ImportError:
            return json.dumps(decoders, indent=2)
    return {"data": {"affected_items": decoders}}


def put_decoders_file(filename, content, overwrite=True, relative_dirname=None):
    import json
    try:
        import yaml
        decoder_data = yaml.safe_load(content) if isinstance(content, str) else content
    except ImportError:
        decoder_data = json.loads(content) if isinstance(content, str) else content
    return watchtower_request("/api/v1/decoders", method="POST", json_body=decoder_data)


def delete_decoders_file(filename, relative_dirname=None):
    return {"data": {"affected_items": [], "failed_items": []}, "message": "File-based decoder deletion not supported."}


# ---------------------------------------------------------------------------
# Vulnerabilities — WatchNode vulnerability collector emits event_type="vulnerability"
# into watchvault-events-*. Flat fields: cve_id, severity, cvss_score, package_name,
# package_version, description, fixed_version, agent_id, ecosystem.
# ---------------------------------------------------------------------------

def _vuln_base_must(severity=None, agent_name=None, package=None, cve=None,
                    cvss_min=None, cvss_max=None, time_from=None, time_to=None):
    """Build the must clauses for a vulnerability query, always including the event_type filter."""
    must = [VULN_FILTER]   # {"term": {"event_type": "vulnerability"}}
    if severity:
        sevs = [s.strip().upper() for s in severity.split(",") if s.strip()]
        if sevs:
            must.append({"terms": {"severity.keyword": sevs}})
    if agent_name:
        must.append({"term": {"agent_id": agent_name}})
    if package:
        must.append({"match": {"package_name": package}})
    if cve:
        must.append({"match": {"cve_id": cve}})
    if cvss_min is not None or cvss_max is not None:
        r = {"range": {"cvss_score": {}}}
        if cvss_min is not None:
            r["range"]["cvss_score"]["gte"] = float(cvss_min)
        if cvss_max is not None:
            r["range"]["cvss_score"]["lte"] = float(cvss_max)
        must.append(r)
    if time_from or time_to:
        tr = {"range": {"timestamp": {}}}
        if time_from:
            tr["range"]["timestamp"]["gte"] = _to_epoch_ms(time_from)
        if time_to:
            tr["range"]["timestamp"]["lte"] = _to_epoch_ms(time_to)
        must.append(tr)
    return must


def get_vulnerabilities_summary():
    body = {
        "size": 0,
        "query": {"bool": {"must": [VULN_FILTER]}},
        "aggs": {"by_severity": {"terms": {"field": "severity.keyword", "size": 10}}},
    }
    return indexer_search(VULN_INDEX, body)


def get_vulnerabilities_recent(size=50):
    body = {
        "size": size,
        "query": {"bool": {"must": [VULN_FILTER]}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    return indexer_search(VULN_INDEX, body)


def get_vulnerabilities_list(size=25, offset=0, severity=None, agent_name=None,
                             package=None, cve=None, cvss_min=None, cvss_max=None,
                             time_from=None, time_to=None):
    must = _vuln_base_must(severity, agent_name, package, cve, cvss_min, cvss_max, time_from, time_to)
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [
            {"cvss_score": {"order": "desc", "unmapped_type": "float"}},
            {"timestamp": {"order": "desc", "unmapped_type": "date"}},
        ],
    }
    try:
        res = indexer_search(VULN_INDEX, body)
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        hits = (res.get("hits") or {}).get("hits", [])
        rows = []
        for h in hits:
            s = h.get("_source", {})
            rows.append({
                "cve_id":          s.get("cve_id", ""),
                "severity":        s.get("severity", "UNKNOWN"),
                "cvss_score":      s.get("cvss_score"),
                "package_name":    s.get("package_name", ""),
                "package_version": s.get("package_version", ""),
                "fixed_version":   s.get("fixed_version", ""),
                "description":     s.get("description") or s.get("summary", ""),
                "agent_id":        s.get("agent_id", ""),
                "agent_name":      s.get("agent_name", ""),
                "ecosystem":       s.get("ecosystem", ""),
                "timestamp":       s.get("timestamp"),
                "status":          s.get("status", "open"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_vulnerabilities_trends(days=30):
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = int((now - timedelta(days=days)).timestamp() * 1000)
    body = {
        "size": 0,
        "query": {"bool": {"must": [VULN_FILTER, {"range": {"timestamp": {"gte": start}}}]}},
        "aggs": {
            "by_date": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "1d", "min_doc_count": 0},
                "aggs": {"by_severity": {"terms": {"field": "severity.keyword", "size": 5}}},
            }
        },
    }
    return indexer_search(VULN_INDEX, body)


def get_vulnerabilities_top_agents(size=10, severity=None, time_from=None, time_to=None):
    must = _vuln_base_must(severity=severity, time_from=time_from, time_to=time_to)
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {"by_agent": {"terms": {"field": "agent_id", "size": size}}},
    }
    return indexer_search(VULN_INDEX, body)


def get_vulnerabilities_top_packages(size=10, severity=None, time_from=None, time_to=None):
    must = _vuln_base_must(severity=severity, time_from=time_from, time_to=time_to)
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {"by_package": {"terms": {"field": "package_name.keyword", "size": size}}},
    }
    return indexer_search(VULN_INDEX, body)


def get_vulnerabilities_kpis(time_from=None, time_to=None):
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(days=30)).timestamp() * 1000)
    end   = _to_epoch_ms(time_to)   if time_to   else int(now.timestamp() * 1000)
    must = [VULN_FILTER, {"range": {"timestamp": {"gte": start, "lte": end}}}]
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "affected_agents": {"cardinality": {"field": "agent_id"}},
            "unique_cves":     {"cardinality": {"field": "cve_id.keyword"}},
            "avg_cvss":        {"avg": {"field": "cvss_score"}},
            "by_severity":     {"terms": {"field": "severity.keyword", "size": 10}},
        },
    }
    try:
        res = indexer_search(VULN_INDEX, body)
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        aggs = res.get("aggregations") or {}
        by_sev = {b["key"].upper(): b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
        critical_high = by_sev.get("CRITICAL", 0) + by_sev.get("HIGH", 0)
        return {
            "total":           total_val,
            "critical_high":   critical_high,
            "avg_cvss":        round(aggs.get("avg_cvss", {}).get("value") or 0, 1),
            "affected_agents": aggs.get("affected_agents", {}).get("value", 0),
            "unique_cves":     aggs.get("unique_cves",     {}).get("value", 0),
        }
    except Exception:
        return {"total": 0, "critical_high": 0, "avg_cvss": 0, "affected_agents": 0, "unique_cves": 0}


# ---------------------------------------------------------------------------
# Generic compliance — queries watchvault-alerts-* by rule_groups for any of
# the 6 supported frameworks. Sentinel's native compliance rules (batches
# 7100-7600) tag framework + control via the rule groups list, e.g.
#   [compliance, pci_dss, req_2] / [compliance, hipaa, technical] / ...
# These functions filter on rule_groups == <framework> and aggregate on the
# per-control sub-tags, dropping the generic "compliance"/framework tags so
# the dashboard shows meaningful control IDs.
# ---------------------------------------------------------------------------

_COMPLIANCE_NOISE = {
    "pci_dss":     {"compliance", "pci_dss"},
    "hipaa":       {"compliance", "hipaa"},
    "gdpr":        {"compliance", "gdpr"},
    "nist_800_53": {"compliance", "nist_800_53"},
    "soc2":        {"compliance", "soc2"},
    "cis_v8":      {"compliance", "cis_v8"},
}

COMPLIANCE_FRAMEWORKS = list(_COMPLIANCE_NOISE.keys())


def _compliance_base_query(framework, time_from=None, time_to=None):
    from datetime import datetime, timezone, timedelta
    must = [{"term": {"rule_groups": framework}}]
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    return must


def get_compliance_stats(framework, time_from=None, time_to=None):
    if framework not in _COMPLIANCE_NOISE:
        return {"total_alerts": 0, "max_rule_level": None}
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        "aggs": {
            "total": {"value_count": {"field": "timestamp"}},
            "max_level": {"max": {"field": "rule_level"}},
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (aggs.get("total") or {}).get("value", 0)
        max_level = (aggs.get("max_level") or {}).get("value")
        return {"total_alerts": total, "max_rule_level": int(max_level) if max_level is not None else None}
    except Exception:
        return {"total_alerts": 0, "max_rule_level": None}


def get_compliance_by_control(framework, size=20, time_from=None, time_to=None):
    """Top per-control buckets (e.g. PCI: req_2, req_8...) by alert count,
    with the generic compliance/framework tags stripped out."""
    if framework not in _COMPLIANCE_NOISE:
        return []
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        "aggs": {"by_group": {"terms": {"field": "rule_groups", "size": size + 4, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_group", {}).get("buckets", [])
        noise = _COMPLIANCE_NOISE[framework]
        out = []
        for b in buckets:
            k = b.get("key")
            if k in noise:
                continue
            out.append({"key": k, "doc_count": b.get("doc_count", 0)})
            if len(out) >= size:
                break
        return out
    except Exception:
        return []


def get_compliance_by_agent(framework, size=10, time_from=None, time_to=None):
    if framework not in _COMPLIANCE_NOISE:
        return []
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        "aggs": {"by_agent": {"terms": {"field": "agent_name", "size": size, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_agent", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_compliance_evolution(framework, interval="1h", time_from=None, time_to=None):
    if framework not in _COMPLIANCE_NOISE:
        return []
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        "aggs": {
            "by_time": {
                "date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0},
            },
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_time", {}).get("buckets", [])
        return [{"date": b.get("key_as_string"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# HIPAA compliance — queries watchvault-alerts-* for rule_groups containing "hipaa"
# (Since WatchTower doesn't have a dedicated rule.hipaa field, we use rule_groups)
# ---------------------------------------------------------------------------

def _hipaa_base_query(time_from=None, time_to=None):
    from datetime import datetime, timezone, timedelta
    must = [{"term": {"rule_groups": "hipaa"}}]
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    return must


def get_hipaa_stats(time_from=None, time_to=None):
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {
            "total": {"value_count": {"field": "timestamp"}},
            "max_level": {"max": {"field": "rule_level"}},
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (aggs.get("total") or {}).get("value", 0)
        max_level = (aggs.get("max_level") or {}).get("value")
        return {"total_alerts": total, "max_rule_level": int(max_level) if max_level is not None else None}
    except Exception:
        return {"total_alerts": 0, "max_rule_level": None}


def get_hipaa_by_requirement(size=20, time_from=None, time_to=None):
    """HIPAA requirements from rule_groups that contain 'hipaa'."""
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {"by_requirement": {"terms": {"field": "rule_groups", "size": size, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_requirement", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_hipaa_requirements_high_level(time_from=None, time_to=None):
    buckets = get_hipaa_by_requirement(size=200, time_from=time_from, time_to=time_to)
    high_level = {}
    for b in buckets:
        key = (b.get("key") or "").strip()
        if not key:
            continue
        prefix = key.split(".")[0] + "." + key.split(".")[1] if "." in key else key
        high_level[prefix] = high_level.get(prefix, 0) + b.get("doc_count", 0)
    return [{"key": k, "doc_count": v} for k, v in sorted(high_level.items(), key=lambda x: -x[1])]


def get_hipaa_alerts_volume_by_agent(agent_size=10, requirement_size=15, time_from=None, time_to=None):
    must = _hipaa_base_query(time_from, time_to)
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent_name", "size": agent_size, "order": {"_count": "desc"}},
                "aggs": {
                    "by_req": {"terms": {"field": "rule_groups", "size": requirement_size, "order": {"_count": "desc"}}},
                },
            },
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        agent_buckets = (res.get("aggregations") or {}).get("by_agent", {}).get("buckets", [])
        all_reqs = set()
        for ab in agent_buckets:
            for rb in (ab.get("by_req") or {}).get("buckets", []):
                all_reqs.add(rb.get("key"))
        req_list = sorted(all_reqs)
        agents = [{"id": ab.get("key"), "name": ab.get("key")} for ab in agent_buckets]
        matrix = []
        for ab in agent_buckets:
            row = {}
            for rb in (ab.get("by_req") or {}).get("buckets", []):
                row[rb.get("key")] = rb.get("doc_count", 0)
            matrix.append([row.get(r, 0) for r in req_list])
        return {"agents": agents, "requirements": req_list, "matrix": matrix}
    except Exception:
        return {"agents": [], "requirements": [], "matrix": []}


def get_hipaa_evolution_over_time(interval="30m", time_from=None, time_to=None, requirement_size=10):
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {
            "by_time": {
                "date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0},
                "aggs": {"by_req": {"terms": {"field": "rule_groups", "size": requirement_size, "order": {"_count": "desc"}}}},
            },
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_time", {}).get("buckets", [])
        return [
            {"key": b.get("key_as_string") or b.get("key"),
             "buckets": [{"key": r.get("key"), "doc_count": r.get("doc_count", 0)} for r in (b.get("by_req") or {}).get("buckets", [])]}
            for b in buckets
        ]
    except Exception:
        return []


def get_hipaa_by_agent(size=10, time_from=None, time_to=None):
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {"by_agent": {"terms": {"field": "agent_name", "size": size, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_agent", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_hipaa_events_list(size=25, offset=0, time_from=None, time_to=None):
    must = _hipaa_base_query(time_from, time_to)
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        return {"hits": hits, "total": total_val}
    except Exception:
        return {"hits": [], "total": 0}


# ---------------------------------------------------------------------------
# IT Hygiene / Inventory — queries watchvault-events-* for syscollector data
# (WatchVault does not have separate inventory indices; syscollector events
#  land in the events index with event_type = "syscollector.*")
# ---------------------------------------------------------------------------

def _get_nested(source, path):
    if not source or not path:
        return None
    val = source.get(path)
    if val is not None:
        return val
    obj = source
    for key in path.split("."):
        obj = (obj or {}).get(key)
        if obj is None:
            return None
    return obj


def get_inventory_system_summary(platform=None, name=None, architecture=None, cluster_name=None):
    # Real field mapping: event_type=syscollector.os, flat fields (text type → .keyword for aggs)
    must = [{"term": {"event_type": "syscollector.os"}}]
    if platform:
        must.append({"term": {"platform.keyword": platform}})
    if name:
        must.append({"match": {"os_name": name}})
    if architecture:
        must.append({"term": {"arch.keyword": architecture}})
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "top_platforms":    {"terms": {"field": "platform.keyword",        "size": 5}},
            "top_os":           {"terms": {"field": "os_name.keyword",          "size": 5}},
            "top_architecture": {"terms": {"field": "arch.keyword",             "size": 5}},
        },
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        aggs = res.get("aggregations") or {}
        return {
            "top_platforms":    [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_platforms",    {}).get("buckets", [])],
            "top_os":           [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_os",           {}).get("buckets", [])],
            "top_architecture": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_architecture", {}).get("buckets", [])],
        }
    except Exception as e:
        return {"top_platforms": [], "top_os": [], "top_architecture": [], "error": str(e)}


def get_inventory_system_list(size=15, offset=0, platform=None, name=None, architecture=None,
                              cluster_name=None, sort_field="agent_id", sort_order="asc"):
    must = [{"term": {"event_type": "syscollector.os"}}]
    if platform:
        must.append({"term": {"platform.keyword": platform}})
    if name:
        must.append({"match": {"os_name": name}})
    if architecture:
        must.append({"term": {"arch.keyword": architecture}})
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"agent_id": {"order": sort_order, "unmapped_type": "keyword"}}],
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = h.get("_source", {})
            rows.append({
                "agent_name":           s.get("agent_name") or s.get("hostname") or s.get("agent_id", ""),
                "agent_id":             s.get("agent_id"),
                "host_os_platform":     s.get("platform"),
                "host_os_name":         s.get("os_name") or s.get("os"),
                "host_os_version":      s.get("platform_version"),
                "host_os_kernel_release": s.get("kernel_version"),
                "host_architecture":    s.get("arch"),
                "host_hostname":        s.get("hostname") or s.get("agent_id"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_hardware_list(size=20, offset=0):
    """Return per-agent hardware info from syscollector.hardware events."""
    body = {
        "size": size, "from": offset,
        "query": {"term": {"event_type": "syscollector.hardware"}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = h.get("_source", {})
            ram_gb = round(s.get("ram_total", 0) / (1024**3), 1) if s.get("ram_total") else None
            rows.append({
                "agent_id":   s.get("agent_id"),
                "cpu_model":  s.get("cpu_model"),
                "cpu_vendor": s.get("cpu_vendor"),
                "cpu_cores":  s.get("cpu_cores"),
                "num_cpu":    s.get("num_cpu"),
                "cpu_mhz":    round(s.get("cpu_mhz", 0), 0) if s.get("cpu_mhz") else None,
                "ram_total_gb": ram_gb,
                "ram_free_gb":  round(s.get("ram_free", 0) / (1024**3), 1) if s.get("ram_free") else None,
                "ram_used_gb":  round(s.get("ram_used", 0) / (1024**3), 1) if s.get("ram_used") else None,
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_packages_summary(vendor=None, package_name=None, package_type=None, cluster_name=None):
    # syscollector.packages — flat fields: name, version, arch, vendor, format
    must = [{"term": {"event_type": "syscollector.packages"}}]
    if vendor:
        must.append({"match": {"vendor": vendor}})
    if package_name:
        must.append({"match": {"name": package_name}})
    if package_type:
        must.append({"term": {"format": package_type}})
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "top_vendors":      {"terms": {"field": "vendor.keyword",  "size": 5}},
            "package_formats":  {"terms": {"field": "format.keyword",  "size": 10}},
            "unique_packages":  {"cardinality": {"field": "name.keyword"}},
        },
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        return {
            "top_vendors":    [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_vendors",    {}).get("buckets", [])],
            "package_types":  [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("package_formats",{}).get("buckets", [])],
            "unique_packages": (aggs.get("unique_packages") or {}).get("value", 0),
            "total": total_val,
        }
    except Exception as e:
        return {"top_vendors": [], "package_types": [], "unique_packages": 0, "total": 0, "error": str(e)}


def get_inventory_packages_list(size=15, offset=0, vendor=None, package_name=None, package_type=None,
                                cluster_name=None, sort_field="name", sort_order="asc"):
    # Flat fields: name, version, arch, vendor, format, agent_id
    must = [{"term": {"event_type": "syscollector.packages"}}]
    if vendor:
        must.append({"match": {"vendor": vendor}})
    if package_name:
        must.append({"match": {"name": package_name}})
    if package_type:
        must.append({"term": {"format": package_type}})
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"name.keyword": {"order": sort_order, "unmapped_type": "keyword"}}],
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = h.get("_source", {})
            rows.append({
                "agent_id":       s.get("agent_id", ""),
                "agent_name":     s.get("agent_name", ""),
                "package_name":   s.get("name", ""),
                "package_version":s.get("version", ""),
                "package_arch":   s.get("arch", ""),
                "package_vendor": s.get("vendor", ""),
                "package_type":   s.get("format", ""),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def _get_inventory_packages_list_UNUSED(size=15, offset=0, vendor=None, package_name=None, package_type=None,
                                cluster_name=None, sort_field="name", sort_order="asc"):
    """Kept for reference — not called while syscollector.packages is disabled."""
    must = [{"term": {"event_type": "syscollector.packages"}}]
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = h.get("_source", {})
            f = s.get("fields", {})
            rows.append({
                "agent_name": s.get("agent_name"),
                "package_vendor": f.get("vendor"),
                "package_name": f.get("name"),
                "package_version": f.get("version"),
                "package_type": f.get("type"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_processes_summary(process_name=None, cluster_name=None):
    # process.new events have flat fields: name, pid, ppid, cmdline (not nested under fields.*)
    must = [{"term": {"event_type": "process.new"}}]
    if process_name:
        must.append({"match": {"name": process_name}})
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {"top_processes": {"terms": {"field": "name.keyword", "size": 5}}},
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("top_processes", {}).get("buckets", [])
        return {"top_processes": [{"key": b["key"], "count": b["doc_count"]} for b in buckets]}
    except Exception as e:
        return {"top_processes": [], "error": str(e)}


def get_inventory_processes_start_histogram(cluster_name=None, interval="1h"):
    body = {
        "size": 0,
        "query": {"term": {"event_type": "process.new"}},
        "aggs": {"by_time": {"date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0}}},
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        buckets = (res.get("aggregations") or {}).get("by_time", {}).get("buckets", [])
        return {"buckets": [{"key": b.get("key"), "count": b["doc_count"]} for b in buckets]}
    except Exception as e:
        return {"buckets": [], "error": str(e)}


def get_inventory_processes_list(size=15, offset=0, process_name=None, command_line=None,
                                 agent_name=None, cluster_name=None, sort_field="timestamp", sort_order="desc"):
    # Flat fields: name, pid, ppid, cmdline, create_time, agent_id, event_type
    must = [{"term": {"event_type": "process.new"}}]
    if process_name:
        must.append({"match": {"name": process_name}})
    if command_line:
        must.append({"match": {"cmdline": command_line}})
    if agent_name:
        must.append({"term": {"agent_id": agent_name}})
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": sort_order, "unmapped_type": "date"}}],
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = h.get("_source", {})
            rows.append({
                "agent_name":            s.get("agent_name") or s.get("agent_id", ""),
                "agent_id":              s.get("agent_id"),
                "process_name":          s.get("name"),
                "process_start":         s.get("create_time") or s.get("timestamp"),
                "process_pid":           s.get("pid"),
                "process_parent_pid":    s.get("ppid"),
                "process_command_line":  s.get("cmdline") or "",
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_users_summary(cluster_name=None):
    # syscollector.users — flat fields: username, uid, gid, shell, home, type, full_name, enabled
    body = {
        "size": 0,
        "query": {"term": {"event_type": "syscollector.users"}},
        "aggs": {
            "top_users":  {"terms": {"field": "username.keyword", "size": 10}},
            "top_shells": {"terms": {"field": "shell.keyword",    "size": 10}},
            "top_types":  {"terms": {"field": "type.keyword",     "size": 5}},
        },
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        return {
            "top_users":  [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_users",  {}).get("buckets", [])],
            "top_groups": [],  # Not available from passwd — gid only
            "top_shells": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_shells", {}).get("buckets", [])],
            "total": total_val,
        }
    except Exception as e:
        return {"top_users": [], "top_groups": [], "top_shells": [], "total": 0, "error": str(e)}


def get_inventory_users_list(size=15, offset=0, user_name=None, group=None, shell=None,
                             cluster_name=None, sort_field="username", sort_order="asc"):
    # Flat fields: username, uid, gid, shell, home, type, full_name, enabled, agent_id
    must = [{"term": {"event_type": "syscollector.users"}}]
    if user_name:
        must.append({"match": {"username": user_name}})
    if shell:
        must.append({"term": {"shell.keyword": shell}})
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"username.keyword": {"order": sort_order, "unmapped_type": "keyword"}}],
    }
    try:
        res = indexer_search(EVENTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = h.get("_source", {})
            rows.append({
                "agent_id":   s.get("agent_id", ""),
                "agent_name": s.get("agent_name", "") or s.get("agent_id", ""),
                "user_name":  s.get("username", ""),
                "uid":        s.get("uid", ""),
                "gid":        s.get("gid", ""),
                "user_groups":s.get("gid", ""),
                "user_shell": s.get("shell", ""),
                "user_home":  s.get("home", ""),
                "user_type":  s.get("type", ""),
                "full_name":  s.get("full_name", "") or s.get("comment", ""),
                "enabled":    s.get("enabled", "true"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


# ── Services Inventory ────────────────────────────────────────────────────────

def get_inventory_services_summary(cluster_name=None):
    body = {
        "size": 0,
        "query": {"term": {"event_type": "syscollector.services"}},
        "aggs": {
            "by_state":      {"terms": {"field": "state.keyword",      "size": 10}},
            "by_start_type": {"terms": {"field": "start_type.keyword", "size": 10}},
            "top_services":  {"terms": {"field": "name.keyword",       "size": 10}},
        },
    }
    try:
        res = indexer_search(SYSTEM_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        return {
            "total": total_val,
            "by_state":      [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_state", {}).get("buckets", [])],
            "by_start_type": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_start_type", {}).get("buckets", [])],
            "top_services":  [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_services", {}).get("buckets", [])],
        }
    except Exception as e:
        return {"total": 0, "by_state": [], "by_start_type": [], "top_services": [], "error": str(e)}


def get_inventory_services_list(size=15, offset=0, service_name=None, state=None, agent_name=None, cluster_name=None):
    must = [{"term": {"event_type": "syscollector.services"}}]
    if service_name:
        must.append({"match": {"name": service_name}})
    if state:
        must.append({"term": {"state.keyword": state}})
    if agent_name:
        must.append({"term": {"agent_id": agent_name}})
    body = {
        "size": size, "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    try:
        res = indexer_search(SYSTEM_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        rows = [{"agent_name": h["_source"].get("agent_name") or h["_source"].get("agent_id", ""),
                 "agent_id": h["_source"].get("agent_id"), "name": h["_source"].get("name", ""),
                 "display_name": h["_source"].get("display_name", ""), "state": h["_source"].get("state", ""),
                 "start_type": h["_source"].get("start_type", ""), "pid": h["_source"].get("pid"),
                 "binary_path": h["_source"].get("binary_path", ""),
                 "description": h["_source"].get("description", "")} for h in hits]
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


# ── Hotfixes / Patch Status ────────────────────────────────────────────────────

def get_inventory_hotfixes_summary(cluster_name=None):
    body = {
        "size": 0,
        "query": {"term": {"event_type": "syscollector.hotfixes"}},
        "aggs": {"by_description": {"terms": {"field": "description.keyword", "size": 10}}},
    }
    try:
        res = indexer_search(SYSTEM_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        return {"total": total_val,
                "by_description": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_description", {}).get("buckets", [])]}
    except Exception as e:
        return {"total": 0, "by_description": [], "error": str(e)}


def get_inventory_hotfixes_list(size=15, offset=0, hotfix_id=None, agent_name=None, cluster_name=None):
    must = [{"term": {"event_type": "syscollector.hotfixes"}}]
    if hotfix_id:
        must.append({"match": {"hotfix_id": hotfix_id}})
    if agent_name:
        must.append({"term": {"agent_id": agent_name}})
    body = {
        "size": size, "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"installed_on": {"order": "desc", "unmapped_type": "date"}}],
    }
    try:
        res = indexer_search(SYSTEM_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        rows = [{"agent_name": h["_source"].get("agent_name") or h["_source"].get("agent_id", ""),
                 "agent_id": h["_source"].get("agent_id"), "hotfix_id": h["_source"].get("hotfix_id", ""),
                 "installed_on": h["_source"].get("installed_on", ""),
                 "description": h["_source"].get("description", ""),
                 "installed_by": h["_source"].get("installed_by", "")} for h in hits]
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


# ── Ports / Network Services Inventory ────────────────────────────────────────

def get_inventory_ports_summary(cluster_name=None):
    body = {
        "size": 0,
        "query": {"term": {"event_type": "syscollector.ports"}},
        "aggs": {
            "by_protocol": {"terms": {"field": "protocol.keyword", "size": 5}},
            "by_state":    {"terms": {"field": "state.keyword",    "size": 10}},
            "top_ports":   {"terms": {"field": "local_port",       "size": 15}},
        },
    }
    try:
        res = indexer_search(SYSTEM_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        return {
            "total": total_val,
            "by_protocol": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_protocol", {}).get("buckets", [])],
            "by_state":    [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_state", {}).get("buckets", [])],
            "top_ports":   [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_ports", {}).get("buckets", [])],
        }
    except Exception as e:
        return {"total": 0, "by_protocol": [], "by_state": [], "top_ports": [], "error": str(e)}


def get_inventory_ports_list(size=15, offset=0, protocol=None, state=None, agent_name=None, cluster_name=None):
    must = [{"term": {"event_type": "syscollector.ports"}}]
    if protocol:
        must.append({"term": {"protocol.keyword": protocol}})
    if state:
        must.append({"term": {"state.keyword": state}})
    if agent_name:
        must.append({"term": {"agent_id": agent_name}})
    body = {
        "size": size, "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    try:
        res = indexer_search(SYSTEM_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        rows = [{"agent_name": h["_source"].get("agent_name") or h["_source"].get("agent_id", ""),
                 "agent_id": h["_source"].get("agent_id"), "protocol": h["_source"].get("protocol", ""),
                 "local_ip": h["_source"].get("local_ip", ""), "local_port": h["_source"].get("local_port"),
                 "state": h["_source"].get("state", ""), "pid": h["_source"].get("pid")} for h in hits]
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


# ── Threat Intelligence / IOC ─────────────────────────────────────────────────

def get_threatintel_summary():
    body = {
        "size": 0,
        "query": {"bool": {"must": [{"terms": {"rule_groups": ["threat_intel", "ioc"]}}]}},
        "aggs": {
            "by_ioc_type": {"terms": {"field": "rule_groups.keyword", "size": 10}},
            "by_agent":    {"terms": {"field": "agent_id.keyword",    "size": 10}},
            "over_time":   {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0}},
        },
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        aggs = res.get("aggregations") or {}
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        return {
            "total_ioc_hits": total_val,
            "by_ioc_type":   [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_ioc_type", {}).get("buckets", [])],
            "by_agent":      [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("by_agent", {}).get("buckets", [])],
            "over_time":     [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("over_time", {}).get("buckets", [])],
        }
    except Exception as e:
        return {"total_ioc_hits": 0, "by_ioc_type": [], "by_agent": [], "over_time": [], "error": str(e)}


def get_threatintel_hits(size=20, offset=0, ioc_type=None, agent_name=None):
    must = [{"terms": {"rule_groups": ["threat_intel", "ioc"]}}]
    if ioc_type:
        must.append({"term": {"rule_groups.keyword": ioc_type}})
    if agent_name:
        must.append({"term": {"agent_id": agent_name}})
    body = {
        "size": size, "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    try:
        res = indexer_search(ALERTS_INDEX, body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        rows = [{"agent_name": h["_source"].get("agent_name") or h["_source"].get("agent_id", ""),
                 "agent_id": h["_source"].get("agent_id"), "title": h["_source"].get("title", ""),
                 "rule_id": h["_source"].get("rule_id"), "level": h["_source"].get("level"),
                 "rule_groups": h["_source"].get("rule_groups", []),
                 "timestamp": h["_source"].get("timestamp"),
                 "description": h["_source"].get("description", "")} for h in hits]
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}
