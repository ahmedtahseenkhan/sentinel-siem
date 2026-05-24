"""Sentinel Manager and Indexer API clients."""
import time as _time
import threading as _threading
import requests
from requests.auth import HTTPBasicAuth
from config import (
    SENTINEL_MANAGER_URL,
    SENTINEL_MANAGER_USER,
    SENTINEL_MANAGER_PASSWORD,
    SENTINEL_INDEXER_URL,
    SENTINEL_INDEXER_USER,
    SENTINEL_INDEXER_PASSWORD,
    VERIFY_SSL,
    REQUEST_TIMEOUT,
)

# Disable SSL warnings when using self-signed certs
if not VERIFY_SSL:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# JWT token cache — avoid re-authenticating on every API call.
# Tokens are cached for TOKEN_TTL_SECONDS (default 3300 s / 55 min).
# The cache is invalidated on 401 responses so a rotated credential triggers
# a fresh login rather than retrying with a stale token.
# ---------------------------------------------------------------------------
_TOKEN_TTL_SECONDS = 3300  # 55 minutes — well within typical 60-min JWT expiry
_token_cache: dict = {"token": None, "expires_at": 0.0}
_token_lock = _threading.Lock()


def _get_cached_token() -> str:
    """Return a valid cached token, or fetch a fresh one."""
    now = _time.monotonic()
    with _token_lock:
        if _token_cache["token"] and now < _token_cache["expires_at"]:
            return _token_cache["token"]
    # Fetch outside the lock so concurrent callers don't all block.
    token = _fetch_manager_token()
    with _token_lock:
        _token_cache["token"] = token
        _token_cache["expires_at"] = _time.monotonic() + _TOKEN_TTL_SECONDS
    return token


def _invalidate_token_cache() -> None:
    with _token_lock:
        _token_cache["token"] = None
        _token_cache["expires_at"] = 0.0


def _fetch_manager_token() -> str:
    """Perform the actual authentication request and return the raw JWT."""
    url = f"{SENTINEL_MANAGER_URL.rstrip('/')}/security/user/authenticate?raw=true"
    r = requests.post(
        url,
        auth=HTTPBasicAuth(SENTINEL_MANAGER_USER, SENTINEL_MANAGER_PASSWORD),
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT,
    )
    if r.status_code == 401:
        raise requests.HTTPError(
            "401 Unauthorized: Sentinel Manager rejected the username or password. "
            "Check SENTINEL_MANAGER_USER and SENTINEL_MANAGER_PASSWORD in your .env file. "
            "If you migrated from Wazuh-based variables, verify the updated credentials.",
            response=r,
        )
    r.raise_for_status()
    return r.text.strip().strip('"')


def get_manager_token() -> str:
    """Return a valid JWT for the Sentinel Manager (cached)."""
    return _get_cached_token()


def manager_request(path, method="GET", params=None, data=None, content_type=None):
    """Call Sentinel Manager API with JWT. Retries once on 401 with a fresh token."""
    for attempt in range(2):
        token = _get_cached_token()
        url = f"{SENTINEL_MANAGER_URL.rstrip('/')}{path}"
        headers = {"Authorization": f"Bearer {token}"}
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
        if data is not None:
            kwargs["data"] = data
        r = requests.request(**kwargs)
        if r.status_code == 401 and attempt == 0:
            # Token may have expired early — invalidate cache and retry once.
            _invalidate_token_cache()
            continue
        r.raise_for_status()
        if not r.content:
            return {}
        try:
            return r.json()
        except Exception:
            return {"raw": r.text}
    return {}  # unreachable but satisfies type checkers


def indexer_request(path, method="GET", json_body=None):
    """Call Sentinel Indexer API with Basic Auth."""
    url = f"{SENTINEL_INDEXER_URL.rstrip('/')}{path}"
    auth = HTTPBasicAuth(SENTINEL_INDEXER_USER, SENTINEL_INDEXER_PASSWORD)
    kwargs = {"auth": auth, "verify": VERIFY_SSL, "timeout": REQUEST_TIMEOUT}
    if json_body is not None:
        kwargs["json"] = json_body
        kwargs["headers"] = {"Content-Type": "application/json"}
    r = requests.request(method, url, **kwargs)
    r.raise_for_status()
    return r.json()


def get_agents_summary():
    """Get agent summary from manager (status counts)."""
    try:
        # Prefer single summary endpoint if available
        return manager_request("/agents/summary/status")
    except Exception:
        # Fallback: get agents list and compute summary
        data = manager_request("/agents", params={"limit": 10000})
        total = data.get("data", {}).get("total", 0)
        items = data.get("data", {}).get("affected_items", [])
        status_counts = {"active": 0, "disconnected": 0, "never_connected": 0, "pending": 0}
        for a in items:
            s = (a.get("status") or "").lower()
            if s in status_counts:
                status_counts[s] = status_counts.get(s, 0) + 1
        return {
            "connection": {
                "total": total,
                **status_counts,
            },
            "configuration": {"synced": total, "total": total, "not_synced": 0},
        }


def get_agents_list(limit=50, offset=0):
    """Get paginated list of agents from manager. Sort omitted for API compatibility (some versions reject sort=-last_keep_alive with 400)."""
    return manager_request(
        "/agents",
        params={"limit": limit, "offset": offset},
    )


def get_agent_by_id(agent_id):
    """Get a single agent by ID from manager. Uses WQL q=id=<agent_id>."""
    try:
        res = manager_request("/agents", params={"q": f"id={str(agent_id)}", "limit": 1})
        data = res.get("data") or {}
        items = data.get("affected_items") or []
        return items[0] if items else None
    except Exception:
        return None


def get_manager_status():
    """Get Wazuh manager daemons status."""
    return manager_request("/manager/status")


def get_indexer_health():
    """Get indexer cluster health."""
    return indexer_request("/_cluster/health")


def get_recent_alerts(size=50):
    """Get recent alerts from indexer (wazuh-alerts*)."""
    body = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
        "_source": [
            "timestamp",
            "rule.description",
            "rule.level",
            "rule.id",
            "agent.name",
            "agent.id",
            "data.srcip",
            "data.dstuser",
            "manager.name",
        ],
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_by_severity():
    """Aggregate alerts by rule level (severity) from indexer."""
    body = {
        "size": 0,
        "aggs": {
            "by_level": {
                "terms": {"field": "rule.level", "size": 20, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_by_rule(size=10):
    """Top alert rules by count."""
    body = {
        "size": 0,
        "aggs": {
            "by_rule": {
                "terms": {
                    "field": "rule.description",
                    "size": size,
                    "order": {"_count": "desc"},
                }
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_indexer_indices():
    """List indexer indices (wazuh-*)."""
    return indexer_request("/_cat/indices/wazuh-*?format=json")


def get_index_management_list(pattern="*", bytes_=None):
    """List all indices for Index Management. pattern: index name pattern (default *). bytes_: 'b' for byte size."""
    import urllib.parse
    safe_pattern = urllib.parse.quote((pattern or "*").strip(), safe="*")
    path = "/_cat/indices/" + safe_pattern + "?format=json"
    if bytes_:
        path += "&bytes=" + str(bytes_)
    return indexer_request(path)


def get_manager_info():
    """Get Wazuh manager version and info. Tries /manager/info then /cluster/local/info."""
    for path in ("/manager/info", "/cluster/local/info"):
        try:
            data = manager_request(path)
            raw = data.get("data")
            items = (raw or {}).get("affected_items") if isinstance(raw, dict) else None
            if items and len(items) > 0 and isinstance(items[0], dict):
                info = items[0]
            elif isinstance(raw, dict):
                info = raw
            else:
                info = {}
            return {"ok": True, "info": info}
        except Exception:
            continue
    return {"ok": False, "info": {}}


def get_indexer_info():
    """Get indexer/OpenSearch version and cluster info (GET /)."""
    try:
        data = indexer_request("/")
        version = (data.get("version") or {}) if isinstance(data.get("version"), dict) else {}
        return {
            "ok": True,
            "name": data.get("name"),
            "cluster_name": data.get("cluster_name"),
            "cluster_uuid": data.get("cluster_uuid"),
            "version_number": version.get("number"),
            "version_distribution": version.get("distribution"),
            "tagline": data.get("tagline"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ----- Rules (Wazuh Manager) -----


def get_rules_list(limit=20, offset=0, search=None, rule_ids=None, file_=None, group=None, level=None):
    """List rules from manager. GET /rules with optional filters."""
    params = {"limit": limit, "offset": offset}
    if search:
        params["search"] = search
    if rule_ids:
        params["rule_ids"] = rule_ids
    if file_:
        params["file"] = file_
    if group:
        params["group"] = group
    if level is not None:
        params["level"] = level
    return manager_request("/rules", params=params)


def get_rules_files():
    """List rule files. GET /rules/files."""
    return manager_request("/rules/files")


def get_rules_file_content(filename, raw=False, relative_dirname=None):
    """Get content of a rule file. GET /rules/files/{filename}. If raw=True, returns raw XML text."""
    params = {}
    if raw:
        params["raw"] = "true"
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    if raw:
        token = get_manager_token()
        url = f"{SENTINEL_MANAGER_URL.rstrip('/')}/rules/files/{filename}"
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(url, headers=headers, params=params or {}, verify=VERIFY_SSL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    return manager_request(f"/rules/files/{filename}", params=params or None)


def put_rules_file(filename, content, overwrite=True, relative_dirname=None):
    """Upload or replace a rule file. PUT /rules/files/{filename}. content: XML string or bytes."""
    params = {"overwrite": "true" if overwrite else "false"}
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    if isinstance(content, str):
        content = content.encode("utf-8")
    return manager_request(
        f"/rules/files/{filename}",
        method="PUT",
        params=params,
        data=content,
        content_type="application/octet-stream",
    )


def delete_rules_file(filename, relative_dirname=None):
    """Delete a rule file. DELETE /rules/files/{filename}. Only custom (user) files can be deleted."""
    params = {}
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    return manager_request(f"/rules/files/{filename}", method="DELETE", params=params or None)


# ----- Decoders (Wazuh Manager) -----


def get_decoders_list(limit=20, offset=0, search=None, filename=None, relative_dirname=None):
    """List decoders from manager. GET /decoders."""
    params = {"limit": limit, "offset": offset}
    if search:
        params["search"] = search
    if filename:
        params["filename"] = filename
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    return manager_request("/decoders", params=params)


def get_decoders_files():
    """List decoder files. GET /decoders/files."""
    return manager_request("/decoders/files")


def get_decoders_file_content(filename, raw=False, relative_dirname=None):
    """Get content of a decoder file. GET /decoders/files/{filename}. If raw=True, returns raw XML text."""
    params = {}
    if raw:
        params["raw"] = "true"
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    if raw:
        token = get_manager_token()
        url = f"{SENTINEL_MANAGER_URL.rstrip('/')}/decoders/files/{filename}"
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(url, headers=headers, params=params or {}, verify=VERIFY_SSL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    return manager_request(f"/decoders/files/{filename}", params=params or None)


def put_decoders_file(filename, content, overwrite=True, relative_dirname=None):
    """Upload or replace a decoder file. PUT /decoders/files/{filename}."""
    params = {"overwrite": "true" if overwrite else "false"}
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    if isinstance(content, str):
        content = content.encode("utf-8")
    return manager_request(
        f"/decoders/files/{filename}",
        method="PUT",
        params=params,
        data=content,
        content_type="application/octet-stream",
    )


def delete_decoders_file(filename, relative_dirname=None):
    """Delete a decoder file. DELETE /decoders/files/{filename}."""
    params = {}
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    return manager_request(f"/decoders/files/{filename}", method="DELETE", params=params or None)


def get_vulnerabilities_summary():
    """Aggregate vulnerabilities by severity from wazuh-states-vulnerabilities*."""
    body = {
        "size": 0,
        "aggs": {
            "by_severity": {
                "terms": {"field": "vulnerability.severity", "size": 10, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)


def get_vulnerabilities_recent(size=50):
    """Recent vulnerability findings from indexer."""
    body = {
        "size": size,
        "sort": [{"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"match_all": {}},
        "_source": [
            "agent.id",
            "agent.name",
            "vulnerability.id",
            "vulnerability.severity",
            "vulnerability.description",
            "vulnerability.score.base",
            "vulnerability.detected_at",
            "package.name",
            "package.version",
        ],
    }
    return indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)


def _vuln_filter(severity=None, agent_name=None, package=None, cve=None, cvss_min=None, cvss_max=None, time_from=None, time_to=None):
    """Build bool must list for vulnerability queries."""
    must = []
    if severity:
        sevs = [s.strip() for s in severity.split(",") if s.strip()]
        if sevs:
            must.append({"terms": {"vulnerability.severity": sevs}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if package:
        must.append({"wildcard": {"package.name": "*" + package + "*"}})
    if cve:
        must.append({"wildcard": {"vulnerability.id": "*" + cve + "*"}})
    if cvss_min is not None or cvss_max is not None:
        r = {"range": {"vulnerability.score.base": {}}}
        if cvss_min is not None:
            r["range"]["vulnerability.score.base"]["gte"] = float(cvss_min)
        if cvss_max is not None:
            r["range"]["vulnerability.score.base"]["lte"] = float(cvss_max)
        must.append(r)
    if time_from or time_to:
        r = {"range": {"vulnerability.detected_at": {}}}
        if time_from:
            r["range"]["vulnerability.detected_at"]["gte"] = time_from
        if time_to:
            r["range"]["vulnerability.detected_at"]["lte"] = time_to
        must.append(r)
    return must


def get_vulnerabilities_list(
    size=25,
    offset=0,
    severity=None,
    agent_name=None,
    package=None,
    cve=None,
    cvss_min=None,
    cvss_max=None,
    time_from=None,
    time_to=None,
):
    """Paginated vulnerability list with filters; sort by severity (high first), score desc, detected_at desc."""
    must = _vuln_filter(severity, agent_name, package, cve, cvss_min, cvss_max, time_from, time_to)
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [
            {"vulnerability.severity": {"order": "desc", "unmapped_type": "keyword"}},
            {"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}},
            {"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}},
        ],
        "_source": [
            "agent.id", "agent.name", "vulnerability.id", "vulnerability.severity",
            "vulnerability.description", "vulnerability.score.base", "vulnerability.detected_at",
            "package.name", "package.version",
        ],
    }
    res = indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)
    hits_total = (res.get("hits") or {}).get("total") or {}
    total = hits_total.get("value", hits_total) if isinstance(hits_total, dict) else (hits_total or 0)
    return {"hits": res.get("hits", {}), "total": total}


def get_vulnerabilities_trends(days=30):
    """Date histogram of vulnerabilities by severity for trend chart."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")
    body = {
        "size": 0,
        "query": {"range": {"vulnerability.detected_at": {"gte": start}}},
        "aggs": {
            "by_date": {
                "date_histogram": {
                    "field": "vulnerability.detected_at",
                    "calendar_interval": "1d",
                    "min_doc_count": 0,
                },
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "vulnerability.severity", "size": 5, "order": {"_count": "desc"}},
                    }
                },
            }
        },
    }
    return indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)


def get_vulnerabilities_top_agents(size=10, severity=None, time_from=None, time_to=None):
    """Top agents by vulnerability count."""
    must = _vuln_filter(severity=severity, time_from=time_from, time_to=time_to)
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)


def get_vulnerabilities_top_packages(size=10, severity=None, time_from=None, time_to=None):
    """Top packages by vulnerability count."""
    must = _vuln_filter(severity=severity, time_from=time_from, time_to=time_to)
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {
            "by_package": {
                "terms": {"field": "package.name", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)


def get_vulnerabilities_kpis(time_from=None, time_to=None):
    """KPIs: total, critical_high count, avg CVSS, affected agents, unique CVEs."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = time_from or (now - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000Z")
    end = time_to or now.strftime("%Y-%m-%dT23:59:59.999Z")
    body = {
        "size": 0,
        "query": {"range": {"vulnerability.detected_at": {"gte": start, "lte": end}}},
        "aggs": {
            "affected_agents": {"cardinality": {"field": "agent.id"}},
            "unique_cves": {"cardinality": {"field": "vulnerability.id"}},
            "avg_cvss": {"avg": {"field": "vulnerability.score.base"}},
            "by_severity": {
                "terms": {"field": "vulnerability.severity", "size": 10, "order": {"_count": "desc"}},
            },
        },
    }
    try:
        res = indexer_request("/wazuh-states-vulnerabilities*/_search", method="POST", json_body=body)
        hits_total = (res.get("hits") or {}).get("total") or {}
        total = hits_total.get("value", hits_total) if isinstance(hits_total, dict) else (hits_total or 0)
        aggs = res.get("aggregations") or {}
        by_sev = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
        critical_high = sum(by_sev.get(s, 0) for s in ("Critical", "High", "critical", "high"))
        return {
            "total": total,
            "critical_high": critical_high,
            "avg_cvss": round(aggs.get("avg_cvss", {}).get("value") or 0, 1),
            "affected_agents": aggs.get("affected_agents", {}).get("value", 0),
            "unique_cves": aggs.get("unique_cves", {}).get("value", 0),
        }
    except Exception:
        return {"total": 0, "critical_high": 0, "avg_cvss": 0, "affected_agents": 0, "unique_cves": 0}


def _alerts_filter(
    min_level=None,
    time_from=None,
    time_to=None,
    agent_name=None,
    agent_id=None,
    rule_groups=None,
    exclude_rule_ids=None,
):
    """Build bool must list for dashboard-level filters (Phase 4/6)."""
    must = []
    if time_from or time_to:
        r = {"range": {"timestamp": {}}}
        if time_from:
            r["range"]["timestamp"]["gte"] = time_from
        if time_to:
            r["range"]["timestamp"]["lte"] = time_to
        must.append(r)
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if agent_id is not None:
        must.append({"term": {"agent.id": str(agent_id)}})
    if rule_groups:
        groups = rule_groups if isinstance(rule_groups, (list, tuple)) else [rule_groups]
        groups = [str(g).strip() for g in groups if g]
        if groups:
            must.append({"terms": {"rule.groups": groups}})
    must_not = []
    if exclude_rule_ids:
        raw = exclude_rule_ids if isinstance(exclude_rule_ids, (list, tuple)) else [exclude_rule_ids]
        ids = [str(x).strip() for part in raw for x in (part.split(",") if isinstance(part, str) else [part]) if str(x).strip()]
        if ids:
            must_not.append({"terms": {"rule.id": ids}})
    return must, must_not


def get_alerts_by_agent(
    size=15,
    min_level=None,
    time_from=None,
    time_to=None,
    agent_name=None,
    agent_id=None,
    rule_groups=None,
    exclude_rule_ids=None,
):
    """Top agents by alert count (for threat hunting)."""
    body = {
        "size": 0,
        "aggs": {
            "by_agent": {
                "terms": {
                    "field": "agent.name",
                    "size": size,
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "agent_id": {"terms": {"field": "agent.id", "size": 1}},
                },
            }
        },
    }
    must, must_not = _alerts_filter(
        min_level, time_from, time_to, agent_name, agent_id, rule_groups, exclude_rule_ids
    )
    if must or must_not:
        body["query"] = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_timeline_24h():
    """Alerts per hour for last 24 hours (for anomaly-style timeline)."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": start}}},
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "1h",
                    "min_doc_count": 0,
                }
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_severity_24h():
    """Alert counts by rule.level for last 24h; bucket into Critical/High/Medium/Low."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": start}}},
        "aggs": {
            "by_level": {
                "terms": {"field": "rule.level", "size": 20, "order": {"_count": "desc"}},
            }
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_level", {}).get("buckets", [])
        critical = high = medium = low = 0
        for b in buckets:
            level = int(b.get("key", 0))
            count = b.get("doc_count", 0)
            if level >= 15:
                critical += count
            elif level >= 12:
                high += count
            elif level >= 7:
                medium += count
            else:
                low += count
        return {"critical": critical, "high": high, "medium": medium, "low": low}
    except Exception:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}


def get_top_source_ips(size=20):
    """Top source IPs from alerts (for attack origin)."""
    body = {
        "size": 0,
        "aggs": {
            "by_ip": {
                "terms": {"field": "data.srcip", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_by_user(size=10):
    """Top users (dstuser) by alert count - at-risk users."""
    body = {
        "size": 0,
        "aggs": {
            "by_user": {
                "terms": {"field": "data.dstuser", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_high_level_count():
    """Count alerts with rule.level >= 10 (critical/high) in last 24h."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start}}},
                    {"range": {"rule.level": {"gte": 10}}},
                ]
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_mitre_techniques(size=15):
    """Top MITRE ATT&CK technique IDs from alerts (rule.mitre.id)."""
    body = {
        "size": 0,
        "aggs": {
            "by_technique": {
                "terms": {"field": "rule.mitre.id", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    try:
        return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
    except Exception:
        return {"aggregations": {"by_technique": {"buckets": []}}}


def get_alerts_severity_over_time(
    days=7,
    interval="1d",
    min_level=None,
    time_from=None,
    time_to=None,
    agent_name=None,
    agent_id=None,
    rule_groups=None,
    exclude_rule_ids=None,
):
    """Phase 3/4/6: Alert count over time by rule.level; supports dashboard and agent/rule filters."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    if time_from or time_to:
        start = time_from or (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    else:
        start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    must = [{"range": {"timestamp": {"gte": start, "lte": end}}}]
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if agent_id is not None:
        must.append({"term": {"agent.id": str(agent_id)}})
    if rule_groups:
        groups = rule_groups if isinstance(rule_groups, (list, tuple)) else [rule_groups]
        groups = [g for g in groups if g]
        if groups:
            must.append({"terms": {"rule.groups": groups}})
    must_not = []
    if exclude_rule_ids:
        ids = [x.strip() for x in (exclude_rule_ids if isinstance(exclude_rule_ids, (list, tuple)) else [exclude_rule_ids]) if x]
        if ids:
            must_not.append({"terms": {"rule.id": ids}})
    query = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "by_date": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": interval,
                    "min_doc_count": 0,
                },
                "aggs": {
                    "by_level": {
                        "terms": {"field": "rule.level", "size": 15, "order": {"_count": "desc"}},
                    }
                },
            }
        },
    }
    return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)


def get_alerts_by_tactic(
    size=15,
    min_level=None,
    time_from=None,
    time_to=None,
    agent_name=None,
    agent_id=None,
    rule_groups=None,
    exclude_rule_ids=None,
):
    """Phase 3/4/6: Terms on rule.mitre.tactic; supports dashboard and agent/rule filters."""
    body = {
        "size": 0,
        "aggs": {
            "by_tactic": {
                "terms": {"field": "rule.mitre.tactic", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    must, must_not = _alerts_filter(
        min_level, time_from, time_to, agent_name, agent_id, rule_groups, exclude_rule_ids
    )
    if must or must_not:
        body["query"] = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    try:
        return indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
    except Exception:
        return {"aggregations": {"by_tactic": {"buckets": []}}}


def get_alerts_cardinality(time_from=None, time_to=None, min_level=None, exclude_rule_ids=None):
    """Phase 6.1: Unique count of source IPs and agents, plus total events (advanced aggregations)."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = time_from or (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    must = [{"range": {"timestamp": {"gte": start, "lte": end}}}]
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})
    must_not = []
    if exclude_rule_ids:
        raw = exclude_rule_ids if isinstance(exclude_rule_ids, (list, tuple)) else [exclude_rule_ids]
        ids = [str(x).strip() for part in raw for x in (part.split(",") if isinstance(part, str) else [part]) if str(x).strip()]
        if ids:
            must_not.append({"terms": {"rule.id": ids}})
    query = {"bool": {"must": must, "must_not": must_not}} if must_not else {"bool": {"must": must}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "unique_srcip": {"cardinality": {"field": "data.srcip"}},
            "unique_agents": {"cardinality": {"field": "agent.id"}},
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        hits_total = (res.get("hits") or {}).get("total") or {}
        total = hits_total.get("value", hits_total) if isinstance(hits_total, dict) else (hits_total or 0)
        aggs = res.get("aggregations") or {}
        return {
            "unique_src_ips": (aggs.get("unique_srcip") or {}).get("value", 0),
            "unique_agents": (aggs.get("unique_agents") or {}).get("value", 0),
            "total_events": total,
        }
    except Exception:
        return {"unique_src_ips": 0, "unique_agents": 0, "total_events": 0}


def get_rule_groups(size=50):
    """Phase 6.2: Top rule.groups for dashboard filter dropdown."""
    body = {
        "size": 0,
        "aggs": {
            "by_group": {
                "terms": {"field": "rule.groups", "size": size, "order": {"_count": "desc"}},
            }
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        return [b.get("key") for b in (res.get("aggregations") or {}).get("by_group", {}).get("buckets", []) if b.get("key")]
    except Exception:
        return []


def get_alerts_by_rule_groups(size=10, time_from=None, time_to=None):
    """Top rule.groups (categories) by count; optional time range."""
    from datetime import datetime, timezone, timedelta
    body = {"size": 0, "aggs": {"by_group": {"terms": {"field": "rule.groups", "size": size, "order": {"_count": "desc"}}}}}
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        body["query"] = {"range": {"timestamp": {"gte": start, "lte": end}}}
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_group", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_alerts_list(size=25, offset=0, time_from=None, time_to=None, min_level=None, agent_name=None, rule_group=None, search=None, dsl_query=None, source_fields=None):
    """Paginated alerts with filters. If dsl_query (dict) is provided, it is used as the query (time range not auto-added).
    source_fields: optional list of field names to return in _source."""
    if dsl_query is not None and isinstance(dsl_query, dict):
        return get_alerts_list_with_dsl(size=size, offset=offset, dsl_query=dsl_query, source_fields=source_fields)
    from datetime import datetime, timezone, timedelta
    must = []
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if rule_group:
        must.append({"term": {"rule.groups": rule_group}})
    if search and search.strip():
        must.append({
            "multi_match": {
                "query": search.strip(),
                "fields": ["rule.description", "agent.name", "agent.id", "rule.id"],
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
        "_source": source_fields if source_fields else True,
    }
    res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
    hits = (res.get("hits") or {}).get("hits", [])
    total = (res.get("hits") or {}).get("total") or {}
    total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
    return {"hits": hits, "total": total_val}


def get_alerts_list_with_dsl(size=25, offset=0, dsl_query=None, source_fields=None, index_pattern="wazuh-alerts*"):
    """Paginated alerts using optional raw DSL query and optional _source field list.
    dsl_query: dict with 'query' and optionally 'sort'. If provided, time range is NOT auto-applied (caller can put it in DSL).
    source_fields: list of field names to return; None means _source: true.
    """
    if dsl_query and isinstance(dsl_query, dict):
        query = dsl_query.get("query") or {"match_all": {}}
        sort = dsl_query.get("sort") or [{"timestamp": {"order": "desc"}}]
    else:
        query = {"match_all": {}}
        sort = [{"timestamp": {"order": "desc"}}]
    body = {
        "size": min(size, 100),
        "from": offset,
        "query": query,
        "sort": sort,
        "_source": source_fields if source_fields else True,
    }
    res = indexer_request(f"/{index_pattern}/_search", method="POST", json_body=body)
    hits = (res.get("hits") or {}).get("hits", [])
    total = (res.get("hits") or {}).get("total") or {}
    total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
    return {"hits": hits, "total": total_val}


def _flatten_mapping(mapping, prefix=""):
    """Recursively flatten ES mapping to list of (path, type)."""
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


def get_discover_fields(index_pattern="wazuh-alerts*"):
    """Return list of available field names and types from index mapping for Discover field picker."""
    try:
        res = indexer_request(f"/{index_pattern}/_mapping", method="GET")
        fields = []
        for index_name, index_body in (res or {}).items():
            if index_name.startswith("."):
                continue
            mappings = (index_body or {}).get("mappings", {})
            # handle optional "properties" wrapper
            props = mappings.get("properties", mappings) if isinstance(mappings, dict) else {}
            for f in _flatten_mapping({"properties": props}):
                if f["name"] not in [x["name"] for x in fields]:
                    fields.append(f)
        # sort and dedupe by name
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


def get_discover_field_values(field, size=25, time_from=None, time_to=None, index_pattern="wazuh-alerts*"):
    """Terms aggregation for a field to power autocomplete/suggestions in Discover filter builder."""
    from datetime import datetime, timezone, timedelta
    must = []
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {
        "size": 0,
        "query": query,
        "aggs": {"values": {"terms": {"field": field, "size": min(size, 100), "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_request(f"/{index_pattern}/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("values", {}).get("buckets", [])
        return [b.get("key") for b in buckets if b.get("key") is not None]
    except Exception:
        return []


# ----- Generic compliance (queries native rules tagged via rule.groups) -----
#
# Sentinel's 290 native compliance rules (batches 7100-7600) tag their
# framework + control via the YAML `groups:` list:
#     groups: [compliance, pci_dss, req_2]
#     groups: [compliance, hipaa, technical]
#     groups: [compliance, gdpr, art_5]
#     groups: [compliance, nist_800_53, ac]
#     groups: [compliance, soc2, cc6]
#     groups: [compliance, cis_v8, control_6]
#
# These functions filter by rule.groups containing the framework name and
# aggregate on the per-rule tags, dropping the generic "compliance" / the
# framework name itself from the bucket list so the dashboard shows
# meaningful control IDs instead of "compliance: 100, pci_dss: 100".

# Map framework slug -> set of "generic" group tags to filter out of result
# buckets so users see only the meaningful per-control tags.
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
    must = [{"term": {"rule.groups": framework}}]
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    return must


def get_compliance_stats(framework, time_from=None, time_to=None):
    """Total alerts + max rule level for a compliance framework."""
    if framework not in _COMPLIANCE_NOISE:
        return {"total_alerts": 0, "max_rule_level": None}
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        "aggs": {
            "total": {"value_count": {"field": "timestamp"}},
            "max_level": {"max": {"field": "rule.level"}},
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        aggs = res.get("aggregations") or {}
        total = (aggs.get("total") or {}).get("value", 0)
        max_level = (aggs.get("max_level") or {}).get("value")
        return {"total_alerts": total, "max_rule_level": int(max_level) if max_level is not None else None}
    except Exception:
        return {"total_alerts": 0, "max_rule_level": None}


def get_compliance_by_control(framework, size=20, time_from=None, time_to=None):
    """Top per-control buckets — e.g. for PCI: req_2, req_8, req_10 with counts.
    Strips the generic "compliance" and framework tags out of results."""
    if framework not in _COMPLIANCE_NOISE:
        return []
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        # Over-fetch then post-filter generic tags; we can't easily express
        # an exclude-list in OpenSearch terms agg without painless.
        "aggs": {"by_group": {"terms": {"field": "rule.groups", "size": size + 4, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
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
    """Top agents by alert count for this framework — for the per-host panel."""
    if framework not in _COMPLIANCE_NOISE:
        return []
    body = {
        "size": 0,
        "query": {"bool": {"must": _compliance_base_query(framework, time_from, time_to)}},
        "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": size, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_agent", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_compliance_evolution(framework, interval="1h", time_from=None, time_to=None):
    """Date histogram for compliance alerts. Returns [{date, count}]."""
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
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_time", {}).get("buckets", [])
        return [{"date": b.get("key_as_string"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


# ----- HIPAA compliance (alerts with rule.hipaa) -----

def _hipaa_base_query(time_from=None, time_to=None):
    """Build bool must list for HIPAA alerts: rule.hipaa exists + optional time range."""
    from datetime import datetime, timezone, timedelta
    must = [{"exists": {"field": "rule.hipaa"}}]
    if time_from or time_to:
        now = datetime.now(timezone.utc)
        start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        must.append({"range": {"timestamp": {"gte": start, "lte": end}}})
    return must


def get_hipaa_stats(time_from=None, time_to=None):
    """Total HIPAA alerts and max rule level in period."""
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {
            "total": {"value_count": {"field": "timestamp"}},
            "max_level": {"max": {"field": "rule.level"}},
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        aggs = res.get("aggregations") or {}
        total = (aggs.get("total") or {}).get("value", 0)
        max_level = (aggs.get("max_level") or {}).get("value")
        return {"total_alerts": total, "max_rule_level": int(max_level) if max_level is not None else None}
    except Exception:
        return {"total_alerts": 0, "max_rule_level": None}


def get_hipaa_by_requirement(size=20, time_from=None, time_to=None):
    """Top HIPAA requirements (rule.hipaa) by alert count. Returns list of {key, doc_count}."""
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {"by_requirement": {"terms": {"field": "rule.hipaa", "size": size, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_requirement", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_hipaa_requirements_high_level(time_from=None, time_to=None):
    """HIPAA requirements grouped by high-level prefix (e.g. 164.312.b -> 164.312) with total count."""
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
    """Heatmap data: agents x requirements with counts. Returns {agents: [{id, name}], requirements: [keys], matrix: [[count per agent per req]]}."""
    must = _hipaa_base_query(time_from, time_to)
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": agent_size, "order": {"_count": "desc"}},
                "aggs": {
                    "by_req": {"terms": {"field": "rule.hipaa", "size": requirement_size, "order": {"_count": "desc"}}},
                },
            },
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
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
    """Time series of HIPAA alert counts by requirement (stacked)."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {
            "by_time": {
                "date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0},
                "aggs": {"by_req": {"terms": {"field": "rule.hipaa", "size": requirement_size, "order": {"_count": "desc"}}},
                },
            },
        },
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_time", {}).get("buckets", [])
        return [
            {
                "key": b.get("key_as_string") or b.get("key"),
                "buckets": [{"key": r.get("key"), "doc_count": r.get("doc_count", 0)} for r in (b.get("by_req") or {}).get("buckets", [])],
            }
            for b in buckets
        ]
    except Exception:
        return []


def get_hipaa_by_agent(size=10, time_from=None, time_to=None):
    """Top agents by HIPAA alert count (for donut / most active agents)."""
    body = {
        "size": 0,
        "query": {"bool": {"must": _hipaa_base_query(time_from, time_to)}},
        "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": size, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_agent", {}).get("buckets", [])
        return [{"key": b.get("key"), "doc_count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        return []


def get_hipaa_events_list(size=25, offset=0, time_from=None, time_to=None):
    """Paginated HIPAA events (alerts with rule.hipaa) for Events table."""
    from datetime import datetime, timezone, timedelta
    must = _hipaa_base_query(time_from, time_to)
    now = datetime.now(timezone.utc)
    start = time_from or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = time_to or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.description", "rule.level", "rule.id", "rule.hipaa", "agent.name", "agent.id"],
    }
    try:
        res = indexer_request("/wazuh-alerts*/_search", method="POST", json_body=body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        return {"hits": hits, "total": total_val}
    except Exception:
        return {"hits": [], "total": 0}


# ----- IT Hygiene (inventory indices) -----

def _get_nested(source, path):
    """Get value from nested dict using dot path (e.g. 'agent.name' -> source['agent']['name']).
    Also supports flat keys like source.get('agent.name') if the indexer returns them."""
    if not source or not path:
        return None
    # Try flat key first (some indexers return "agent.name" as literal key)
    val = source.get(path)
    if val is not None:
        return val
    # Then try nested path
    obj = source
    for key in path.split("."):
        obj = (obj or {}).get(key)
        if obj is None:
            return None
    return obj


def _inventory_filter(agent_name=None, platform=None, name=None, cluster_name=None):
    """Build bool must for inventory queries (agent, platform, name, cluster)."""
    must = []
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if platform:
        must.append({"term": {"host.os.platform": platform}})
    if name:
        must.append({"wildcard": {"host.os.name": "*" + name + "*"}})
    if cluster_name:
        must.append({"term": {"wazuh.cluster.name": cluster_name}})
    return must


def get_inventory_system_summary(platform=None, name=None, architecture=None, cluster_name=None):
    """Top 5 platforms, Top 5 OS, Top 5 architecture from wazuh-states-inventory-system-*."""
    must = _inventory_filter(agent_name=None, platform=platform, name=name, cluster_name=cluster_name)
    if architecture:
        must.append({"term": {"host.architecture": architecture}})
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {
            "top_platforms": {"terms": {"field": "host.os.platform", "size": 5, "order": {"_count": "desc"}}},
            "top_os": {"terms": {"field": "host.os.name", "size": 5, "order": {"_count": "desc"}}},
            "top_architecture": {"terms": {"field": "host.architecture", "size": 5, "order": {"_count": "desc"}}},
        },
    }
    try:
        res = indexer_request("/wazuh-states-inventory-system-*/_search", method="POST", json_body=body)
        aggs = res.get("aggregations") or {}
        return {
            "top_platforms": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_platforms", {}).get("buckets", [])],
            "top_os": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_os", {}).get("buckets", [])],
            "top_architecture": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_architecture", {}).get("buckets", [])],
        }
    except Exception as e:
        return {"top_platforms": [], "top_os": [], "top_architecture": [], "error": str(e)}


def get_inventory_system_list(size=15, offset=0, platform=None, name=None, architecture=None, cluster_name=None, sort_field="agent.name", sort_order="asc"):
    """Paginated system/OS list from wazuh-states-inventory-system-*."""
    must = _inventory_filter(agent_name=None, platform=platform, name=name, cluster_name=cluster_name)
    if architecture:
        must.append({"term": {"host.architecture": architecture}})
    sort_key = sort_field if sort_field in ("agent.name", "host.os.platform", "host.os.name", "host.os.version", "host.os.kernel.release", "host.architecture") else "agent.name"
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{sort_key: {"order": sort_order, "unmapped_type": "keyword"}}],
        "_source": ["agent.name", "agent.id", "host.os.platform", "host.os.name", "host.os.version", "host.os.kernel.release", "host.architecture", "host.hostname"],
    }
    try:
        res = indexer_request("/wazuh-states-inventory-system-*/_search", method="POST", json_body=body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = (h.get("_source") or {})
            rows.append({
                "agent_name": _get_nested(s, "agent.name"),
                "agent_id": _get_nested(s, "agent.id"),
                "host_os_platform": _get_nested(s, "host.os.platform"),
                "host_os_name": _get_nested(s, "host.os.name"),
                "host_os_version": _get_nested(s, "host.os.version"),
                "host_os_kernel_release": _get_nested(s, "host.os.kernel.release"),
                "host_architecture": _get_nested(s, "host.architecture"),
                "host_hostname": _get_nested(s, "host.hostname"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_packages_summary(vendor=None, package_name=None, package_type=None, cluster_name=None):
    """Top 5 vendors, unique package count, package types from wazuh-states-inventory-packages-*."""
    must = []
    if vendor:
        must.append({"wildcard": {"package.vendor": "*" + vendor + "*"}})
    if package_name:
        must.append({"wildcard": {"package.name": "*" + package_name + "*"}})
    if package_type:
        must.append({"term": {"package.type": package_type}})
    if cluster_name:
        must.append({"term": {"wazuh.cluster.name": cluster_name}})
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {
            "top_vendors": {"terms": {"field": "package.vendor", "size": 5, "order": {"_count": "desc"}}},
            "package_types": {"terms": {"field": "package.type", "size": 10, "order": {"_count": "desc"}}},
            "unique_packages": {"cardinality": {"field": "package.name"}},
        },
    }
    try:
        res = indexer_request("/wazuh-states-inventory-packages-*/_search", method="POST", json_body=body)
        aggs = res.get("aggregations") or {}
        return {
            "top_vendors": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_vendors", {}).get("buckets", [])],
            "package_types": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("package_types", {}).get("buckets", [])],
            "unique_packages": (aggs.get("unique_packages") or {}).get("value", 0),
        }
    except Exception as e:
        return {"top_vendors": [], "package_types": [], "unique_packages": 0, "error": str(e)}


def get_inventory_packages_list(size=15, offset=0, vendor=None, package_name=None, package_type=None, cluster_name=None, sort_field="package.name", sort_order="asc"):
    """Paginated packages list from wazuh-states-inventory-packages-*."""
    must = []
    if vendor:
        must.append({"wildcard": {"package.vendor": "*" + vendor + "*"}})
    if package_name:
        must.append({"wildcard": {"package.name": "*" + package_name + "*"}})
    if package_type:
        must.append({"term": {"package.type": package_type}})
    if cluster_name:
        must.append({"term": {"wazuh.cluster.name": cluster_name}})
    sort_key = sort_field if sort_field in ("agent.name", "package.vendor", "package.name", "package.version", "package.type") else "package.name"
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{sort_key: {"order": sort_order, "unmapped_type": "keyword"}}],
        "_source": ["agent.name", "agent.id", "package.vendor", "package.name", "package.version", "package.type"],
    }
    try:
        res = indexer_request("/wazuh-states-inventory-packages-*/_search", method="POST", json_body=body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = (h.get("_source") or {})
            rows.append({
                "agent_name": _get_nested(s, "agent.name"),
                "package_vendor": _get_nested(s, "package.vendor"),
                "package_name": _get_nested(s, "package.name"),
                "package_version": _get_nested(s, "package.version"),
                "package_type": _get_nested(s, "package.type"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_processes_summary(process_name=None, cluster_name=None):
    """Top 5 processes from wazuh-states-inventory-processes-*."""
    must = []
    if process_name:
        must.append({"wildcard": {"process.name": "*" + process_name + "*"}})
    if cluster_name:
        must.append({"term": {"wazuh.cluster.name": cluster_name}})
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {"top_processes": {"terms": {"field": "process.name", "size": 5, "order": {"_count": "desc"}}}},
    }
    try:
        res = indexer_request("/wazuh-states-inventory-processes-*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("top_processes", {}).get("buckets", [])
        return {"top_processes": [{"key": b["key"], "count": b["doc_count"]} for b in buckets]}
    except Exception as e:
        return {"top_processes": [], "error": str(e)}


def get_inventory_processes_start_histogram(cluster_name=None, interval="1h"):
    """Process start time histogram (date_histogram on process.start)."""
    must = [] if not cluster_name else [{"term": {"wazuh.cluster.name": cluster_name}}]
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {"by_time": {"date_histogram": {"field": "process.start", "calendar_interval": interval, "min_doc_count": 0}}},
    }
    try:
        res = indexer_request("/wazuh-states-inventory-processes-*/_search", method="POST", json_body=body)
        buckets = (res.get("aggregations") or {}).get("by_time", {}).get("buckets", [])
        return {"buckets": [{"key": b.get("key_as_string"), "count": b["doc_count"]} for b in buckets]}
    except Exception as e:
        return {"buckets": [], "error": str(e)}


def get_inventory_processes_list(size=15, offset=0, process_name=None, command_line=None, agent_name=None, cluster_name=None, sort_field="process.start", sort_order="desc"):
    """Paginated processes list from wazuh-states-inventory-processes-*."""
    must = []
    if process_name:
        must.append({"wildcard": {"process.name": "*" + process_name + "*"}})
    if command_line:
        must.append({"wildcard": {"process.command_line": "*" + command_line + "*"}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if cluster_name:
        must.append({"term": {"wazuh.cluster.name": cluster_name}})
    sort_key = sort_field if sort_field in ("agent.name", "process.name", "process.start", "process.pid", "process.parent.pid", "process.command_line") else "process.start"
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{sort_key: {"order": sort_order, "unmapped_type": "keyword"}}],
        "_source": ["agent.name", "agent.id", "process.name", "process.start", "process.pid", "process.parent.pid", "process.command_line"],
    }
    try:
        res = indexer_request("/wazuh-states-inventory-processes-*/_search", method="POST", json_body=body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = (h.get("_source") or {})
            rows.append({
                "agent_name": _get_nested(s, "agent.name"),
                "process_name": _get_nested(s, "process.name"),
                "process_start": _get_nested(s, "process.start"),
                "process_pid": _get_nested(s, "process.pid"),
                "process_parent_pid": _get_nested(s, "process.parent.pid"),
                "process_command_line": _get_nested(s, "process.command_line"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}


def get_inventory_users_summary(cluster_name=None):
    """Top 5 users, Top 5 groups, Top 5 shells from wazuh-states-inventory-users-*."""
    must = [] if not cluster_name else [{"term": {"wazuh.cluster.name": cluster_name}}]
    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {
            "top_users": {"terms": {"field": "user.name", "size": 5, "order": {"_count": "desc"}}},
            "top_groups": {"terms": {"field": "user.groups", "size": 5, "order": {"_count": "desc"}}},
            "top_shells": {"terms": {"field": "user.shell", "size": 5, "order": {"_count": "desc"}}},
        },
    }
    try:
        res = indexer_request("/wazuh-states-inventory-users-*/_search", method="POST", json_body=body)
        aggs = res.get("aggregations") or {}
        return {
            "top_users": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_users", {}).get("buckets", [])],
            "top_groups": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_groups", {}).get("buckets", [])],
            "top_shells": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("top_shells", {}).get("buckets", [])],
        }
    except Exception as e:
        return {"top_users": [], "top_groups": [], "top_shells": [], "error": str(e)}


def get_inventory_users_list(size=15, offset=0, user_name=None, group=None, shell=None, cluster_name=None, sort_field="user.name", sort_order="asc"):
    """Paginated users list from wazuh-states-inventory-users-*."""
    must = []
    if user_name:
        must.append({"wildcard": {"user.name": "*" + user_name + "*"}})
    if group:
        must.append({"term": {"user.groups": group}})
    if shell:
        must.append({"wildcard": {"user.shell": "*" + shell + "*"}})
    if cluster_name:
        must.append({"term": {"wazuh.cluster.name": cluster_name}})
    sort_key = sort_field if sort_field in ("agent.name", "user.name", "user.groups", "user.shell", "user.home") else "user.name"
    body = {
        "size": size,
        "from": offset,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{sort_key: {"order": sort_order, "unmapped_type": "keyword"}}],
        "_source": ["agent.name", "agent.id", "user.name", "user.groups", "user.shell", "user.home"],
    }
    try:
        res = indexer_request("/wazuh-states-inventory-users-*/_search", method="POST", json_body=body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total") or {}
        total_val = total.get("value", total) if isinstance(total, dict) else (total or 0)
        rows = []
        for h in hits:
            s = (h.get("_source") or {})
            rows.append({
                "agent_name": _get_nested(s, "agent.name"),
                "user_name": _get_nested(s, "user.name"),
                "user_groups": _get_nested(s, "user.groups"),
                "user_shell": _get_nested(s, "user.shell"),
                "user_home": _get_nested(s, "user.home"),
            })
        return {"hits": rows, "total": total_val}
    except Exception as e:
        return {"hits": [], "total": 0, "error": str(e)}
