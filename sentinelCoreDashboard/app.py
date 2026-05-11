"""
Sentinel Core SIEM Dashboard – WatchTower (Manager) + WatchVault (Indexer).
Professional SIEM dashboard: Overview, Stack Status, Agent Health, Threat Hunting, Alerts, Vulnerabilities, Compliance.
"""
import os
import re
import hmac
import logging as _logging
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

_logger = _logging.getLogger(__name__)


def _api_error(exc: Exception, status: int = 502) -> tuple:
    """Log the full exception but return a generic message to the client
    so internal details (file paths, query structure) are not leaked."""
    _logger.exception("API error: %s", exc)
    return jsonify({"error": "Backend request failed. See server logs for details."}), status
from config import (
    get_display_config,
    get_dashboard_users,
    _verify_password,
    SECRET_KEY,
    ROLE_SUPER_ADMIN,
    ROLES_CAN_SAVE_DASHBOARD,
    INDEX_PREFIX,
)
from watchtower_client import (
    _os_search,
    _to_epoch_ms,
    get_agents_summary,
    get_agents_list,
    get_agent_by_id,
    get_manager_status,
    get_manager_info,
    get_indexer_health,
    get_indexer_info,
    get_indexer_indices,
    get_index_management_list,
    get_recent_alerts,
    get_alerts_by_severity,
    get_alerts_by_rule,
    get_alerts_by_agent,
    get_alerts_by_user,
    get_alerts_timeline_24h,
    get_alerts_severity_24h,
    get_top_source_ips,
    get_alerts_high_level_count,
    get_mitre_techniques,
    get_alerts_severity_over_time,
    get_alerts_by_tactic,
    get_alerts_cardinality,
    get_rule_groups,
    get_alerts_by_rule_groups,
    get_alerts_list,
    get_discover_fields,
    get_discover_field_values,
    get_hipaa_stats,
    get_hipaa_by_requirement,
    get_hipaa_requirements_high_level,
    get_hipaa_alerts_volume_by_agent,
    get_hipaa_evolution_over_time,
    get_hipaa_by_agent,
    get_hipaa_events_list,
    get_vulnerabilities_summary,
    get_vulnerabilities_recent,
    get_vulnerabilities_list,
    get_vulnerabilities_trends,
    get_vulnerabilities_top_agents,
    get_vulnerabilities_top_packages,
    get_vulnerabilities_kpis,
    get_inventory_system_summary,
    get_inventory_system_list,
    get_inventory_packages_summary,
    get_inventory_packages_list,
    get_inventory_processes_summary,
    get_inventory_processes_start_histogram,
    get_inventory_processes_list,
    get_inventory_users_summary,
    get_inventory_users_list,
    get_rules_list,
    get_rules_files,
    get_rules_file_content,
    put_rules_file,
    delete_rules_file,
    get_decoders_list,
    get_decoders_files,
    get_decoders_file_content,
    put_decoders_file,
    delete_decoders_file,
)

from custom_store import (
    list_visualizations, get_visualization, create_visualization,
    update_visualization, delete_visualization,
    list_dashboards, get_dashboard, create_dashboard,
    update_dashboard, delete_dashboard,
)
from custom_queries import run_visualization as _run_viz

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Secure session cookie flags — never weaken these in production.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Enable Secure flag only when served over HTTPS (set FLASK_HTTPS=true in prod).
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_HTTPS", "false").lower() in ("true", "1", "yes")
app.config["SESSION_COOKIE_NAME"] = "sentinel_session"

# ---------------------------------------------------------------------------
# Login rate limiter — simple in-process tracker (IP + username).
# For multi-process/multi-replica deployments, back this with Redis.
# ---------------------------------------------------------------------------
import time as _time
import threading as _threading
from collections import defaultdict as _defaultdict

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes

_login_attempts: dict = _defaultdict(list)   # key -> [timestamp, ...]
_login_lock = _threading.Lock()


def _login_key() -> str:
    """Per-IP + per-username throttle key."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    username = (request.form.get("username") or "").strip().lower()
    return f"{ip}:{username}"


def _is_login_locked(key: str) -> bool:
    now = _time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_attempts[key] if now - t < _LOGIN_LOCKOUT_SECONDS]
        _login_attempts[key] = attempts
        return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def _record_login_failure(key: str) -> None:
    with _login_lock:
        _login_attempts[key].append(_time.monotonic())


def _clear_login_failures(key: str) -> None:
    with _login_lock:
        _login_attempts.pop(key, None)

@app.after_request
def _set_security_headers(response):
    """Attach security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Content-Security-Policy: tighten per your CDN/static asset setup.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self';"
    )
    return response


# Routes that only super_admin can access (configuration, API connection, settings)
SUPER_ADMIN_ONLY_PATHS = {
    "/api/stack/status",
    "/api/manager/test",
    "/api/indexer/test",
    "/api/indexer/patterns",
    "/api/manager/info",
    "/api/indexer/info",
}


def _check_login():
    """Return (username, role) if logged in, else None."""
    user = session.get("user")
    role = session.get("role")
    if user and role:
        return user, role
    return None


def _validate_dashboard_user(username, password):
    """Return role if credentials are valid, else None.
    Supports both bcrypt hashes ($2b$) and plaintext (dev only) stored credentials.
    """
    users = get_dashboard_users()
    if not username:
        return None
    if username not in users:
        return None
    stored_credential, role = users[username]
    if not _verify_password(password, stored_credential):
        return None
    return role


@app.route("/")
def index():
    if _check_login() is None:
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    # Prevent noisy 404s from browser automatic favicon requests.
    return ("", 204)


@app.route("/login", methods=["GET", "POST"])
def login():
    if _check_login() is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        key = _login_key()
        if _is_login_locked(key):
            return render_template(
                "login.html",
                error="Too many failed attempts. Try again in 15 minutes.",
            ), 429
        role = _validate_dashboard_user(username, password)
        if role:
            _clear_login_failures(key)
            # Regenerate session to prevent session fixation.
            session.clear()
            session["user"] = username
            session["role"] = role
            return redirect(url_for("index"))
        _record_login_failure(key)
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html", error=None)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.pop("user", None)
    session.pop("role", None)
    return redirect(url_for("login"))


@app.route("/api/me")
def api_me():
    """Return current user, role, and permissions; 401 if not logged in. No auth required."""
    login = _check_login()
    if login is None:
        return jsonify({"error": "Unauthorized"}), 401
    user, role = login
    return jsonify({
        "username": user,
        "role": role,
        "can_save_dashboard": role in ROLES_CAN_SAVE_DASHBOARD,
    })


@app.before_request
def _api_auth():
    """Require login for all /api/* except /api/me; require super_admin for config/settings APIs."""
    path = request.path
    if not path.startswith("/api/"):
        return None
    if path == "/api/me":
        return None
    login = _check_login()
    if login is None:
        return jsonify({"error": "Unauthorized", "login_required": True}), 401
    _, role = login
    if path in SUPER_ADMIN_ONLY_PATHS and role != ROLE_SUPER_ADMIN:
        return jsonify({"error": "Forbidden", "required_role": ROLE_SUPER_ADMIN}), 403
    return None


def _normalize_alerts(res, include_hipaa=False):
    """Map indexer hit format to a simple list of alerts.
    Handles both WatchVault flat schema (rule_level, agent_name) and
    legacy nested Wazuh schema (rule.level, agent.name)."""
    hits = (res.get("hits") or {}).get("hits") or []
    out = []
    for h in hits:
        s = h.get("_source") or {}
        # WatchVault flat schema
        rule_id = s.get("rule_id") or (s.get("rule") or {}).get("id")
        rule_desc = s.get("rule_description") or (s.get("rule") or {}).get("description")
        rule_level = s.get("rule_level") or (s.get("rule") or {}).get("level")
        agent_id = s.get("agent_id") or (s.get("agent") or {}).get("id")
        agent_name = s.get("agent_name") or (s.get("agent") or {}).get("name")
        event_data = s.get("event_data") or {}
        if isinstance(event_data, str):
            try:
                import json
                event_data = json.loads(event_data)
            except Exception:
                event_data = {}
        groups = s.get("rule_groups") or (s.get("rule") or {}).get("groups") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        row = {
            "timestamp": s.get("timestamp"),
            "rule_id": rule_id,
            "rule_description": rule_desc,
            "rule_level": rule_level,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_ip": (s.get("agent") or {}).get("ip") or event_data.get("agent_ip"),
            "srcip": event_data.get("srcip") or (s.get("data") or {}).get("srcip"),
            "dstuser": event_data.get("dstuser") or (s.get("data") or {}).get("dstuser"),
            "manager": "WatchTower",
            "rule_groups": groups,
        }
        if include_hipaa:
            hipaa = event_data.get("hipaa") or (s.get("rule") or {}).get("hipaa")
            if isinstance(hipaa, list):
                row["rule_hipaa"] = ", ".join(str(x) for x in hipaa) if hipaa else None
            else:
                row["rule_hipaa"] = str(hipaa) if hipaa is not None else None
        out.append(row)
    return out


def _normalize_vulns(res):
    """Map indexer hits to vulnerability list.
    Handles WatchVault flat schema (severity, cve_id, package_name) and
    legacy nested Wazuh schema (vulnerability.severity, vulnerability.id, package.name)."""
    hits = (res.get("hits") or {}).get("hits") or []
    out = []
    for h in hits:
        s = h.get("_source") or {}
        # WatchVault flat fields
        vuln = s.get("vulnerability") or {}
        pkg = s.get("package") or {}
        agent = s.get("agent") or {}
        out.append({
            "agent_id": s.get("agent_id") or agent.get("id"),
            "agent_name": s.get("agent_name") or agent.get("name"),
            "vuln_id": s.get("cve_id") or vuln.get("id"),
            "severity": s.get("severity") or vuln.get("severity"),
            "description": (s.get("description") or vuln.get("description") or "")[:200],
            "score_base": s.get("cvss_score") or (vuln.get("score", {}).get("base") if isinstance(vuln.get("score"), dict) else None),
            "detected_at": s.get("timestamp") or vuln.get("detected_at"),
            "package_name": s.get("package_name") or pkg.get("name"),
            "package_version": s.get("package_version") or pkg.get("version"),
        })
    return out


def _aggregation_buckets(res, key):
    """Get aggregation buckets from indexer response."""
    aggs = (res.get("aggregations") or {}).get(key) or {}
    return aggs.get("buckets") or []


import time as _time_mod
_agent_map_cache = {}
_agent_map_ts = 0.0
_AGENT_MAP_TTL = 60.0  # seconds

def _get_agent_id_map():
    """Return {agent_id: hostname} from WatchTower, cached for 60 s."""
    global _agent_map_cache, _agent_map_ts
    now = _time_mod.monotonic()
    if now - _agent_map_ts < _AGENT_MAP_TTL and _agent_map_cache:
        return _agent_map_cache
    try:
        res = get_agents_list(limit=500, offset=0)
        raw = res.get("data") or {}
        agents = raw.get("affected_items") or [] if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        _agent_map_cache = {a.get("id", ""): a.get("hostname") or a.get("name") or "" for a in agents if a.get("id")}
        _agent_map_ts = now
    except Exception:
        pass
    return _agent_map_cache


# ---- Manager API proxy ----
@app.route("/api/agents/summary")
def api_agents_summary():
    try:
        data = get_agents_summary()
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/agents")
def api_agents():
    try:
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        data = get_agents_list(limit=limit, offset=offset)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/agents/<agent_id>")
def api_agent_detail(agent_id):
    """Single agent detail for the agent detail page (view eye icon)."""
    from datetime import datetime, timezone
    try:
        raw = get_agent_by_id(agent_id)
        if not raw:
            return jsonify({"error": "Agent not found"}), 404
        status = (raw.get("status") or "unknown").lower().replace(" ", "_")
        os_info = raw.get("os") or {}
        os_name = os_info.get("name") or os_info.get("platform") or ""
        os_ver = os_info.get("version") or ""
        os_label = (os_name + " " + os_ver).strip() or "—"
        groups = raw.get("group") or raw.get("groups") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        group_label = ", ".join(groups) if groups else "default"
        _node = (raw.get("node_name") or raw.get("manager") or "").strip()
        node_name = "WatchTower" if not _node else _node
        _ver = (raw.get("version") or "").strip()
        version = _ver
        last_keep = raw.get("lastKeepAlive") or raw.get("last_keep_alive")
        date_added = raw.get("dateAdd") or raw.get("date_add")
        hostname = (raw.get("hostname") or (os_info.get("hostname") if isinstance(os_info.get("hostname"), str) else "") or "").strip()
        return jsonify({
            "id": raw.get("id"),
            "name": raw.get("name") or raw.get("id"),
            "ip": raw.get("ip") or "any",
            "status": status,
            "os_label": os_label,
            "version": version,
            "group": group_label,
            "groups": groups,
            "node_name": node_name,
            "last_keep_alive": last_keep,
            "date_added": date_added,
            "hostname": hostname or None,
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/agents/health")
def api_agents_health():
    """Agent Health Dashboard: summary, list with OS/lastSeen/offline duration, by_os breakdown."""
    from datetime import datetime, timezone
    try:
        raw = get_agents_list(limit=1000, offset=0)
        data = raw.get("data") or {}
        items = data.get("affected_items") or []
        total = data.get("total_affected_items", len(items)) or len(items)

        status_counts = {"active": 0, "disconnected": 0, "pending": 0, "never_connected": 0}
        by_os = {}  # os_label -> { total, active, disconnected, pending, never_connected }
        now = datetime.now(timezone.utc)
        agents = []

        for a in items:
            status = (a.get("status") or "unknown").lower().replace(" ", "_")
            if status not in status_counts:
                status_counts[status] = 0
            status_counts[status] += 1

            os_info = a.get("os") or {}
            os_name = os_info.get("name") or os_info.get("platform") or ""
            os_ver = os_info.get("version") or ""
            os_label = (os_name + " " + os_ver).strip() or "—"
            if os_label not in by_os:
                by_os[os_label] = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "never_connected": 0}
            by_os[os_label]["total"] += 1
            by_os[os_label][status] = by_os[os_label].get(status, 0) + 1

            last_keep = a.get("lastKeepAlive") or a.get("last_keep_alive")
            last_seen_label = "Never"
            offline_minutes = None
            if last_keep:
                try:
                    t = datetime.fromisoformat(last_keep.replace("Z", "+00:00"))
                    if t.tzinfo is None:
                        t = t.replace(tzinfo=timezone.utc)
                    delta = (now - t).total_seconds()
                    if delta < 60:
                        last_seen_label = "Just now"
                    elif delta < 3600:
                        last_seen_label = f"{int(delta // 60)}m ago"
                    elif delta < 86400:
                        h, m = int(delta // 3600), int((delta % 3600) // 60)
                        last_seen_label = f"{h}h {m}m ago"
                    else:
                        d, r = int(delta // 86400), delta % 86400
                        h = int(r // 3600)
                        last_seen_label = f"{d}d {h}h ago"
                    if status == "disconnected":
                        offline_minutes = int(delta // 60)
                except Exception:
                    last_seen_label = "—"

            date_add = a.get("dateAdd") or a.get("date_add")
            added_label = ""
            if date_add and status == "pending":
                try:
                    t = datetime.fromisoformat(date_add.replace("Z", "+00:00"))
                    if t.tzinfo is None:
                        t = t.replace(tzinfo=timezone.utc)
                    delta_d = int((now - t).total_seconds() // 86400)
                    added_label = f"Added {delta_d}d ago" if delta_d > 0 else "Added today"
                except Exception:
                    pass

            groups = a.get("group") or a.get("groups") or []
            if isinstance(groups, str):
                groups = [g.strip() for g in groups.split(",") if g.strip()]
            group_label = ", ".join(groups) if groups else "default"
            _ver = (a.get("version") or "").strip()
            version = _ver or None
            _node = (a.get("node_name") or a.get("manager") or "").strip()
            node_name = "WatchTower" if not _node else _node
            date_added = a.get("dateAdd") or a.get("date_add")
            hostname = (a.get("hostname") or (os_info.get("hostname") if isinstance(os_info.get("hostname"), str) else "") or "").strip() or None
            agents.append({
                "id": a.get("id"),
                "name": a.get("name") or a.get("id"),
                "ip": a.get("ip") or "any",
                "status": status,
                "os_label": os_label,
                "last_keep_alive": last_keep,
                "last_seen_label": last_seen_label,
                "offline_minutes": offline_minutes,
                "added_label": added_label,
                "version": version,
                "group": group_label,
                "groups": groups,
                "node_name": node_name,
                "date_added": date_added,
                "hostname": hostname,
            })

        active = status_counts.get("active", 0)
        disconnected = status_counts.get("disconnected", 0)
        pending = status_counts.get("pending", 0)
        never_connected = status_counts.get("never_connected", 0)
        pct_active = round(100 * active / total) if total else 0
        pct_disconnected = round(100 * disconnected / total) if total else 0
        pct_pending = round(100 * pending / total) if total else 0

        by_os_list = [
            {"os": k, "total": v["total"], "active": v.get("active", 0), "disconnected": v.get("disconnected", 0), "pending": v.get("pending", 0), "never_connected": v.get("never_connected", 0)}
            for k, v in sorted(by_os.items(), key=lambda x: -x[1]["total"])
        ]

        # Enrich agents with alert counts from OpenSearch
        try:
            alert_body = {
                "size": 0,
                "query": {"match_all": {}},
                "aggs": {
                    "by_agent": {"terms": {"field": "agent_id", "size": 100}},
                    "critical_by_agent": {
                        "filter": {"range": {"rule_level": {"gte": 10}}},
                        "aggs": {"agents": {"terms": {"field": "agent_id", "size": 100}}},
                    },
                },
            }
            alert_res = _os_search(f"{INDEX_PREFIX}-alerts-*", alert_body)
            alert_counts = {b["key"]: b["doc_count"] for b in
                            ((alert_res.get("aggregations") or {}).get("by_agent") or {}).get("buckets", [])}
            crit_counts = {b["key"]: b["doc_count"] for b in
                           ((alert_res.get("aggregations") or {}).get("critical_by_agent") or {})
                           .get("agents", {}).get("buckets", [])}
            for a in agents:
                a["alert_count"] = alert_counts.get(a["id"], 0)
                a["critical_count"] = crit_counts.get(a["id"], 0)
        except Exception:
            for a in agents:
                a.setdefault("alert_count", 0)
                a.setdefault("critical_count", 0)

        return jsonify({
            "updated_at": now.isoformat(),
            "summary": {
                "total": total,
                "active": active,
                "disconnected": disconnected,
                "pending": pending,
                "never_connected": never_connected,
                "pct_active": pct_active,
                "pct_disconnected": pct_disconnected,
                "pct_pending": pct_pending,
            },
            "agents": agents,
            "by_os": by_os_list,
            "trend": [],
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/manager/status")
def api_manager_status():
    try:
        data = get_manager_status()
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


# ---- Indexer API proxy ----
@app.route("/api/indexer/health")
def api_indexer_health():
    try:
        data = get_indexer_health()
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/indexer/indices")
def api_indexer_indices():
    try:
        data = get_indexer_indices()
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/indexer/management/indices")
def api_indexer_management_indices():
    """List indices for Index Management page. Optional query: pattern (default *), bytes (e.g. b)."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        pattern = request.args.get("pattern", "*", type=str).strip() or "*"
        bytes_param = request.args.get("bytes", type=str) or None
        data = get_index_management_list(pattern=pattern, bytes_=bytes_param)
        return jsonify(data if isinstance(data, list) else [])
    except Exception as e:
        return _api_error(e)


@app.route("/api/manager/test")
def api_manager_test():
    """Test WatchTower API connection."""
    try:
        get_manager_info()
        return jsonify({"ok": True, "message": "Connection successful"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route("/api/indexer/test")
def api_indexer_test():
    """Test WatchVault API connection."""
    try:
        get_indexer_info()
        return jsonify({"ok": True, "message": "Connection successful"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route("/api/indexer/patterns")
def api_indexer_patterns():
    """Phase 2.2: Index patterns (watchvault-alerts-*, watchvault-fim-*, etc.) with doc counts."""
    try:
        raw = get_indexer_indices()
        if not isinstance(raw, list):
            raw = []
        # Group by pattern: watchvault-alerts-2025.01.01 -> watchvault-alerts-*
        patterns = {}
        for idx in raw:
            name = (idx.get("index") or "").strip()
            if not name or not name.startswith(f"{INDEX_PREFIX}-"):
                continue
            parts = name.split("-")
            if len(parts) >= 2:
                pattern = f"{parts[0]}-{parts[1]}-*"
            else:
                pattern = name + "*"
            if pattern not in patterns:
                patterns[pattern] = {"pattern": pattern, "indices": [], "total_docs": 0, "status": "exists"}
            doc_count = int(idx.get("docs.count") or idx.get("docs_count") or 0)
            patterns[pattern]["indices"].append({"name": name, "docs": doc_count, "status": idx.get("status", "green")})
            patterns[pattern]["total_docs"] += doc_count
        # Sort by pattern name, primary first
        order = [f"{INDEX_PREFIX}-alerts-*", f"{INDEX_PREFIX}-events-*", f"{INDEX_PREFIX}-fim-*",
                 f"{INDEX_PREFIX}-vulnerability-*", f"{INDEX_PREFIX}-system-*"]
        result = []
        for p in order:
            if p in patterns:
                result.append(patterns[p])
        for p in sorted(patterns.keys()):
            if p not in order:
                result.append(patterns[p])
        return jsonify({"patterns": result})
    except Exception as e:
        return _api_error(e)


@app.route("/api/dashboard/overview")
def api_dashboard_overview():
    """Single payload for home page: KPIs, timeline, top sources, at-risk, MITRE, alerts."""
    try:
        # Parallel fetch
        import concurrent.futures
        out = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            f_alerts = ex.submit(get_recent_alerts, 50)
            f_sev = ex.submit(get_alerts_by_severity)
            f_agents = ex.submit(get_agents_summary)
            f_agents_list = ex.submit(get_agents_list, 15, 0)
            f_timeline = ex.submit(get_alerts_timeline_24h)
            f_sources = ex.submit(get_top_source_ips)
            f_users = ex.submit(get_alerts_by_user, 10)
            f_agent_risk = ex.submit(get_alerts_by_agent, 10)
            f_critical = ex.submit(get_alerts_high_level_count)
            f_mitre = ex.submit(get_mitre_techniques)
            f_sev_24h = ex.submit(get_alerts_severity_24h)
        alerts_res = f_alerts.result()
        sev_res = f_sev.result()
        sev_24h_res = f_sev_24h.result()
        agents_res = f_agents.result()
        agents_list_res = f_agents_list.result()
        timeline_res = f_timeline.result()
        sources_res = f_sources.result()
        users_res = f_users.result()
        agent_risk_res = f_agent_risk.result()
        critical_res = f_critical.result()
        mitre_res = f_mitre.result()

        alerts = _normalize_alerts(alerts_res)
        total_alerts = (alerts_res.get("hits") or {}).get("total") or {}
        total_count = total_alerts.get("value", 0)

        # Risk score 0–100 from average rule level (level 1–15 -> score ~7–100)
        levels = [int(a.get("rule_level") or 0) for a in alerts[:100] if a.get("rule_level")]
        avg_level = sum(levels) / len(levels) if levels else 5
        risk_score = min(100, max(0, int(avg_level * 6.5)))
        out["risk_score"] = risk_score
        out["risk_label"] = "LOW" if risk_score < 40 else "MODERATE" if risk_score < 70 else "HIGH"

        # Critical incidents (level >= 10, last 24h)
        hits_total = (critical_res.get("hits") or {}).get("total")
        critical_count = hits_total.get("value", hits_total) if isinstance(hits_total, dict) else (hits_total or 0)
        out["critical_incidents"] = critical_count
        out["mttr_min"] = 18 + (critical_count % 30)

        # system_health computed below after conn is available; placeholder for now
        out["ingestion_lag"] = "<1SEC"

        # Threat detection rate: pct of recent alerts that have a MITRE technique
        recent_alerts_raw_hits = alerts_res.get("hits", {}).get("hits", [])
        mitre_alert_count = sum(
            1 for h in recent_alerts_raw_hits
            if h.get("_source", {}).get("rule_mitre_technique_id")
               or h.get("_source", {}).get("rule_mitre_tactic")
               or (h.get("_source", {}).get("rule") or {}).get("mitre")
               or (h.get("_source", {}).get("event_data") or {}).get("mitre")
        )
        out["threat_detection_rate"] = round(mitre_alert_count / max(len(recent_alerts_raw_hits), 1) * 100, 1)

        # Timeline 24h
        by_hour = _aggregation_buckets(timeline_res, "by_hour")
        timeline_list = [{"key": b.get("key_as_string"), "count": b.get("doc_count", 0)} for b in by_hour]
        out["timeline_24h"] = timeline_list
        out["timeline_total"] = sum(t["count"] for t in timeline_list)
        out["timeline_peak"] = max([t["count"] for t in timeline_list], default=0)

        # Top sources (IPs)
        src_buckets = _aggregation_buckets(sources_res, "by_ip")
        out["top_sources"] = [{"ip": b.get("key"), "count": b.get("doc_count", 0)} for b in src_buckets]
        out["top_source_first"] = out["top_sources"][0] if out["top_sources"] else None

        # At-risk users (score 0–100 from count rank)
        user_buckets = _aggregation_buckets(users_res, "by_user")
        max_user = max([b.get("doc_count", 0) for b in user_buckets], default=1)
        out["at_risk_users"] = [
            {"name": b.get("key") or "—", "count": b.get("doc_count", 0), "score": min(100, int(100 * b.get("doc_count", 0) / max_user))}
            for b in user_buckets[:5]
        ]

        # At-risk devices (agents)
        agent_buckets = _aggregation_buckets(agent_risk_res, "by_agent")
        max_agent = max([b.get("doc_count", 0) for b in agent_buckets], default=1)
        out["at_risk_devices"] = [
            {"name": b.get("key") or "—", "count": b.get("doc_count", 0), "score": min(100, int(100 * b.get("doc_count", 0) / max_agent))}
            for b in agent_buckets[:5]
        ]

        # MITRE
        mitre_buckets = _aggregation_buckets(mitre_res, "by_technique")
        total_mitre = sum(b.get("doc_count", 0) for b in mitre_buckets)
        out["mitre"] = [
            {"technique": b.get("key") or "—", "count": b.get("doc_count", 0), "pct": round(100 * b.get("doc_count", 0) / total_mitre) if total_mitre else 0}
            for b in mitre_buckets
        ]

        # Agent status for Real-Time Source Assets (merge with at_risk for alert count)
        agent_count_by_name = {d["name"]: d["count"] for d in out["at_risk_devices"]}
        agents_data = (agents_list_res.get("data") or {}).get("affected_items") or []
        out["agent_status_list"] = [
            {
                "id": a.get("id"),
                "name": a.get("name") or a.get("id"),
                "status": (a.get("status") or "unknown").lower(),
                "alerts": agent_count_by_name.get(a.get("name") or a.get("id"), 0),
                "last_keep_alive": a.get("lastKeepAlive") or a.get("last_keep_alive"),
            }
            for a in agents_data[:15]
        ]

        out["recent_alerts"] = alerts[:20]
        out["recent_alerts_total"] = total_count

        # Agents summary (for donut: Active / Disconnected / etc.)
        # Wazuh 4.x typically returns {"data": {"connection": {...}}}; our fallback in
        # get_agents_summary() already normalizes to that shape when the summary
        # endpoint is unavailable. Support both raw and wrapped formats here.
        conn = (
            (agents_res.get("connection") if isinstance(agents_res, dict) else None)
            or ((agents_res.get("data") or {}).get("connection") if isinstance(agents_res, dict) else {})
            or {}
        )
        _total_agents = conn.get("total", 0)
        _active_agents = conn.get("active", 0)
        out["system_health_pct"] = round(_active_agents / max(_total_agents, 1) * 100, 1)
        out["agents_summary"] = {
            "total": _total_agents,
            "active": _active_agents,
            "disconnected": conn.get("disconnected", 0),
            "pending": conn.get("pending", 0),
            "never_connected": conn.get("never_connected", 0),
        }

        # Last 24h alerts by severity (Critical 15+, High 12–14, Medium 7–11, Low 0–6)
        out["alert_severity_24h"] = sev_24h_res if isinstance(sev_24h_res, dict) else {"critical": 0, "high": 0, "medium": 0, "low": 0}

        return jsonify(out)
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/recent")
def api_alerts_recent():
    try:
        size = request.args.get("size", 50, type=int)
        res = get_recent_alerts(size=size)
        alerts = _normalize_alerts(res)
        total = (res.get("hits") or {}).get("total") or {}
        return jsonify({
            "alerts": alerts,
            "total": total.get("value", 0),
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/discover/fields")
def api_discover_fields():
    """Return available field names and types from index mapping for Discover field picker."""
    try:
        index = request.args.get("index", f"{INDEX_PREFIX}-alerts-*", type=str)
        fields = get_discover_fields(index_pattern=index)
        return jsonify({"fields": fields})
    except Exception as e:
        return _api_error(e)


@app.route("/api/discover/field-values")
def api_discover_field_values():
    """Terms aggregation for a field to power filter builder autocomplete."""
    try:
        field = request.args.get("field", type=str)
        if not field:
            return jsonify({"error": "field required"}), 400
        size = request.args.get("size", 25, type=int)
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        index = request.args.get("index", f"{INDEX_PREFIX}-alerts-*", type=str)
        values = get_discover_field_values(field=field, size=size, time_from=time_from, time_to=time_to, index_pattern=index)
        return jsonify({"values": values})
    except Exception as e:
        return _api_error(e)


@app.route("/api/rules")
def api_rules_list():
    """List rules from manager with optional search and pagination."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        limit = request.args.get("limit", 20, type=int)
        offset = request.args.get("offset", 0, type=int)
        search = request.args.get("search", type=str) or None
        rule_ids = request.args.get("rule_ids", type=str) or None
        file_ = request.args.get("file", type=str) or None
        group = request.args.get("group", type=str) or None
        level = request.args.get("level", type=int)
        data = get_rules_list(limit=limit, offset=offset, search=search, rule_ids=rule_ids, file_=file_, group=group, level=level if level is not None else None)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/rules/files")
def api_rules_files():
    """List rule files from manager."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = get_rules_files()
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/rules/files/<path:filename>", methods=["GET", "PUT"])
def api_rules_file(filename):
    """GET: rule file content (raw XML). PUT: upload/replace rule file (body: XML or JSON with 'content' key)."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        relative_dirname = request.args.get("relative_dirname", type=str) or None
        if request.method == "GET":
            raw = request.args.get("raw", "true").lower() in ("1", "true", "yes")
            if raw:
                content = get_rules_file_content(filename, raw=True, relative_dirname=relative_dirname)
                from flask import Response
                return Response(content, mimetype="application/xml")
            data = get_rules_file_content(filename, raw=False, relative_dirname=relative_dirname)
            return jsonify(data)
        else:
            overwrite = request.args.get("overwrite", "true").lower() in ("1", "true", "yes")
            if request.content_type and "application/json" in (request.content_type or ""):
                body = request.get_json(silent=True)
                content = (body.get("content") or body.get("xml") or "") if isinstance(body, dict) else ""
            else:
                content = request.get_data(as_text=True) or ""
            if not content.strip():
                return jsonify({"error": "Empty rule file content"}), 400
            data = put_rules_file(filename, content, overwrite=overwrite, relative_dirname=relative_dirname)
            return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/rules/files/<path:filename>", methods=["DELETE"])
def api_rules_file_delete(filename):
    """Delete a custom rule file."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        relative_dirname = request.args.get("relative_dirname", type=str) or None
        data = delete_rules_file(filename, relative_dirname=relative_dirname)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders")
def api_decoders_list():
    """List decoders from manager."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        limit = request.args.get("limit", 20, type=int)
        offset = request.args.get("offset", 0, type=int)
        search = request.args.get("search", type=str) or None
        filename = request.args.get("filename", type=str) or None
        relative_dirname = request.args.get("relative_dirname", type=str) or None
        data = get_decoders_list(limit=limit, offset=offset, search=search, filename=filename, relative_dirname=relative_dirname)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders/files")
def api_decoders_files():
    """List decoder files from manager."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = get_decoders_files()
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders/files/<path:filename>", methods=["GET", "PUT", "DELETE"])
def api_decoders_file(filename):
    """GET: decoder file content (raw XML). PUT: upload/replace. DELETE: delete custom file."""
    _user, _role = _check_login()
    if not _user:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        relative_dirname = request.args.get("relative_dirname", type=str) or None
        if request.method == "GET":
            raw = request.args.get("raw", "true").lower() in ("1", "true", "yes")
            if raw:
                content = get_decoders_file_content(filename, raw=True, relative_dirname=relative_dirname)
                from flask import Response
                return Response(content, mimetype="application/xml")
            data = get_decoders_file_content(filename, raw=False, relative_dirname=relative_dirname)
            return jsonify(data)
        elif request.method == "DELETE":
            data = delete_decoders_file(filename, relative_dirname=relative_dirname)
            return jsonify(data)
        else:
            overwrite = request.args.get("overwrite", "true").lower() in ("1", "true", "yes")
            if request.content_type and "application/json" in (request.content_type or ""):
                body = request.get_json(silent=True)
                content = (body.get("content") or body.get("xml") or "") if isinstance(body, dict) else ""
            else:
                content = request.get_data(as_text=True) or ""
            if not content.strip():
                return jsonify({"error": "Empty decoder file content"}), 400
            data = put_decoders_file(filename, content, overwrite=overwrite, relative_dirname=relative_dirname)
            return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/list", methods=["GET", "POST"])
def api_alerts_list():
    """Paginated alerts table. Supports DSL (POST body or query param 'dsl') and fields (comma-separated) for Discover."""
    try:
        size = request.args.get("size", 25, type=int)
        offset = request.args.get("offset", 0, type=int)
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        min_level = request.args.get("min_level", type=int)
        agent_name = request.args.get("agent_name", type=str) or None
        rule_group = request.args.get("rule_group", type=str) or None
        search = request.args.get("search", type=str) or None
        fields_param = request.args.get("fields", type=str) or None
        dsl_query = None
        if request.method == "POST" and request.is_json:
            body = request.get_json(silent=True) or {}
            dsl_query = body.get("dsl")
        if dsl_query is None:
            dsl_query = request.args.get("dsl", type=str)
            if dsl_query:
                import json
                try:
                    dsl_query = json.loads(dsl_query)
                except Exception:
                    dsl_query = None
        source_fields = None
        if fields_param:
            source_fields = [f.strip() for f in fields_param.split(",") if f.strip()]
        data = get_alerts_list(
            size=size, offset=offset, time_from=time_from, time_to=time_to,
            min_level=min_level if min_level is not None else None,
            agent_name=agent_name, rule_group=rule_group, search=search,
            dsl_query=dsl_query, source_fields=source_fields,
        )
        hits = data.get("hits", [])
        alerts = _normalize_alerts({"hits": {"hits": hits}})

        # Build agent_id → hostname map from WatchTower for name resolution.
        # Use a short-lived cache so one page-load doesn't hit the manager repeatedly.
        agent_map = _get_agent_id_map()
        for i, hit in enumerate(hits):
            if i < len(alerts):
                src = hit.get("_source") or {}
                # Resolve agent_name from WatchTower when the document field is empty.
                if not alerts[i].get("agent_name") and alerts[i].get("agent_id"):
                    alerts[i]["agent_name"] = agent_map.get(alerts[i]["agent_id"], "")
                    src["agent_name"] = alerts[i]["agent_name"]
                # Expose real network fields as top-level aliases for easier column access.
                fields = (src.get("event_data") or {}).get("fields") or {}
                ev_type = (src.get("event_data") or {}).get("type", "")
                if "network" in ev_type:
                    raddr = fields.get("raddr", "")
                    rport = fields.get("rport", "")
                    laddr = fields.get("laddr", "")
                    lport = fields.get("lport", "")
                    src["net_remote"] = (raddr + ":" + rport).strip(":") if raddr else ""
                    src["net_local"]  = (laddr + ":" + lport).strip(":") if laddr else ""
                    src["net_status"] = fields.get("status", "")
                elif "process" in ev_type:
                    src["proc_name"]    = fields.get("name", "")
                    src["proc_pid"]     = fields.get("pid", "")
                    src["proc_cmdline"] = fields.get("cmdline", "")
                alerts[i]["source"] = src
                if hit.get("_index"):
                    src["_index"] = hit["_index"]
                if hit.get("_id"):
                    src["id"] = hit["_id"]
        return jsonify({"alerts": alerts, "total": data.get("total", 0), "histogram": data.get("histogram", [])})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/dashboard")
def api_alerts_dashboard():
    """Alerts dashboard: KPIs, timeline by severity, top categories, top agents, incidents (high-level alerts)."""
    try:
        import concurrent.futures
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start_24 = int((now - timedelta(hours=24)).timestamp() * 1000)
        end_24 = int(now.timestamp() * 1000)
        out = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            f_sev = ex.submit(get_alerts_severity_24h)
            f_timeline = ex.submit(get_alerts_severity_over_time, 1, "1h", None, start_24, end_24)
            f_categories = ex.submit(get_alerts_by_rule_groups, 10, start_24, end_24)
            f_agents = ex.submit(get_alerts_by_agent, 10, None, start_24, end_24, None, None, None, None)
            f_incidents = ex.submit(get_alerts_list, 10, 0, start_24, end_24, 8, None, None)
            f_total = ex.submit(get_alerts_list, 0, 0, start_24, end_24, None, None, None)
        sev = f_sev.result()
        out["severity_24h"] = sev
        out["total_24h"] = (f_total.result() or {}).get("total", 0)
        timeline_res = f_timeline.result()
        by_date = (timeline_res.get("aggregations") or {}).get("by_date", {}).get("buckets", [])
        timeline_by_severity = []
        for b in by_date:
            key = b.get("key_as_string") or b.get("key")
            by_level = (b.get("by_level") or {}).get("buckets", [])
            crit = high = med = low = 0
            for lev in by_level:
                lv = int(lev.get("key", 0))
                c = lev.get("doc_count", 0)
                if lv >= 12:
                    crit += c
                elif lv >= 8:
                    high += c
                elif lv >= 4:
                    med += c
                else:
                    low += c
            timeline_by_severity.append({"key": key, "critical": crit, "high": high, "medium": med, "low": low})
        out["timeline_24h_by_severity"] = timeline_by_severity
        cat = f_categories.result() or []
        out["top_categories"] = [{"key": c.get("key"), "count": c.get("doc_count", 0)} for c in cat]
        ag = f_agents.result()
        agent_buckets = _aggregation_buckets(ag, "by_agent")
        out["top_agents"] = [{"key": b.get("key"), "count": b.get("doc_count", 0), "agent_id": (b.get("agent_id") or {}).get("buckets")[0].get("key") if (b.get("agent_id") or {}).get("buckets") else None} for b in agent_buckets]
        inc_data = f_incidents.result() or {}
        inc_hits = inc_data.get("hits", [])
        out["incidents"] = _normalize_alerts({"hits": {"hits": inc_hits}})
        return jsonify(out)
    except Exception as e:
        return _api_error(e)


# ----- HIPAA compliance -----

@app.route("/api/hipaa/dashboard")
def api_hipaa_dashboard():
    """HIPAA dashboard: stats, top requirements, by agent, heatmap, evolution over time."""
    try:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        start_24 = time_from or int((now - timedelta(hours=24)).timestamp() * 1000)
        end_24 = time_to or int(now.timestamp() * 1000)
        stats = get_hipaa_stats(start_24, end_24)
        top_requirements = get_hipaa_by_requirement(10, start_24, end_24)
        by_agent = get_hipaa_by_agent(10, start_24, end_24)
        heatmap = get_hipaa_alerts_volume_by_agent(10, 15, start_24, end_24)
        evolution = get_hipaa_evolution_over_time("30m", start_24, end_24, 10)
        return jsonify({
            "total_alerts": stats.get("total_alerts", 0),
            "max_rule_level": stats.get("max_rule_level"),
            "top_requirements": [{"key": r.get("key"), "count": r.get("doc_count", 0)} for r in top_requirements],
            "by_agent": [{"key": a.get("key"), "count": a.get("doc_count", 0)} for a in by_agent],
            "heatmap": heatmap,
            "evolution": evolution,
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/hipaa/controls")
def api_hipaa_controls():
    """HIPAA controls: high-level requirements and detailed requirements with alert counts."""
    try:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        start_24 = time_from or int((now - timedelta(hours=24)).timestamp() * 1000)
        end_24 = time_to or int(now.timestamp() * 1000)
        high_level = get_hipaa_requirements_high_level(start_24, end_24)
        detailed = get_hipaa_by_requirement(50, start_24, end_24)
        return jsonify({
            "high_level": [{"key": h.get("key"), "count": h.get("doc_count", 0)} for h in high_level],
            "requirements": [{"key": r.get("key"), "count": r.get("doc_count", 0)} for r in detailed],
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/hipaa/events")
def api_hipaa_events():
    """Paginated HIPAA events list for Events tab."""
    try:
        size = request.args.get("size", 15, type=int)
        offset = request.args.get("offset", 0, type=int)
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start = time_from or int((now - timedelta(hours=24)).timestamp() * 1000)
        end = time_to or int(now.timestamp() * 1000)
        data = get_hipaa_events_list(size=size, offset=offset, time_from=start, time_to=end)
        events = _normalize_alerts({"hits": {"hits": data.get("hits", [])}}, include_hipaa=True)
        return jsonify({"events": events, "total": data.get("total", 0)})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/by-severity")
def api_alerts_by_severity():
    try:
        res = get_alerts_by_severity()
        buckets = _aggregation_buckets(res, "by_level")
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/by-rule")
def api_alerts_by_rule():
    try:
        size = request.args.get("size", 10, type=int)
        res = get_alerts_by_rule(size=size)
        buckets = _aggregation_buckets(res, "by_rule")
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


# Allowlist patterns for filter parameters — prevent injection into OpenSearch queries.
_RE_SAFE_AGENT_NAME = re.compile(r'^[a-zA-Z0-9._\-]{1,64}$')
_RE_SAFE_AGENT_ID   = re.compile(r'^[a-zA-Z0-9\-]{1,64}$')
_RE_SAFE_RULE_GROUP = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')
_RE_SAFE_RULE_ID    = re.compile(r'^\d{1,10}$')
_RE_SAFE_INTERVAL   = re.compile(r'^\d+[smhdwMy]$')
# Epoch-ms (13 digits) or ISO-8601 date (up to 30 chars of safe chars)
_RE_SAFE_TIMESTAMP  = re.compile(r'^[\d\-T:Z.+]{1,30}$')


def _sanitize_str(value: str | None, pattern: re.Pattern, max_len: int = 64) -> str | None:
    """Return value only if it matches the allowlist pattern, else None."""
    if not value:
        return None
    v = value.strip()[:max_len]
    return v if pattern.match(v) else None


def _dashboard_filter_args():
    """Parse and validate dashboard-level filter params from request.
    All values are checked against strict allowlist regexes before use in queries.
    """
    raw_min_level = request.args.get("min_level", type=int)
    min_level = raw_min_level if raw_min_level is not None and 1 <= raw_min_level <= 15 else None

    time_from_raw = (request.args.get("time_from", type=str) or "").strip()
    time_to_raw   = (request.args.get("time_to", type=str) or "").strip()
    time_from = _sanitize_str(time_from_raw, _RE_SAFE_TIMESTAMP, 30)
    time_to   = _sanitize_str(time_to_raw, _RE_SAFE_TIMESTAMP, 30)

    agent_name = _sanitize_str(request.args.get("agent_name", type=str), _RE_SAFE_AGENT_NAME)
    agent_id   = _sanitize_str(request.args.get("agent_id", type=str), _RE_SAFE_AGENT_ID)
    rule_group = _sanitize_str(request.args.get("rule_group", type=str), _RE_SAFE_RULE_GROUP)

    raw_exclude = (request.args.get("exclude_rule_ids", type=str) or "").strip()
    if raw_exclude:
        safe_ids = [p.strip() for p in raw_exclude.split(",") if _RE_SAFE_RULE_ID.match(p.strip())]
        exclude_rule_ids = ",".join(safe_ids) if safe_ids else None
    else:
        exclude_rule_ids = None

    return min_level, time_from, time_to, agent_name, agent_id, rule_group, exclude_rule_ids


@app.route("/api/alerts/by-agent")
def api_alerts_by_agent():
    try:
        size = request.args.get("size", 15, type=int)
        min_level, time_from, time_to, agent_name, agent_id, rule_group, exclude_rule_ids = _dashboard_filter_args()
        rule_groups = [rule_group] if rule_group else None
        res = get_alerts_by_agent(
            size=size,
            min_level=min_level,
            time_from=time_from,
            time_to=time_to,
            agent_name=agent_name,
            agent_id=agent_id,
            rule_groups=rule_groups,
            exclude_rule_ids=exclude_rule_ids,
        )
        buckets = _aggregation_buckets(res, "by_agent")
        for b in buckets:
            aid = (b.get("agent_id") or {}).get("buckets") or []
            b["agent_id"] = aid[0].get("key") if aid else None
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/severity-over-time")
def api_alerts_severity_over_time():
    """Phase 3/4/6: Date histogram + terms on rule.level; supports dashboard and agent/rule filters."""
    try:
        days = request.args.get("days", 7, type=int)
        interval = request.args.get("interval", "1d", type=str)
        min_level, time_from, time_to, agent_name, agent_id, rule_group, exclude_rule_ids = _dashboard_filter_args()
        rule_groups = [rule_group] if rule_group else None
        res = get_alerts_severity_over_time(
            days=days,
            interval=interval,
            min_level=min_level,
            time_from=time_from,
            time_to=time_to,
            agent_name=agent_name,
            agent_id=agent_id,
            rule_groups=rule_groups,
            exclude_rule_ids=exclude_rule_ids,
        )
        by_date = _aggregation_buckets(res, "by_date")
        series = []
        for b in by_date:
            key = b.get("key_as_string") or b.get("key")
            by_level = (b.get("by_level") or {}).get("buckets") or []
            series.append({"date": key, "buckets": by_level})
        return jsonify({"series": series})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/by-tactic")
def api_alerts_by_tactic():
    """Phase 3/4/6: Terms on rule.mitre.tactic; supports dashboard and agent/rule filters."""
    try:
        size = request.args.get("size", 15, type=int)
        min_level, time_from, time_to, agent_name, agent_id, rule_group, exclude_rule_ids = _dashboard_filter_args()
        rule_groups = [rule_group] if rule_group else None
        res = get_alerts_by_tactic(
            size=size,
            min_level=min_level,
            time_from=time_from,
            time_to=time_to,
            agent_name=agent_name,
            agent_id=agent_id,
            rule_groups=rule_groups,
            exclude_rule_ids=exclude_rule_ids,
        )
        buckets = _aggregation_buckets(res, "by_tactic")
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/rule-groups")
def api_alerts_rule_groups():
    """Phase 6.2: List rule.groups for dashboard filter dropdown."""
    try:
        size = request.args.get("size", 50, type=int)
        groups = get_rule_groups(size=size)
        return jsonify({"rule_groups": groups})
    except Exception as e:
        return _api_error(e)


@app.route("/api/dashboard/stats")
def api_dashboard_stats():
    """Phase 6.1: Unique count of source IPs and agents, total events (advanced aggregations)."""
    try:
        min_level, time_from, time_to, _a, _b, _c, exclude_rule_ids = _dashboard_filter_args()
        data = get_alerts_cardinality(
            time_from=time_from,
            time_to=time_to,
            min_level=min_level,
            exclude_rule_ids=exclude_rule_ids,
        )
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


# ---- Stack verification (Phase 1) ----
@app.route("/api/stack/status")
def api_stack_status():
    """Combined stack status: config (no secrets), WatchTower + WatchVault connection and versions."""
    try:
        display = get_display_config()
        manager_info = get_manager_info()
        indexer_info = get_indexer_info()
        manager_ok = manager_info.get("ok", False)
        indexer_ok = indexer_info.get("ok", False)
        return jsonify({
            "config": display,
            "manager": {
                "connected": manager_ok,
                "info": manager_info.get("info") if manager_ok else None,
                "error": None if manager_ok else (manager_info.get("error") or "Connection failed"),
            },
            "indexer": {
                "connected": indexer_ok,
                "info": indexer_info if indexer_ok else {"error": indexer_info.get("error", "Connection failed")},
            },
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/manager/info")
def api_manager_info():
    try:
        return jsonify(get_manager_info())
    except Exception as e:
        return _api_error(e)


@app.route("/api/indexer/info")
def api_indexer_info():
    try:
        return jsonify(get_indexer_info())
    except Exception as e:
        return _api_error(e)


# ---- Vulnerabilities ----
@app.route("/api/vulnerabilities/summary")
def api_vulnerabilities_summary():
    try:
        res = get_vulnerabilities_summary()
        buckets = _aggregation_buckets(res, "by_severity")
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/vulnerabilities/recent")
def api_vulnerabilities_recent():
    try:
        size = request.args.get("size", 50, type=int)
        res = get_vulnerabilities_recent(size=size)
        vulns = _normalize_vulns(res)
        total = (res.get("hits") or {}).get("total") or {}
        return jsonify({"vulnerabilities": vulns, "total": total.get("value", 0)})
    except Exception as e:
        return _api_error(e)


def _vuln_filter_args():
    """Parse vulnerability filter params from request."""
    severity = request.args.get("severity", type=str) or None
    agent_name = request.args.get("agent_name", type=str) or None
    package = request.args.get("package", type=str) or None
    cve = request.args.get("cve", type=str) or None
    cvss_min = request.args.get("cvss_min", type=float)
    cvss_max = request.args.get("cvss_max", type=float)
    time_from = request.args.get("time_from", type=str) or None
    time_to = request.args.get("time_to", type=str) or None
    return severity, agent_name, package, cve, cvss_min, cvss_max, time_from, time_to


@app.route("/api/vulnerabilities/list")
def api_vulnerabilities_list():
    try:
        size = request.args.get("size", 25, type=int)
        offset = request.args.get("offset", 0, type=int)
        severity, agent_name, package, cve, cvss_min, cvss_max, time_from, time_to = _vuln_filter_args()
        res = get_vulnerabilities_list(
            size=size, offset=offset,
            severity=severity, agent_name=agent_name, package=package, cve=cve,
            cvss_min=cvss_min, cvss_max=cvss_max, time_from=time_from, time_to=time_to,
        )
        hits = res.get("hits", {}).get("hits", [])
        vulns = _normalize_vulns({"hits": {"hits": hits}})
        return jsonify({"vulnerabilities": vulns, "total": res.get("total", 0)})
    except Exception as e:
        return _api_error(e)


@app.route("/api/vulnerabilities/trends")
def api_vulnerabilities_trends():
    try:
        days = request.args.get("days", 30, type=int)
        res = get_vulnerabilities_trends(days=days)
        by_date = _aggregation_buckets(res, "by_date")
        series = []
        for b in by_date:
            key = b.get("key_as_string") or b.get("key")
            by_sev = (b.get("by_severity") or {}).get("buckets") or []
            series.append({"date": key, "buckets": by_sev})
        return jsonify({"series": series})
    except Exception as e:
        return _api_error(e)


@app.route("/api/vulnerabilities/top-agents")
def api_vulnerabilities_top_agents():
    try:
        size = request.args.get("size", 10, type=int)
        severity, _a, _b, _c, _d, _e, time_from, time_to = _vuln_filter_args()
        res = get_vulnerabilities_top_agents(size=size, severity=severity, time_from=time_from, time_to=time_to)
        buckets = _aggregation_buckets(res, "by_agent")
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/vulnerabilities/top-packages")
def api_vulnerabilities_top_packages():
    try:
        size = request.args.get("size", 10, type=int)
        severity, _a, _b, _c, _d, _e, time_from, time_to = _vuln_filter_args()
        res = get_vulnerabilities_top_packages(size=size, severity=severity, time_from=time_from, time_to=time_to)
        buckets = _aggregation_buckets(res, "by_package")
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/vulnerabilities/kpis")
def api_vulnerabilities_kpis():
    try:
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        data = get_vulnerabilities_kpis(time_from=time_from, time_to=time_to)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


# ----- IT Hygiene (inventory) -----

@app.route("/api/inventory/system/summary")
def api_inventory_system_summary():
    try:
        platform = request.args.get("platform", type=str) or None
        name = request.args.get("name", type=str) or None
        architecture = request.args.get("architecture", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        data = get_inventory_system_summary(platform=platform, name=name, architecture=architecture, cluster_name=cluster_name)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/system/list")
def api_inventory_system_list():
    try:
        size = request.args.get("size", 15, type=int)
        offset = request.args.get("offset", 0, type=int)
        platform = request.args.get("platform", type=str) or None
        name = request.args.get("name", type=str) or None
        architecture = request.args.get("architecture", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        sort_field = request.args.get("sort_field", "agent.name", type=str)
        sort_order = request.args.get("sort_order", "asc", type=str)
        data = get_inventory_system_list(size=size, offset=offset, platform=platform, name=name, architecture=architecture, cluster_name=cluster_name, sort_field=sort_field, sort_order=sort_order)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/packages/summary")
def api_inventory_packages_summary():
    try:
        vendor = request.args.get("vendor", type=str) or None
        package_name = request.args.get("package_name", type=str) or None
        package_type = request.args.get("package_type", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        data = get_inventory_packages_summary(vendor=vendor, package_name=package_name, package_type=package_type, cluster_name=cluster_name)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/packages/list")
def api_inventory_packages_list():
    try:
        size = request.args.get("size", 15, type=int)
        offset = request.args.get("offset", 0, type=int)
        vendor = request.args.get("vendor", type=str) or None
        package_name = request.args.get("package_name", type=str) or None
        package_type = request.args.get("package_type", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        sort_field = request.args.get("sort_field", "package.name", type=str)
        sort_order = request.args.get("sort_order", "asc", type=str)
        data = get_inventory_packages_list(size=size, offset=offset, vendor=vendor, package_name=package_name, package_type=package_type, cluster_name=cluster_name, sort_field=sort_field, sort_order=sort_order)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/processes/summary")
def api_inventory_processes_summary():
    try:
        process_name = request.args.get("process_name", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        data = get_inventory_processes_summary(process_name=process_name, cluster_name=cluster_name)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/processes/histogram")
def api_inventory_processes_histogram():
    try:
        cluster_name = request.args.get("cluster_name", type=str) or None
        interval = request.args.get("interval", "1h", type=str)
        data = get_inventory_processes_start_histogram(cluster_name=cluster_name, interval=interval)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/processes/list")
def api_inventory_processes_list():
    try:
        size = request.args.get("size", 15, type=int)
        offset = request.args.get("offset", 0, type=int)
        process_name = request.args.get("process_name", type=str) or None
        command_line = request.args.get("command_line", type=str) or None
        agent_name = request.args.get("agent_name", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        sort_field = request.args.get("sort_field", "process.start", type=str)
        sort_order = request.args.get("sort_order", "desc", type=str)
        data = get_inventory_processes_list(size=size, offset=offset, process_name=process_name, command_line=command_line, agent_name=agent_name, cluster_name=cluster_name, sort_field=sort_field, sort_order=sort_order)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/users/summary")
def api_inventory_users_summary():
    try:
        cluster_name = request.args.get("cluster_name", type=str) or None
        data = get_inventory_users_summary(cluster_name=cluster_name)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/users/list")
def api_inventory_users_list():
    try:
        size = request.args.get("size", 15, type=int)
        offset = request.args.get("offset", 0, type=int)
        user_name = request.args.get("user_name", type=str) or None
        group = request.args.get("group", type=str) or None
        shell = request.args.get("shell", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        sort_field = request.args.get("sort_field", "user.name", type=str)
        sort_order = request.args.get("sort_order", "asc", type=str)
        data = get_inventory_users_list(size=size, offset=offset, user_name=user_name, group=group, shell=shell, cluster_name=cluster_name, sort_field=sort_field, sort_order=sort_order)
        return jsonify(data)
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# MITRE ATT&CK matrix endpoint
# ---------------------------------------------------------------------------

@app.route("/api/mitre/matrix")
def api_mitre_matrix():
    """MITRE ATT&CK matrix: tactics and techniques aggregated from alerts."""
    try:
        tactics_res = get_alerts_by_tactic(size=20)
        tactic_buckets = _aggregation_buckets(tactics_res, "by_tactic")
        tactics_out = [
            {"tactic": b.get("key") or "—", "count": b.get("doc_count", 0)}
            for b in tactic_buckets
        ]

        techniques_res = get_mitre_techniques(size=50)
        tech_buckets = _aggregation_buckets(techniques_res, "by_technique")
        techniques_out = [
            {
                "technique_id": b.get("key") or "—",
                "key": b.get("key") or "—",
                "technique_name": b.get("key") or "—",
                "count": b.get("doc_count", 0),
            }
            for b in tech_buckets
        ]
        return jsonify({"tactics": tactics_out, "techniques": techniques_out, "total_techniques": len(techniques_out)})
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# File Integrity Monitoring (FIM) endpoints
# ---------------------------------------------------------------------------

@app.route("/api/fim/summary")
def api_fim_summary():
    """FIM summary: total changes, added/modified/deleted counts in last 24h."""
    try:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(hours=24)).timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}},
                        {"bool": {"should": [
                            {"match": {"collector": "fim"}},
                            {"match": {"event_type": "fim"}},
                            {"match": {"type": "fim"}},
                        ], "minimum_should_match": 1}}
                    ]
                }
            },
            "aggs": {
                "by_action": {
                    "terms": {"field": "fim_action.keyword", "size": 20}
                },
                "by_action_alt": {
                    "terms": {"field": "action.keyword", "size": 20}
                }
            }
        }
        res = _os_search(f"{INDEX_PREFIX}-events-*", body)
        total = (res.get("hits") or {}).get("total") or {}
        total_count = total.get("value", 0) if isinstance(total, dict) else (total or 0)

        if total_count == 0:
            # Also try the FIM-specific index
            res2 = _os_search(f"{INDEX_PREFIX}-fim-*", {"size": 0, "query": {"match_all": {}},
                "aggs": {"by_action": {"terms": {"field": "action.keyword", "size": 20}}}})
            total2 = (res2.get("hits") or {}).get("total") or {}
            total_count = total2.get("value", 0) if isinstance(total2, dict) else (total2 or 0)
            if total_count > 0:
                res = res2

        buckets = _aggregation_buckets(res, "by_action")
        if not buckets:
            buckets = _aggregation_buckets(res, "by_action_alt")

        action_counts = {}
        for b in buckets:
            key = (b.get("key") or "").lower()
            action_counts[key] = b.get("doc_count", 0)

        added = action_counts.get("added", 0) + action_counts.get("add", 0) + action_counts.get("created", 0)
        modified = action_counts.get("modified", 0) + action_counts.get("modify", 0) + action_counts.get("changed", 0)
        deleted = action_counts.get("deleted", 0) + action_counts.get("delete", 0) + action_counts.get("removed", 0)

        return jsonify({
            "total": total_count,
            "added": added,
            "modified": modified,
            "deleted": deleted,
        })
    except Exception as e:
        return jsonify({"total": 0, "added": 0, "modified": 0, "deleted": 0})


@app.route("/api/fim/events")
def api_fim_events():
    """Paginated FIM events. Supports size, offset, agent_name, path query params."""
    try:
        size = request.args.get("size", 20, type=int)
        offset = request.args.get("offset", 0, type=int)
        agent_name = request.args.get("agent_name", type=str) or None
        path_filter = request.args.get("path", type=str) or None

        must_clauses = [
            {"bool": {"should": [
                {"match": {"collector": "fim"}},
                {"match": {"event_type": "fim"}},
                {"match": {"type": "fim"}},
            ], "minimum_should_match": 1}}
        ]
        if agent_name:
            must_clauses.append({"match": {"agent_name": agent_name}})
        if path_filter:
            must_clauses.append({"query_string": {"query": f"*{path_filter}*", "fields": ["fim_path", "file_path", "event_data.path"]}})

        body = {
            "size": size,
            "from": offset,
            "query": {"bool": {"must": must_clauses}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        res = _os_search(f"{INDEX_PREFIX}-events-*", body)
        raw_hits = (res.get("hits") or {}).get("hits") or []
        if not raw_hits:
            res2 = _os_search(f"{INDEX_PREFIX}-fim-*", body)
            raw_hits = (res2.get("hits") or {}).get("hits") or []
            total = (res2.get("hits") or {}).get("total") or {}
        else:
            total = (res.get("hits") or {}).get("total") or {}

        total_count = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        hits = [h.get("_source", {}) for h in raw_hits]
        return jsonify({"hits": hits, "total": total_count})
    except Exception as e:
        return jsonify({"hits": [], "total": 0})


# ---------------------------------------------------------------------------
# Audit Trail endpoints
# ---------------------------------------------------------------------------

@app.route("/api/audit/summary")
def api_audit_summary():
    """Auth/audit summary: total auth events, failed/successful logins, sudo events in last 24h."""
    try:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(hours=24)).timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
                    ],
                    "should": [
                        {"match": {"rule_groups": "authentication"}},
                        {"match": {"rule_groups": "sshd"}},
                        {"match": {"rule_groups": "pam"}},
                        {"match": {"rule_groups": "sudo"}},
                        {"match_phrase": {"rule_description": "ssh"}},
                        {"match_phrase": {"rule_description": "pam"}},
                        {"match_phrase": {"rule_description": "sudo"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "aggs": {
                "by_rule_id": {"terms": {"field": "rule_id", "size": 100}},
                "failed": {
                    "filter": {"bool": {"should": [
                        {"match": {"rule_description": "failed"}},
                        {"match": {"rule_description": "invalid"}},
                        {"match": {"rule_description": "authentication failure"}},
                    ], "minimum_should_match": 1}}
                },
                "sudo_events": {
                    "filter": {"bool": {"should": [
                        {"match": {"rule_groups": "sudo"}},
                        {"match": {"rule_description": "sudo"}},
                    ], "minimum_should_match": 1}}
                },
            }
        }
        res = _os_search(f"{INDEX_PREFIX}-alerts-*", body)
        total_hits = (res.get("hits") or {}).get("total") or {}
        total_count = total_hits.get("value", 0) if isinstance(total_hits, dict) else (total_hits or 0)

        aggs = res.get("aggregations") or {}
        failed_count = (aggs.get("failed") or {}).get("doc_count", 0)
        sudo_count = (aggs.get("sudo_events") or {}).get("doc_count", 0)
        successful = max(0, total_count - failed_count - sudo_count)

        return jsonify({
            "total": total_count,
            "failed_logins": failed_count,
            "successful_logins": successful,
            "sudo_events": sudo_count,
        })
    except Exception as e:
        return jsonify({"total": 0, "failed_logins": 0, "successful_logins": 0, "sudo_events": 0})


@app.route("/api/audit/events")
def api_audit_events():
    """Paginated auth/audit events. Supports size, offset, agent_name, time_from, time_to."""
    try:
        from datetime import datetime, timezone, timedelta
        size = request.args.get("size", 20, type=int)
        offset = request.args.get("offset", 0, type=int)
        agent_name = request.args.get("agent_name", type=str) or None
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None

        now = datetime.now(timezone.utc)
        start_ms = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end_ms = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)

        must_clauses = [{"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}]
        if agent_name:
            must_clauses.append({"match": {"agent_name": agent_name}})

        body = {
            "size": size,
            "from": offset,
            "query": {
                "bool": {
                    "must": must_clauses,
                    "should": [
                        {"match": {"rule_groups": "authentication"}},
                        {"match": {"rule_groups": "sshd"}},
                        {"match": {"rule_groups": "pam"}},
                        {"match": {"rule_groups": "sudo"}},
                        {"match_phrase": {"rule_description": "ssh"}},
                        {"match_phrase": {"rule_description": "pam"}},
                        {"match_phrase": {"rule_description": "sudo"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        res = _os_search(f"{INDEX_PREFIX}-alerts-*", body)
        raw_hits = (res.get("hits") or {}).get("hits") or []
        total_hits = (res.get("hits") or {}).get("total") or {}
        total_count = total_hits.get("value", 0) if isinstance(total_hits, dict) else (total_hits or 0)
        hits = [h.get("_source", {}) for h in raw_hits]
        return jsonify({"hits": hits, "total": total_count})
    except Exception as e:
        return jsonify({"hits": [], "total": 0})


# ---------------------------------------------------------------------------
# SCA / Policy Monitoring endpoints
# ---------------------------------------------------------------------------

@app.route("/api/sca/summary")
def api_sca_summary():
    """SCA summary: total checks, passed/failed/not_applicable, score, agents checked."""
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "should": [
                        {"match": {"collector": "sca"}},
                        {"match": {"event_type": "sca"}},
                        {"match": {"type": "sca"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "aggs": {
                "by_result": {"terms": {"field": "sca_result.keyword", "size": 10}},
                "by_result_alt": {"terms": {"field": "result.keyword", "size": 10}},
                "agents_checked": {"cardinality": {"field": "agent_name.keyword"}},
            }
        }
        res = _os_search(f"{INDEX_PREFIX}-events-*", body)
        total_hits = (res.get("hits") or {}).get("total") or {}
        total_count = total_hits.get("value", 0) if isinstance(total_hits, dict) else (total_hits or 0)

        if total_count == 0:
            return jsonify({"total_checks": 0, "passed": 0, "failed": 0, "not_applicable": 0, "score_pct": 0, "agents_checked": 0})

        aggs = res.get("aggregations") or {}
        buckets = (aggs.get("by_result") or {}).get("buckets") or []
        if not buckets:
            buckets = (aggs.get("by_result_alt") or {}).get("buckets") or []

        result_counts = {}
        for b in buckets:
            key = (b.get("key") or "").lower()
            result_counts[key] = b.get("doc_count", 0)

        passed = result_counts.get("passed", 0) + result_counts.get("pass", 0)
        failed = result_counts.get("failed", 0) + result_counts.get("fail", 0)
        not_applicable = result_counts.get("not_applicable", 0) + result_counts.get("na", 0) + result_counts.get("not applicable", 0)
        agents_checked = (aggs.get("agents_checked") or {}).get("value", 0)
        score_pct = round(passed / max(passed + failed, 1) * 100, 1) if (passed + failed) > 0 else 0

        return jsonify({
            "total_checks": total_count,
            "passed": passed,
            "failed": failed,
            "not_applicable": not_applicable,
            "score_pct": score_pct,
            "agents_checked": agents_checked,
        })
    except Exception as e:
        return jsonify({"total_checks": 0, "passed": 0, "failed": 0, "not_applicable": 0, "score_pct": 0, "agents_checked": 0})


@app.route("/api/sca/agents")
def api_sca_agents():
    """Per-agent SCA scores, paginated."""
    try:
        size = request.args.get("size", 20, type=int)

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "should": [
                        {"match": {"collector": "sca"}},
                        {"match": {"event_type": "sca"}},
                        {"match": {"type": "sca"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent_name.keyword", "size": size},
                    "aggs": {
                        "passed": {"filter": {"bool": {"should": [
                            {"match": {"sca_result": "passed"}},
                            {"match": {"result": "passed"}},
                        ], "minimum_should_match": 1}}},
                        "failed": {"filter": {"bool": {"should": [
                            {"match": {"sca_result": "failed"}},
                            {"match": {"result": "failed"}},
                        ], "minimum_should_match": 1}}},
                        "not_applicable": {"filter": {"bool": {"should": [
                            {"match": {"sca_result": "not_applicable"}},
                            {"match": {"result": "not_applicable"}},
                        ], "minimum_should_match": 1}}},
                        "last_scan": {"max": {"field": "timestamp"}},
                    }
                }
            }
        }
        res = _os_search(f"{INDEX_PREFIX}-events-*", body)
        aggs = res.get("aggregations") or {}
        agent_buckets = (aggs.get("by_agent") or {}).get("buckets") or []

        agents_out = []
        for b in agent_buckets:
            passed = (b.get("passed") or {}).get("doc_count", 0)
            failed = (b.get("failed") or {}).get("doc_count", 0)
            not_applicable = (b.get("not_applicable") or {}).get("doc_count", 0)
            total = b.get("doc_count", 0)
            score_pct = round(passed / max(passed + failed, 1) * 100, 1) if (passed + failed) > 0 else 0
            last_scan_val = (b.get("last_scan") or {}).get("value_as_string") or (b.get("last_scan") or {}).get("value")
            agents_out.append({
                "agent_name": b.get("key") or "—",
                "policy": "CIS Benchmark",
                "total_checks": total,
                "passed": passed,
                "failed": failed,
                "not_applicable": not_applicable,
                "score_pct": score_pct,
                "last_scan": last_scan_val,
            })
        return jsonify({"agents": agents_out, "total": len(agents_out)})
    except Exception as e:
        return jsonify({"agents": [], "total": 0})


# ===========================================================================
# Custom Visualizations & Dashboards
# ===========================================================================

@app.route("/api/custom/visualizations", methods=["GET"])
def api_custom_viz_list():
    try:
        return jsonify({"visualizations": list_visualizations()})
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/visualizations", methods=["POST"])
def api_custom_viz_create():
    try:
        body = request.get_json(silent=True) or {}
        title = (body.get("title") or "Untitled").strip()[:120]
        viz_type = body.get("viz_type", "metric")
        datasource = body.get("datasource", "watchvault-alerts-*")
        config = body.get("config") or {}
        viz = create_visualization(title, viz_type, datasource, config)
        return jsonify(viz), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/visualizations/<viz_id>", methods=["GET"])
def api_custom_viz_get(viz_id):
    try:
        viz = get_visualization(viz_id)
        if not viz:
            return jsonify({"error": "Not found"}), 404
        return jsonify(viz)
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/visualizations/<viz_id>", methods=["PUT"])
def api_custom_viz_update(viz_id):
    try:
        body = request.get_json(silent=True) or {}
        viz = update_visualization(
            viz_id,
            title=body.get("title"),
            viz_type=body.get("viz_type"),
            datasource=body.get("datasource"),
            config=body.get("config"),
        )
        if not viz:
            return jsonify({"error": "Not found"}), 404
        return jsonify(viz)
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/visualizations/<viz_id>", methods=["DELETE"])
def api_custom_viz_delete(viz_id):
    try:
        delete_visualization(viz_id)
        return jsonify({"ok": True})
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/visualizations/<viz_id>/preview", methods=["POST"])
def api_custom_viz_preview(viz_id):
    try:
        body = request.get_json(silent=True) or {}
        # Can preview with saved viz or with inline config (for builder)
        if viz_id == "_inline":
            viz_type = body.get("viz_type", "metric")
            datasource = body.get("datasource", "watchvault-alerts-*")
            config = body.get("config") or {}
        else:
            viz = get_visualization(viz_id)
            if not viz:
                return jsonify({"error": "Not found"}), 404
            viz_type = viz["viz_type"]
            datasource = viz["datasource"]
            config = viz["config"]
        time_filter = body.get("time_filter", "24h")
        data = _run_viz(viz_type, datasource, config, time_filter)
        return jsonify({"viz_type": viz_type, "data": data})
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/dashboards", methods=["GET"])
def api_custom_dash_list():
    try:
        return jsonify({"dashboards": list_dashboards()})
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/dashboards", methods=["POST"])
def api_custom_dash_create():
    try:
        body = request.get_json(silent=True) or {}
        title = (body.get("title") or "New Dashboard").strip()[:120]
        description = (body.get("description") or "").strip()[:500]
        widgets = body.get("widgets") or []
        time_filter = body.get("time_filter", "24h")
        dash = create_dashboard(title, description, widgets, time_filter)
        return jsonify(dash), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/dashboards/<dash_id>", methods=["GET"])
def api_custom_dash_get(dash_id):
    try:
        dash = get_dashboard(dash_id)
        if not dash:
            return jsonify({"error": "Not found"}), 404
        return jsonify(dash)
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/dashboards/<dash_id>", methods=["PUT"])
def api_custom_dash_update(dash_id):
    try:
        body = request.get_json(silent=True) or {}
        dash = update_dashboard(
            dash_id,
            title=body.get("title"),
            description=body.get("description"),
            widgets=body.get("widgets"),
            time_filter=body.get("time_filter"),
        )
        if not dash:
            return jsonify({"error": "Not found"}), 404
        return jsonify(dash)
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/dashboards/<dash_id>", methods=["DELETE"])
def api_custom_dash_delete(dash_id):
    try:
        delete_dashboard(dash_id)
        return jsonify({"ok": True})
    except Exception as e:
        return _api_error(e)

@app.route("/api/custom/dashboards/<dash_id>/run", methods=["POST"])
def api_custom_dash_run(dash_id):
    """Run all widget queries in a dashboard and return results keyed by widget index."""
    try:
        body = request.get_json(silent=True) or {}
        time_filter = body.get("time_filter")
        dash = get_dashboard(dash_id)
        if not dash:
            return jsonify({"error": "Not found"}), 404
        time_filter = time_filter or dash.get("time_filter", "24h")
        results = {}
        for i, widget in enumerate(dash.get("widgets") or []):
            viz_id = widget.get("viz_id")
            if not viz_id:
                continue
            viz = get_visualization(viz_id)
            if not viz:
                results[str(i)] = {"error": "Visualization not found"}
                continue
            data = _run_viz(viz["viz_type"], viz["datasource"], viz["config"], time_filter)
            results[str(i)] = {"viz_type": viz["viz_type"], "title": viz["title"], "data": data}
        return jsonify({"results": results, "time_filter": time_filter})
    except Exception as e:
        return _api_error(e)


# ── Start background alert watcher (email/Slack notifications) ──────────────
try:
    from notifier import AlertWatcher
    from watchtower_client import _os_search as _aw_os_search
    _alert_watcher = AlertWatcher(_aw_os_search, INDEX_PREFIX)
    _alert_watcher.start()
except Exception as _aw_err:
    _logger.warning("AlertWatcher not started: %s", _aw_err)


# ---------------------------------------------------------------------------
# Notifications — config and test endpoints
# ---------------------------------------------------------------------------

@app.route("/api/notifications/config", methods=["GET"])
def api_notifications_config():
    """Return current notification config (no secrets)."""
    from notifier import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_FROM, SMTP_TLS, ALERT_TO, SLACK_WEBHOOK, THROTTLE_MIN
    return jsonify({
        "smtp_configured": bool(SMTP_HOST and ALERT_TO),
        "slack_configured": bool(SLACK_WEBHOOK),
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "smtp_user": SMTP_USER,
        "smtp_from": SMTP_FROM,
        "smtp_tls": SMTP_TLS,
        "alert_to": ALERT_TO,
        "slack_configured_bool": bool(SLACK_WEBHOOK),
        "throttle_minutes": THROTTLE_MIN,
    })


@app.route("/api/notifications/test", methods=["POST"])
def api_notifications_test():
    """Send a test email/slack notification."""
    try:
        from notifier import send_email, send_slack, _alert_email_html
        results = {}
        test_alert = {
            "rule_id": 9999, "rule_description": "Test notification from Sentinel SIEM",
            "rule_level": 10, "rule_groups": ["test"], "agent_name": "test-agent",
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }
        body = request.get_json(silent=True) or {}
        channel = body.get("channel", "all")
        if channel in ("email", "all"):
            results["email"] = send_email(
                "[Sentinel SIEM] Test Notification",
                _alert_email_html(test_alert)
            )
        if channel in ("slack", "all"):
            results["slack"] = send_slack(test_alert)
        return jsonify({"results": results})
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Reports — PDF and HTML security reports
# ---------------------------------------------------------------------------

@app.route("/api/reports/generate", methods=["POST"])
def api_reports_generate():
    """Generate a PDF (or HTML) security report for the requested time range."""
    try:
        import concurrent.futures
        from datetime import datetime, timezone, timedelta

        body = request.get_json(silent=True) or {}
        time_range = body.get("time_range", "7d")
        fmt = body.get("format", "pdf")   # "pdf" or "html"

        now = datetime.now(timezone.utc)
        days_map = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
        days = days_map.get(time_range, 7)
        start_ms = int((now - timedelta(days=days)).timestamp() * 1000)
        end_ms   = int(now.timestamp() * 1000)
        label    = {1: "Last 24 hours", 7: "Last 7 days", 30: "Last 30 days", 90: "Last 90 days"}.get(days, time_range)

        # Gather data in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            f_agents    = ex.submit(get_agents_list, 1000, 0)
            f_kpis      = ex.submit(get_vulnerabilities_kpis, start_ms, end_ms)
            f_top_rules = ex.submit(_os_search, f"{INDEX_PREFIX}-alerts-*", {
                "size": 0,
                "query": {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}},
                "aggs": {
                    "by_rule": {"terms": {"field": "rule_id", "size": 20}},
                    "by_level": {"terms": {"field": "rule_level", "size": 10}},
                    "total":    {"value_count": {"field": "rule_id"}},
                },
            })
            f_vulns     = ex.submit(get_vulnerabilities_list, 10, 0)

        # Process agents
        raw_agents = f_agents.result()
        agents_data = raw_agents.get("data") or {}
        agent_items = agents_data.get("affected_items") or []
        active = sum(1 for a in agent_items if (a.get("status") or "").lower() == "active")

        # Process alert rules aggregation
        rules_res  = f_top_rules.result()
        rules_aggs = rules_res.get("aggregations") or {}
        total_alerts = (rules_aggs.get("total") or {}).get("value", 0)
        by_level_raw = {b["key"]: b["doc_count"] for b in (rules_aggs.get("by_level") or {}).get("buckets", [])}

        # Map level numbers to severity labels
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for lv, cnt in by_level_raw.items():
            lv = int(lv)
            if lv >= 12:   by_severity["CRITICAL"] += cnt
            elif lv >= 8:  by_severity["HIGH"]     += cnt
            elif lv >= 4:  by_severity["MEDIUM"]   += cnt
            else:          by_severity["LOW"]       += cnt

        # Top alert rules
        top_rules_buckets = (rules_aggs.get("by_rule") or {}).get("buckets", [])

        # Fetch rule descriptions for the top rule IDs
        rule_ids = [b["key"] for b in top_rules_buckets[:15]]
        rule_descs = {}
        if rule_ids:
            try:
                sample_res = _os_search(f"{INDEX_PREFIX}-alerts-*", {
                    "size": len(rule_ids),
                    "query": {"terms": {"rule_id": rule_ids}},
                    "_source": ["rule_id", "rule_description", "rule_level"],
                    "collapse": {"field": "rule_id"},
                })
                for h in (sample_res.get("hits") or {}).get("hits", []):
                    s = h.get("_source", {})
                    rule_descs[s.get("rule_id")] = (s.get("rule_description", ""), s.get("rule_level", 0))
            except Exception:
                pass

        top_alerts = []
        for b in top_rules_buckets[:15]:
            rid = b["key"]
            desc, level = rule_descs.get(rid, ("", 0))
            top_alerts.append({"rule_id": rid, "description": desc, "level": level, "count": b["doc_count"]})

        # Vulnerability KPIs
        vuln_kpis = f_kpis.result()
        vuln_list = f_vulns.result().get("hits", [])

        data = {
            "summary": {
                "total_alerts": total_alerts,
                "active_agents": active,
                "total_agents": len(agent_items),
                "unique_cves": vuln_kpis.get("unique_cves", 0),
                "critical_high": vuln_kpis.get("critical_high", 0),
            },
            "by_severity": by_severity,
            "top_alerts": top_alerts,
            "agents": [
                {
                    "name": a.get("name") or a.get("hostname", ""),
                    "status": a.get("status", ""),
                    "os_label": (a.get("os") or {}).get("platform", ""),
                    "alert_count": 0,
                }
                for a in agent_items[:20]
            ],
            "top_vulns": vuln_list[:10],
        }

        from report_generator import generate_pdf, generate_html
        report_type_label = {
            "24h": "Daily Report", "7d": "Weekly Report",
            "30d": "Monthly Report", "90d": "Quarterly Report",
        }.get(time_range, "Security Report")

        if fmt == "html":
            html = generate_html(data, report_type_label, label)
            return html, 200, {"Content-Type": "text/html; charset=utf-8"}

        pdf_bytes = generate_pdf(data, report_type_label, label)
        if pdf_bytes is None:
            # WeasyPrint not available — return HTML with a notice
            html = generate_html(data, report_type_label, label)
            return html, 200, {
                "Content-Type": "text/html; charset=utf-8",
                "X-Report-Format": "html-fallback",
            }

        filename = f"sentinel-report-{time_range}-{now.strftime('%Y%m%d')}.pdf"
        return pdf_bytes, 200, {
            "Content-Type": "application/pdf",
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
    except Exception as e:
        return _api_error(e)


@app.route("/api/reports/preview", methods=["GET"])
def api_reports_preview():
    """Quick HTML preview — same data as generate but always HTML, no download."""
    try:
        from flask import redirect
        return redirect("/api/reports/generate", code=307)
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Active Response — trigger WatchTower responses from the dashboard
# ---------------------------------------------------------------------------

@app.route("/api/active-response/block-ip", methods=["POST"])
def api_ar_block_ip():
    """Send a firewall-drop command to all agents or a specific agent."""
    _user, role = _check_login() or (None, None)
    if role not in (ROLE_SUPER_ADMIN, "administrator", "admin"):
        return jsonify({"error": "Insufficient permissions"}), 403
    try:
        body = request.get_json(silent=True) or {}
        ip   = (body.get("ip") or "").strip()
        agent_id = (body.get("agent_id") or "").strip()
        if not ip:
            return jsonify({"error": "ip required"}), 400
        # Call WatchTower active response API
        payload = {
            "action": "firewall-drop",
            "arguments": ["-srcip", ip],
            "alert": {"data": {"srcip": ip}},
        }
        if agent_id:
            payload["agents"] = [agent_id]
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/active-response", method="PUT", json_body=payload)
        return jsonify({"ok": True, "ip": ip, "response": res})
    except Exception as e:
        return _api_error(e)


@app.route("/api/active-response/kill-process", methods=["POST"])
def api_ar_kill_process():
    """Send a kill-process command to a specific agent."""
    _user, role = _check_login() or (None, None)
    if role not in (ROLE_SUPER_ADMIN, "administrator", "admin"):
        return jsonify({"error": "Insufficient permissions"}), 403
    try:
        body     = request.get_json(silent=True) or {}
        pid      = body.get("pid")
        agent_id = (body.get("agent_id") or "").strip()
        if not pid or not agent_id:
            return jsonify({"error": "pid and agent_id required"}), 400
        from watchtower_client import watchtower_request
        payload = {
            "action": "kill-process",
            "arguments": [str(pid)],
            "agents": [agent_id],
        }
        res = watchtower_request("/api/v1/active-response", method="PUT", json_body=payload)
        return jsonify({"ok": True, "pid": pid, "agent_id": agent_id, "response": res})
    except Exception as e:
        return _api_error(e)


@app.route("/api/active-response/history", methods=["GET"])
def api_ar_history():
    """Return recent active response actions from WatchTower."""
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/active-response/history", method="GET")
        return jsonify(res or {"history": []})
    except Exception as e:
        return jsonify({"history": [], "error": str(e)})


# ── Case Management ───────────────────────────────────────────────────────────

@app.route("/api/cases", methods=["GET"])
def api_cases_list():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/cases", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases", methods=["POST"])
def api_cases_create():
    try:
        from watchtower_client import watchtower_request
        user = session.get("username", "anonymous")
        body = request.get_json(force=True) or {}
        body.setdefault("created_by", user)
        res = watchtower_request("/api/v1/cases", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>", methods=["GET"])
def api_cases_get(case_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/cases/{case_id}", method="GET")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>", methods=["PUT"])
def api_cases_update(case_id):
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request(f"/api/v1/cases/{case_id}", method="PUT", json_body=body)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>", methods=["DELETE"])
def api_cases_delete(case_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/cases/{case_id}", method="DELETE")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>/notes", methods=["GET"])
def api_cases_notes_list(case_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/cases/{case_id}/notes", method="GET")
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>/notes", methods=["POST"])
def api_cases_notes_add(case_id):
    try:
        from watchtower_client import watchtower_request
        user = session.get("username", "anonymous")
        body = request.get_json(force=True) or {}
        body.setdefault("author", user)
        res = watchtower_request(f"/api/v1/cases/{case_id}/notes", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>/evidence", methods=["GET"])
def api_cases_evidence_list(case_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/cases/{case_id}/evidence", method="GET")
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cases/<int:case_id>/evidence", methods=["POST"])
def api_cases_evidence_add(case_id):
    try:
        from watchtower_client import watchtower_request
        user = session.get("username", "anonymous")
        body = request.get_json(force=True) or {}
        body.setdefault("added_by", user)
        res = watchtower_request(f"/api/v1/cases/{case_id}/evidence", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)


# ── Identity Management ───────────────────────────────────────────────────────

@app.route("/api/identity/status", methods=["GET"])
def api_identity_status():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/identity/status", method="GET")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/identity/users", methods=["GET"])
def api_identity_users():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/identity/users", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/identity/users", methods=["POST"])
def api_identity_users_create():
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request("/api/v1/identity/users", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/identity/users/<sam>", methods=["GET"])
def api_identity_user_get(sam):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/identity/users/{sam}", method="GET")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/identity/users/<sam>", methods=["DELETE"])
def api_identity_user_delete(sam):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/identity/users/{sam}", method="DELETE")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/identity/sync", methods=["POST"])
def api_identity_sync():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/identity/sync", method="POST")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)


# ── Detection Versioning ──────────────────────────────────────────────────────

@app.route("/api/rule-versions", methods=["GET"])
def api_rv_list_files():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/rule-versions", method="GET")
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rule-versions/history", methods=["GET"])
def api_rv_history():
    try:
        from watchtower_client import watchtower_request
        params = {"file": request.args.get("file", "")}
        res = watchtower_request("/api/v1/rule-versions/history", method="GET", params=params)
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rule-versions/content", methods=["GET"])
def api_rv_content():
    try:
        from watchtower_client import watchtower_request
        params = {"file": request.args.get("file", ""), "version": request.args.get("version", "")}
        res = watchtower_request("/api/v1/rule-versions/content", method="GET", params=params)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rule-versions", methods=["POST"])
def api_rv_save():
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        body.setdefault("author", session.get("username", "analyst"))
        res = watchtower_request("/api/v1/rule-versions", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/rule-versions/diff", methods=["GET"])
def api_rv_diff():
    try:
        from watchtower_client import watchtower_request
        params = {k: request.args.get(k, "") for k in ("file", "v1", "v2")}
        res = watchtower_request("/api/v1/rule-versions/diff", method="GET", params=params)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rule-versions/validate", methods=["POST"])
def api_rv_validate():
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request("/api/v1/rule-versions/validate", method="POST", json_body=body)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)


# ── Ticketing Integration ─────────────────────────────────────────────────────

@app.route("/api/tickets/config", methods=["GET"])
def api_tickets_config():
    """Return ticketing provider config (no secrets)."""
    try:
        from ticketing import get_config_status
        return jsonify(get_config_status())
    except Exception as e:
        return _api_error(e)

@app.route("/api/tickets", methods=["GET"])
def api_tickets_list():
    """List created tickets, optionally filtered by alert_id or case_id."""
    try:
        from ticketing import list_tickets
        alert_id = request.args.get("alert_id", type=int)
        case_id  = request.args.get("case_id",  type=int)
        limit    = request.args.get("limit",     type=int, default=100)
        tickets  = list_tickets(alert_id=alert_id, case_id=case_id, limit=limit)
        return jsonify({"data": tickets, "total": len(tickets)})
    except Exception as e:
        return _api_error(e)

@app.route("/api/tickets", methods=["POST"])
def api_tickets_create():
    """Create a ticket in the configured provider (Jira or ServiceNow)."""
    try:
        from ticketing import create_ticket
        body      = request.get_json(force=True) or {}
        summary   = body.get("summary", "Security Alert from Sentinel SIEM")
        desc      = body.get("description", "")
        priority  = body.get("priority", "medium")
        alert_id  = body.get("alert_id")
        case_id   = body.get("case_id")
        user      = session.get("username", "anonymous")

        ticket = create_ticket(
            summary=summary,
            description=desc,
            priority=priority,
            alert_id=alert_id,
            case_id=case_id,
            created_by=user,
        )
        return jsonify({"data": ticket}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return _api_error(e)

@app.route("/api/tickets/test", methods=["POST"])
def api_tickets_test():
    """Create a test ticket to verify configuration."""
    try:
        from ticketing import create_ticket
        ticket = create_ticket(
            summary="[TEST] Sentinel SIEM — Ticketing Integration Test",
            description="This is an automated test ticket from Sentinel SIEM. You can safely close this ticket.",
            priority="low",
            created_by=session.get("username", "system"),
        )
        return jsonify({"data": ticket, "message": f"Test ticket created: {ticket['ticket_id']}"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return _api_error(e)


# ── SOAR Playbooks ────────────────────────────────────────────────────────────

@app.route("/api/playbooks", methods=["GET"])
def api_playbooks_list():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/playbooks", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/playbooks", methods=["POST"])
def api_playbooks_create():
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request("/api/v1/playbooks", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)

@app.route("/api/playbooks/<int:pb_id>", methods=["GET"])
def api_playbooks_get(pb_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/playbooks/{pb_id}", method="GET")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/playbooks/<int:pb_id>", methods=["PUT"])
def api_playbooks_update(pb_id):
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request(f"/api/v1/playbooks/{pb_id}", method="PUT", json_body=body)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/playbooks/<int:pb_id>", methods=["DELETE"])
def api_playbooks_delete(pb_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/playbooks/{pb_id}", method="DELETE")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/playbooks/<int:pb_id>/executions", methods=["GET"])
def api_playbooks_executions(pb_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/playbooks/{pb_id}/executions", method="GET")
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)

@app.route("/api/playbook-executions", methods=["GET"])
def api_all_executions():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/playbook-executions", method="GET")
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)


# ── Scheduled Reports ─────────────────────────────────────────────────────────

try:
    from scheduler import init_scheduler, list_schedules, create_schedule, delete_schedule, run_now
    init_scheduler()
except Exception as _sched_err:
    _logger.warning("Scheduler init failed: %s", _sched_err)
    def list_schedules(): return []
    def create_schedule(*a, **kw): return {}
    def delete_schedule(i): return False
    def run_now(i): pass


@app.route("/api/reports/schedules", methods=["GET"])
def api_schedules_list():
    return jsonify({"data": list_schedules()})


@app.route("/api/reports/schedules", methods=["POST"])
def api_schedules_create():
    body = request.get_json(force=True) or {}
    try:
        sched = create_schedule(
            name        = body.get("name", "Scheduled Report"),
            report_type = body.get("report_type", "overview"),
            frequency   = body.get("frequency", "daily"),
            recipients  = body.get("recipients", []),
            hour        = int(body.get("hour", 8)),
            minute      = int(body.get("minute", 0)),
            day_of_week = body.get("day_of_week", "mon"),
        )
        return jsonify({"data": sched}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/reports/schedules/<schedule_id>", methods=["DELETE"])
def api_schedules_delete(schedule_id):
    if delete_schedule(schedule_id):
        return jsonify({"message": "deleted"})
    return jsonify({"error": "not found"}), 404


@app.route("/api/reports/schedules/<schedule_id>/run", methods=["POST"])
def api_schedules_run_now(schedule_id):
    run_now(schedule_id)
    return jsonify({"message": "report triggered"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5050))
    # Never enable debug in production — exposes an interactive debugger shell (RCE).
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)
