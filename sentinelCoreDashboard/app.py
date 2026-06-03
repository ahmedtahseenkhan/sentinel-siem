"""
Sentinel Core SIEM Dashboard – WatchTower (Manager) + WatchVault (Indexer).
Professional SIEM dashboard: Overview, Stack Status, Agent Health, Threat Hunting, Alerts, Vulnerabilities, Compliance.
"""
import os
import re
import json
import hmac
import logging as _logging
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, g
import audit_log as _audit_log
import log_filters as _log_filters
import silent_sources as _silent
import users_store as _users
import correlations as _corr

_audit_log.init_db()
_log_filters.init_db()
_silent.init_db()
_users.init_db()
_corr.init_db()

_logger = _logging.getLogger(__name__)


def _api_error(exc: Exception, status: int = 500) -> tuple:
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
    ROLE_ADMIN,
    ROLE_ADMINISTRATOR,
    ROLE_SECURITY_ANALYST,
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
    get_discover_field_stats,
    get_discover_correlate,
    COMPLIANCE_FRAMEWORKS,
    get_compliance_stats,
    get_compliance_by_control,
    get_compliance_by_agent,
    get_compliance_evolution,
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
    get_inventory_services_summary,
    get_inventory_services_list,
    get_inventory_hotfixes_summary,
    get_inventory_hotfixes_list,
    get_inventory_ports_summary,
    get_inventory_ports_list,
    get_threatintel_summary,
    get_threatintel_hits,
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

# Idle session timeout — re-auth required after this period of inactivity.
# Default 12h; tune per compliance regime (PCI: 15m, HIPAA: 30m typical).
from datetime import timedelta as _timedelta
_SESSION_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "12"))
app.config["PERMANENT_SESSION_LIFETIME"] = _timedelta(hours=_SESSION_HOURS)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True  # sliding window

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
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "script-src-elem 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
        "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
        "img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self' https://ip-api.com https://unpkg.com;"
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
    "/api/admin/audit-log",
    "/api/admin/audit-log/stats",
    "/api/admin/backup/download",
    "/api/admin/backup/list",
    "/api/admin/system-logs",
    "/api/admin/system-logs/services",
    "/api/admin/retention",
    "/api/admin/retention/purge",
}

# Path prefixes that require write privileges (admin or higher).
# Viewer/Security Analyst roles can read but not modify these resources.
WRITE_PROTECTED_PREFIXES = (
    "/api/rules/",          # Rule creation/edit/delete
    "/api/decoders/",       # Decoder management
    "/api/playbooks/",      # Playbook configuration
    "/api/cases/",          # Case management (analysts can also modify — see role check below)
    "/api/identity/sync",   # Manual identity sync
    "/api/cdb-lists/",      # CDB list management
    "/api/reports/schedules", # Report schedule management
    "/api/admin/filters",   # Whitelist / log-drop rules
    "/api/silent-sources/", # Silent-source thresholds
    "/api/users",           # Dashboard user management
    "/api/correlations/",   # Stateful correlation incidents
)

# HTTP methods that are considered "write" operations
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Roles allowed to perform write operations on protected paths
ROLES_CAN_WRITE = {ROLE_SUPER_ADMIN, ROLE_ADMINISTRATOR, ROLE_ADMIN}

# Cases are an exception — security analysts can also write
ROLES_CAN_MANAGE_CASES = ROLES_CAN_WRITE | {ROLE_SECURITY_ANALYST}


# ── Rate limiting (token bucket per-IP) ──────────────────────────────────────
# Prevents API abuse: each IP gets a refilling bucket of tokens.
# Refill rate = RATE_LIMIT_RPS tokens/sec, burst capacity = RATE_LIMIT_BURST.
import threading as _threading
import time as _time

_RATE_LIMIT_RPS = int(os.getenv("RATE_LIMIT_RPS", "20"))   # sustained req/sec per IP
_RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))
_rate_buckets = {}   # ip -> [tokens, last_refill_ts]
_rate_lock = _threading.Lock()


def _rate_limit_check(client_ip):
    """Returns True if the request is allowed; False if rate-limited."""
    now = _time.time()
    with _rate_lock:
        bucket = _rate_buckets.get(client_ip)
        if bucket is None:
            _rate_buckets[client_ip] = [float(_RATE_LIMIT_BURST), now]
            return True
        tokens, last = bucket
        # Refill based on elapsed time
        tokens = min(float(_RATE_LIMIT_BURST), tokens + (now - last) * _RATE_LIMIT_RPS)
        if tokens < 1:
            bucket[0] = tokens
            bucket[1] = now
            return False
        bucket[0] = tokens - 1
        bucket[1] = now
        return True


def _check_login():
    """Return (username, role) if logged in, else None."""
    user = session.get("user")
    role = session.get("role")
    if user and role:
        return user, role
    return None


def _validate_dashboard_user(username, password):
    """Return role if credentials are valid, else None.

    Resolution order:
      1. SQLite users created via the admin UI (bcrypt only)
      2. DASHBOARD_USERS env-var entries (bcrypt or plaintext)
      3. The DASHBOARD_*_PASSWORD defaults

    SQLite takes priority so an admin can override an env-var account without
    a redeploy. The env-var path remains as a break-glass fallback.
    """
    if not username:
        return None
    db_role = _users.authenticate(username, password)
    if db_role is not None:
        return db_role
    users = get_dashboard_users()
    if username not in users:
        return None
    stored_credential, role = users[username]
    if not _verify_password(password, stored_credential):
        return None
    return role


import hashlib as _hashlib
import os as _os

def _static_version():
    """Return a short hash based on the modification time of key static files."""
    try:
        base = _os.path.dirname(__file__)
        paths = [
            _os.path.join(base, "static", "js", "app.js"),
            _os.path.join(base, "static", "css", "style.css"),
            _os.path.join(base, "templates", "index.html"),
        ]
        sig = "".join(str(int(_os.path.getmtime(p))) for p in paths if _os.path.exists(p))
        return _hashlib.md5(sig.encode()).hexdigest()[:8]
    except Exception:
        return "1"

_STATIC_VER = _static_version()


@app.route("/")
def index():
    if _check_login() is None:
        return redirect(url_for("login"))
    return render_template("index.html", v=_STATIC_VER)


# ── Agent deployment page ───────────────────────────────────────────────────
# Renders an install page showing copy-paste commands for Windows/Linux/macOS,
# pre-filled with the current server IP and enrollment token. Also serves the
# agent binaries so endpoints can `curl ... | sudo bash` directly.

AGENT_BIN_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "WatchNode",
)

DEFAULT_ENROLL_TOKEN = "sentinel-enroll-secret-2024"


def _detect_server_ip() -> str:
    """Return the best IP for agents to connect to.

    Priority:
      1. SENTINEL_SERVER_IP env var (operator-set, most reliable)
      2. X-Forwarded-For / X-Real-IP header (behind a reverse proxy)
      3. Request host if it's a real IP (not localhost / 127.x)
      4. Machine's own outbound network IP (what other devices see)
    """
    # 1. Explicit override
    override = os.getenv("SENTINEL_SERVER_IP", "").strip()
    if override:
        return override
    # 2. Proxy headers
    for hdr in ("X-Forwarded-For", "X-Real-IP"):
        v = request.headers.get(hdr, "").split(",")[0].strip()
        if v and v not in ("127.0.0.1", "::1", "localhost"):
            return v
    # 3. Request host if already a routable IP
    host = request.host.split(":")[0]
    if host and host not in ("localhost", "127.0.0.1", "0.0.0.0", "::1", ""):
        return host
    # 4. Machine's outbound IP — connect a UDP socket (no data sent) to discover
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return host or "YOUR_SERVER_IP"


@app.route("/deploy")
def deploy_page():
    if _check_login() is None:
        return redirect(url_for("login"))
    server_ip = _detect_server_ip()
    enroll_token = os.getenv("WATCHNODE_ENROLL_TOKEN", DEFAULT_ENROLL_TOKEN)
    return render_template(
        "deploy.html",
        server_ip=server_ip,
        enroll_token=enroll_token,
    )


@app.route("/deploy/agent/<platform>")
def deploy_download(platform):
    if _check_login() is None:
        return redirect(url_for("login"))
    from flask import send_from_directory, abort, make_response
    mapping = {
        "windows": ("SentinelAgent.zip", "SentinelAgent.zip"),
        "linux":   ("cmd/agent/watchnode-linux", "watchnode-linux"),
    }
    if platform not in mapping:
        abort(404)
    rel, download_name = mapping[platform]
    full = os.path.normpath(os.path.join(AGENT_BIN_DIR, rel))
    if not full.startswith(os.path.normpath(AGENT_BIN_DIR)):
        abort(403)
    if not os.path.isfile(full):
        abort(404, description=f"Agent binary not built: {rel}")
    directory = os.path.dirname(full)
    filename = os.path.basename(full)
    response = make_response(send_from_directory(
        directory, filename, as_attachment=True, download_name=download_name
    ))
    # Cache-busting headers so a re-deploy never serves a stale agent package
    # from the browser cache. Operators have spent hours debugging "I downloaded
    # the new zip but it still has the old install.ps1" — the actual cause was
    # the browser silently reusing its 200 OK from yesterday.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # Add the file's mtime to the filename so each rebuild is a distinct file
    # name on disk too — easier to spot in the user's Downloads folder.
    try:
        import time as _t
        mtime = int(os.path.getmtime(full))
        stamped = download_name.rsplit(".", 1)
        if len(stamped) == 2:
            stamped_name = f"{stamped[0]}-{mtime}.{stamped[1]}"
        else:
            stamped_name = f"{download_name}-{mtime}"
        response.headers["Content-Disposition"] = f'attachment; filename="{stamped_name}"'
    except Exception:
        pass
    return response


@app.route("/deploy/install.sh")
def deploy_install_script():
    """Serve the one-line Linux installer (unauthenticated so curl can fetch it)."""
    script_path = os.path.normpath(os.path.join(
        AGENT_BIN_DIR, "scripts", "install-oneline.sh"
    ))
    if not os.path.isfile(script_path):
        return "Installer script not found on server", 404
    from flask import send_file
    return send_file(script_path, mimetype="text/x-shellscript")


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
            # Mark permanent so PERMANENT_SESSION_LIFETIME (idle timeout) applies.
            session.permanent = True
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
    """Enforce login + RBAC for all /api/* requests.

    Permission rules:
      - All /api/* (except /api/me) require login.
      - SUPER_ADMIN_ONLY_PATHS require super_admin.
      - Write methods (POST/PUT/PATCH/DELETE) on WRITE_PROTECTED_PREFIXES
        require an admin-level role (write).
      - Case management writes additionally permit security_analyst.
      - Viewers (and lower) can only read (GET/HEAD).
    """
    path = request.path
    # /healthz is the standard convention for load-balancer probes — no auth,
    # no rate limit, no DB hit. Returns 200 if the process can respond at all.
    if path == "/healthz" or path == "/readyz":
        return None
    if not path.startswith("/api/"):
        return None
    # Apply rate limiting before anything else (uses client IP)
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not _rate_limit_check(client_ip):
        return jsonify({"error": "Too Many Requests", "retry_after_seconds": 1}), 429
    if path == "/api/me":
        return None
    login = _check_login()
    if login is None:
        return jsonify({"error": "Unauthorized", "login_required": True}), 401
    _, role = login
    if path in SUPER_ADMIN_ONLY_PATHS and role != ROLE_SUPER_ADMIN:
        return jsonify({"error": "Forbidden", "required_role": ROLE_SUPER_ADMIN}), 403

    # CSRF defense-in-depth on write methods. SameSite=Lax already blocks most
    # cross-site cookie sends, but we additionally require that the request's
    # Origin (or Referer, as a fallback for older clients) matches the host
    # this app is serving. Blocks reflected/embedded CSRF even when a browser
    # vendor regresses on SameSite.
    if request.method in WRITE_METHODS:
        origin = request.headers.get("Origin", "")
        referer = request.headers.get("Referer", "")
        expected_host = request.host  # e.g. "siem.example.com:5050"
        def _host_of(url: str) -> str:
            try:
                from urllib.parse import urlparse
                p = urlparse(url)
                return (p.netloc or "").lower()
            except Exception:
                return ""
        candidate = _host_of(origin) or _host_of(referer)
        # Allow when caller is same-origin OR explicitly whitelisted via env.
        allowed_extra = {h.strip().lower() for h in
                         (os.getenv("CSRF_ALLOWED_HOSTS", "") or "").split(",") if h.strip()}
        if candidate and candidate != expected_host.lower() and candidate not in allowed_extra:
            return jsonify({
                "error": "Forbidden",
                "message": "Cross-origin write blocked. Set CSRF_ALLOWED_HOSTS to whitelist trusted origins.",
            }), 403
        # Missing Origin+Referer is only acceptable from same-process tooling
        # (server-side scripts using session cookies, curl with --cookie). The
        # safest stance is to allow when nothing is presented so internal
        # automation isn't broken; browsers always send at least Referer.
        # If you want strict-mode, set CSRF_STRICT=true.
        if not candidate and os.getenv("CSRF_STRICT", "").lower() in ("1", "true", "yes"):
            return jsonify({
                "error": "Forbidden",
                "message": "Origin or Referer header required for write methods (CSRF_STRICT)",
            }), 403

    # Write protection: deny modify-actions to read-only roles on protected paths
    if request.method in WRITE_METHODS:
        is_protected = any(path.startswith(p) for p in WRITE_PROTECTED_PREFIXES)
        if is_protected:
            allowed = ROLES_CAN_MANAGE_CASES if path.startswith("/api/cases/") else ROLES_CAN_WRITE
            if role not in allowed:
                # Still record the rejection so abuse attempts are auditable.
                _audit_log.record(
                    user=login[0], role=role, method=request.method, path=path,
                    status=403, client_ip=client_ip,
                    user_agent=request.headers.get("User-Agent", "")[:256],
                    payload={"denied": True, "required_any_role": sorted(allowed)},
                )
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Role '{role}' may not modify this resource",
                    "required_any_role": sorted(allowed),
                }), 403

    # Stash everything the audit hook needs on flask.g so after_request can
    # write a row regardless of which view handled the call.
    if _audit_log.should_audit(request.method, path, WRITE_PROTECTED_PREFIXES):
        g.audit_user = login[0]
        g.audit_role = role
        g.audit_ip = client_ip
        # Read the JSON body now; once the view consumes it we can't replay it.
        try:
            g.audit_payload = request.get_json(silent=True)
            if g.audit_payload is None and request.form:
                g.audit_payload = {k: v for k, v in request.form.items()}
        except Exception:
            g.audit_payload = None

    return None


@app.after_request
def _audit_record(response):
    """Write one audit-log row per write-action on a protected path."""
    try:
        if getattr(g, "audit_user", None):
            _audit_log.record(
                user=g.audit_user,
                role=g.audit_role,
                method=request.method,
                path=request.path,
                status=response.status_code,
                client_ip=getattr(g, "audit_ip", ""),
                user_agent=request.headers.get("User-Agent", "")[:256],
                payload=getattr(g, "audit_payload", None),
            )
    except Exception:
        pass
    return response


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
    """Get aggregation buckets from indexer response.
    Normalises OpenSearch's doc_count → count so all callers see a consistent field.
    """
    aggs = (res.get("aggregations") or {}).get(key) or {}
    buckets = aggs.get("buckets") or []
    for b in buckets:
        if "count" not in b and "doc_count" in b:
            b["count"] = b["doc_count"]
    return buckets


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


def _agent_label(aid):
    """Human-readable label for an agent id: the PC hostname when known,
    otherwise a short id. Avoids showing raw 32-char hex ids in the UI."""
    if not aid:
        return "—"
    name = _get_agent_id_map().get(aid)
    if name:
        return name
    return (aid[:8] + "…") if len(aid) > 8 else aid


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

        # Humanised last-seen + offline duration
        now = datetime.now(timezone.utc)
        last_seen_label = "Never"
        offline_minutes = None
        if last_keep:
            try:
                t = datetime.fromisoformat(str(last_keep).replace("Z", "+00:00"))
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                delta = (now - t).total_seconds()
                if delta < 60:
                    last_seen_label = "Just now"
                elif delta < 3600:
                    last_seen_label = f"{int(delta // 60)}m ago"
                elif delta < 86400:
                    last_seen_label = f"{int(delta // 3600)}h {int((delta % 3600) // 60)}m ago"
                else:
                    last_seen_label = f"{int(delta // 86400)}d {int((delta % 86400) // 3600)}h ago"
                if status == "disconnected":
                    offline_minutes = int(delta // 60)
            except Exception:
                last_seen_label = "—"

        # Per-agent alert + critical counts from OpenSearch
        alert_count = 0
        critical_count = 0
        try:
            cnt_body = {
                "size": 0,
                "query": {"term": {"agent_id": raw.get("id")}},
                "aggs": {"crit": {"filter": {"range": {"rule_level": {"gte": 10}}}}},
            }
            cnt_res = _os_search(f"{INDEX_PREFIX}-alerts-*", cnt_body)
            alert_count = ((cnt_res.get("hits") or {}).get("total") or {}).get("value", 0) or 0
            critical_count = ((cnt_res.get("aggregations") or {}).get("crit") or {}).get("doc_count", 0) or 0
        except Exception:
            pass

        return jsonify({
            "id": raw.get("id"),
            "name": raw.get("name") or raw.get("id"),
            "ip": raw.get("ip") or "any",
            "status": status,
            "os_label": os_label,
            "os_name": os_name or None,
            "platform": os_info.get("platform") or None,
            "version": version,
            "group": group_label,
            "groups": groups,
            "node_name": node_name,
            "last_keep_alive": last_keep,
            "last_seen_label": last_seen_label,
            "offline_minutes": offline_minutes,
            "date_added": date_added,
            "hostname": hostname or None,
            "labels": raw.get("labels") or {},
            "alert_count": alert_count,
            "critical_count": critical_count,
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
        import concurrent.futures

        def _safe(fn, *args, default=None):
            """Call fn(*args) and return default on any exception — prevents 502 during startup."""
            try:
                return fn(*args) or default
            except Exception:
                return default

        out = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=11) as ex:
            f_alerts     = ex.submit(_safe, get_recent_alerts, 50, default={})
            f_sev        = ex.submit(_safe, get_alerts_by_severity, default={})
            f_agents     = ex.submit(_safe, get_agents_summary, default={})
            f_agents_list= ex.submit(_safe, get_agents_list, 15, 0, default={})
            f_timeline   = ex.submit(_safe, get_alerts_timeline_24h, default={})
            f_sources    = ex.submit(_safe, get_top_source_ips, default={})
            f_users      = ex.submit(_safe, get_alerts_by_user, 10, default={})
            f_agent_risk = ex.submit(_safe, get_alerts_by_agent, 10, default={})
            f_mitre      = ex.submit(_safe, get_mitre_techniques, default={})
            f_sev_24h    = ex.submit(_safe, get_alerts_severity_24h, default={})
            # f_critical removed: get_alerts_high_level_count used a numeric range on
            # rule_level which fails when the field is string-mapped in OpenSearch.
            # critical_incidents is now derived from sev_24h_res (uses terms agg which
            # works on both keyword and numeric mappings) so all screens stay in sync.

        def _get(f, default=None):
            try:
                return f.result(timeout=30) or default
            except Exception:
                return default

        alerts_res      = _get(f_alerts,     {})
        sev_res         = _get(f_sev,        {})
        sev_24h_res     = _get(f_sev_24h,    {})
        agents_res      = _get(f_agents,     {})
        agents_list_res = _get(f_agents_list,{})
        timeline_res    = _get(f_timeline,   {})
        sources_res     = _get(f_sources,    {})
        users_res       = _get(f_users,      {})
        agent_risk_res  = _get(f_agent_risk, {})
        mitre_res       = _get(f_mitre,      {})

        alerts = _normalize_alerts(alerts_res)
        total_alerts = (alerts_res.get("hits") or {}).get("total") or {}
        total_count = total_alerts.get("value", 0)

        # Risk score 0–100 from average rule level (level 1–15 -> score ~7–100)
        levels = [int(a.get("rule_level") or 0) for a in alerts[:100] if a.get("rule_level")]
        avg_level = sum(levels) / len(levels) if levels else 5
        risk_score = min(100, max(0, int(avg_level * 6.5)))
        out["risk_score"] = risk_score
        out["risk_label"] = "LOW" if risk_score < 40 else "MODERATE" if risk_score < 70 else "HIGH"

        # Critical incidents: use sev_24h_res["critical"] (terms agg, works regardless
        # of whether rule_level is keyword or integer in OpenSearch).
        # Threshold 12+ matches the Alerts page KPI label "CRITICAL · 12+" so all
        # three screens (Overview / Alerts / Agent detail) now show the same number.
        sev_24h = sev_24h_res if isinstance(sev_24h_res, dict) else {}
        critical_count = int(sev_24h.get("critical", 0))
        out["critical_incidents"] = critical_count
        out["mttr_min"] = 18 + (critical_count % 30)

        # system_health computed below after conn is available; placeholder for now
        out["ingestion_lag"] = "<1SEC"

        # Threat detection rate: pct of recent alerts that map to a known attack technique
        # (rule_groups contains attack-category labels like 'malware', 'credential_dumping', etc.)
        ATTACK_GROUPS = {
            "malware", "credential_dumping", "lateral_movement", "privilege_escalation",
            "persistence", "exfiltration", "defense_evasion", "initial_access",
            "execution", "discovery", "ransomware", "brute_force", "attack",
        }
        recent_alerts_raw_hits = alerts_res.get("hits", {}).get("hits", [])
        mitre_alert_count = sum(
            1 for h in recent_alerts_raw_hits
            if set(h.get("_source", {}).get("rule_groups") or []) & ATTACK_GROUPS
        )
        out["threat_detection_rate"] = round(mitre_alert_count / max(len(recent_alerts_raw_hits), 1) * 100, 1)

        # Timeline 24h — use OpenSearch if it has data, else fall back to WatchTower direct
        by_hour = _aggregation_buckets(timeline_res, "by_hour")
        timeline_list = [{"key": b.get("key_as_string"), "count": b.get("doc_count", 0)} for b in by_hour]
        os_timeline_total = sum(t["count"] for t in timeline_list)
        timeline_sev_list = []
        if os_timeline_total == 0:
            try:
                from watchtower_client import get_watchtower_alerts, build_alerts_dashboard_from_wt
                wt_alerts = get_watchtower_alerts(500) or []
                if wt_alerts:
                    wt_stats = build_alerts_dashboard_from_wt(wt_alerts, [])
                    timeline_sev_list = wt_stats.get("timeline_24h_by_severity", [])
                    timeline_list = [
                        {"key": t.get("key"), "count": (t.get("critical",0)+t.get("high",0)+t.get("medium",0)+t.get("low",0))}
                        for t in timeline_sev_list
                    ]
            except Exception:
                pass  # WatchTower not ready yet — timeline stays empty
        out["timeline_24h"] = timeline_list
        out["timeline_24h_by_severity"] = timeline_sev_list  # for sparklines with severity split
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

        # At-risk devices — aggregate by agent_id (keyword), then resolve hostname
        agent_buckets = _aggregation_buckets(agent_risk_res, "by_agent")
        # Build id→hostname lookup from the agents list we already fetched
        _agents_raw = (agents_list_res.get("data") or {}).get("affected_items") or []
        _id_to_name = {a.get("id", ""): (a.get("name") or a.get("hostname") or a.get("id", "")) for a in _agents_raw}
        max_agent = max([b.get("doc_count", 0) for b in agent_buckets], default=1)
        out["at_risk_devices"] = [
            {
                "name": _id_to_name.get(b.get("key"), b.get("key") or "—"),
                "id": b.get("key"),
                "count": b.get("doc_count", 0),
                "score": min(100, int(100 * b.get("doc_count", 0) / max_agent)),
            }
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


@app.route("/api/discover/field-stats")
def api_discover_field_stats():
    """Return top field values with counts and percentages for the Discover field stats popover."""
    try:
        field = request.args.get("field", type=str)
        if not field:
            return jsonify({"error": "field required"}), 400
        size = request.args.get("size", 15, type=int)
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        index = request.args.get("index", f"{INDEX_PREFIX}-alerts-*", type=str)
        result = get_discover_field_stats(field=field, size=size, time_from=time_from, time_to=time_to, index_pattern=index)
        return jsonify(result)
    except Exception as e:
        return _api_error(e)


@app.route("/api/discover/correlate", methods=["POST"])
def api_discover_correlate():
    """Find events related to a given alert by shared field values."""
    try:
        body = request.get_json(silent=True) or {}
        fields = body.get("fields", {})
        exclude_id = body.get("exclude_id")
        time_from = body.get("time_from")
        time_to = body.get("time_to")
        index = body.get("index", f"{INDEX_PREFIX}-alerts-*")
        size = body.get("size", 20)
        result = get_discover_correlate(
            fields=fields, exclude_id=exclude_id,
            time_from=time_from, time_to=time_to,
            index_pattern=index, size=size,
        )
        return jsonify(result)
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
        index_pattern = request.args.get("index", type=str) or None
        dsl_query = None
        if request.method == "POST" and request.is_json:
            body = request.get_json(silent=True) or {}
            dsl_query = body.get("dsl")
            if not index_pattern:
                index_pattern = body.get("index") or None
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
            index_pattern=index_pattern,
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
                # Fields are now flat at the top level (event_data.fields.* was removed).
                # Fall back to the legacy nested path for any old documents still in the index.
                _legacy = (src.get("event_data") or {}).get("fields") or {}
                ev_type = src.get("event_category") or src.get("event_type") or \
                          (src.get("event_data") or {}).get("type", "")
                if "network" in ev_type:
                    raddr = src.get("raddr") or _legacy.get("raddr", "")
                    rport = src.get("rport") or _legacy.get("rport", "")
                    laddr = src.get("laddr") or _legacy.get("laddr", "")
                    lport = src.get("lport") or _legacy.get("lport", "")
                    # Ports may be integers after field flattening — cast to str.
                    rport = str(rport) if rport else ""
                    lport = str(lport) if lport else ""
                    src["net_remote"] = (raddr + ":" + rport).strip(":") if raddr else ""
                    src["net_local"]  = (laddr + ":" + lport).strip(":") if laddr else ""
                    src["net_status"] = src.get("status") or _legacy.get("status", "")
                elif "process" in ev_type:
                    src["proc_name"]    = src.get("process_name") or _legacy.get("name", "")
                    src["proc_pid"]     = src.get("pid") or _legacy.get("pid", "")
                    src["proc_cmdline"] = src.get("cmdline") or _legacy.get("cmdline", "")
                alerts[i]["source"] = src
                if hit.get("_index"):
                    src["_index"] = hit["_index"]
                if hit.get("_id"):
                    src["id"] = hit["_id"]
        os_total = data.get("total", 0)
        # If OpenSearch is behind, supplement with WatchTower direct alerts
        if os_total == 0 and dsl_query is None and (index_pattern is None or "alerts" in (index_pattern or "")):
            from watchtower_client import get_watchtower_alerts, get_watchtower_agents
            wt_raw = get_watchtower_alerts(size, offset)
            wt_agents = get_watchtower_agents()
            amap = {a["id"]: a.get("hostname") or a.get("name") or a["id"] for a in wt_agents if a.get("id")}
            wt_total_res = get_watchtower_alerts(1000)
            alerts = []
            for a in wt_raw:
                aid = a.get("agent_id", "")
                aname = amap.get(aid, "")
                lvl = int(a.get("level", 0))
                src = {
                    "timestamp": a.get("timestamp"), "rule_id": a.get("rule_id"),
                    "rule_level": lvl, "rule_description": a.get("description") or a.get("title"),
                    "agent_id": aid, "agent_name": aname,
                    "event_type": a.get("event_type", ""),
                }
                alerts.append({
                    "timestamp": a.get("timestamp"), "rule_id": a.get("rule_id"),
                    "rule_level": lvl, "rule_description": src["rule_description"],
                    "agent_id": aid, "agent_name": aname,
                    "source": src,
                })
            return jsonify({"alerts": alerts, "total": len(wt_total_res), "histogram": []})
        return jsonify({"alerts": alerts, "total": os_total, "histogram": data.get("histogram", [])})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/dashboard")
def api_alerts_dashboard():
    """Alerts dashboard: KPIs, timeline by severity, top categories, top agents, incidents."""
    try:
        import concurrent.futures
        from datetime import datetime, timezone, timedelta
        from watchtower_client import get_watchtower_alerts, get_watchtower_agents, build_alerts_dashboard_from_wt
        now = datetime.now(timezone.utc)
        start_24 = int((now - timedelta(hours=24)).timestamp() * 1000)
        end_24 = int(now.timestamp() * 1000)

        def _safe(fn, *args, default=None):
            try:
                return fn(*args) or default
            except Exception:
                return default

        def _get(f, default=None):
            try:
                return f.result(timeout=20) or default
            except Exception:
                return default

        # Parallel: OpenSearch stats + WatchTower direct alerts
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            f_os_total  = ex.submit(_safe, get_alerts_list, 0, 0, start_24, end_24, None, None, None, default={})
            f_wt_alerts = ex.submit(_safe, get_watchtower_alerts, 500, default=[])
            f_wt_agents = ex.submit(_safe, get_watchtower_agents, 200, default=[])

        os_total  = (_get(f_os_total,  {}) or {}).get("total", 0)
        wt_alerts = _get(f_wt_alerts, []) or []
        wt_agents = _get(f_wt_agents, []) or []

        # Use WatchTower data when it has more alerts than OpenSearch (streaming lag)
        if len(wt_alerts) > os_total:
            out = build_alerts_dashboard_from_wt(wt_alerts, wt_agents)
        else:
            # OpenSearch is up to date — use it for richer aggregations
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                f_sev        = ex.submit(_safe, get_alerts_severity_24h, default={})
                f_timeline   = ex.submit(_safe, get_alerts_severity_over_time, 1, "1h", None, start_24, end_24, default={})
                f_categories = ex.submit(_safe, get_alerts_by_rule_groups, 10, start_24, end_24, default=[])
                f_agents     = ex.submit(_safe, get_alerts_by_agent, 10, None, start_24, end_24, None, None, None, None, default={})
                f_incidents  = ex.submit(_safe, get_alerts_list, 10, 0, start_24, end_24, 8, None, None, default={})
            sev          = _get(f_sev,        {})
            timeline_res = _get(f_timeline,   {})
            by_date = (timeline_res.get("aggregations") or {}).get("by_date", {}).get("buckets", [])
            tl = []
            for b in by_date:
                key = b.get("key_as_string") or b.get("key")
                crit = high = med = low = 0
                for lev in (b.get("by_level") or {}).get("buckets", []):
                    lv = int(lev.get("key", 0))
                    c = lev.get("doc_count", 0)
                    if lv >= 12: crit += c
                    elif lv >= 8: high += c
                    elif lv >= 4: med += c
                    else: low += c
                tl.append({"key": key, "critical": crit, "high": high, "medium": med, "low": low})
            cat          = _get(f_categories, []) or []
            ag           = _get(f_agents,     {})
            agent_buckets = _aggregation_buckets(ag, "by_agent")
            inc_data     = _get(f_incidents,  {})
            out = {
                "total_24h": os_total,
                "severity_24h": sev,
                "timeline_24h_by_severity": tl,
                "top_categories": [{"key": c.get("key"), "count": c.get("doc_count", 0)} for c in cat],
                "top_agents": [{"key": b.get("key"), "count": b.get("doc_count", 0)} for b in agent_buckets],
                "incidents": _normalize_alerts({"hits": {"hits": (inc_data or {}).get("hits", [])}}),
            }
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


@app.route("/api/compliance/<framework>/dashboard")
def api_compliance_dashboard(framework):
    """Generic compliance dashboard endpoint for the 6 supported frameworks
    (pci_dss, hipaa, gdpr, nist_800_53, soc2, cis_v8). Returns stats, top
    controls, top agents, and an hourly evolution series — all driven by
    rule.groups tagging on the native compliance rules in batches 7100-7600.

    Replaces the gap where only HIPAA had a wired endpoint and that HIPAA
    endpoint queried a Wazuh-specific rule.hipaa field that our native
    rules don't emit."""
    try:
        if framework not in COMPLIANCE_FRAMEWORKS:
            return jsonify({"error": f"unknown framework {framework}"}), 400
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        return jsonify({
            "framework": framework,
            "stats":     get_compliance_stats(framework, time_from, time_to),
            "controls":  get_compliance_by_control(framework, size=20, time_from=time_from, time_to=time_to),
            "agents":    get_compliance_by_agent(framework, size=10, time_from=time_from, time_to=time_to),
            "evolution": get_compliance_evolution(framework, time_from=time_from, time_to=time_to),
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
        from watchtower_client import get_watchtower_alerts

        def _level_to_band(lvl):
            lvl = int(lvl or 0)
            if lvl >= 12: return "Critical"
            if lvl >= 8:  return "High"
            if lvl >= 4:  return "Medium"
            return "Low"

        res = get_alerts_by_severity()
        raw = _aggregation_buckets(res, "by_level")

        # Aggregate raw numeric levels into severity bands, normalize doc_count → count
        band_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        if raw:
            for b in raw:
                band = _level_to_band(b.get("key", 0))
                band_counts[band] += int(b.get("doc_count") or b.get("count") or 0)
        else:
            # Fallback: query WatchTower directly
            for a in (get_watchtower_alerts(500) or []):
                band = _level_to_band(a.get("level", 0))
                band_counts[band] += 1

        # Return in severity order, skip empty bands
        order = ["Critical", "High", "Medium", "Low"]
        buckets = [{"key": k, "count": band_counts[k]} for k in order if band_counts[k] > 0]
        return jsonify({"buckets": buckets})
    except Exception as e:
        return _api_error(e)


@app.route("/api/alerts/by-rule")
def api_alerts_by_rule():
    try:
        from watchtower_client import get_watchtower_alerts
        size = request.args.get("size", 10, type=int)
        res = get_alerts_by_rule(size=size)
        buckets = _aggregation_buckets(res, "by_rule")
        if not buckets:
            wt = get_watchtower_alerts(500)
            counts = {}
            for a in wt:
                title = a.get("title") or a.get("description") or f"Rule {a.get('rule_id','?')}"
                counts[title] = counts.get(title, 0) + 1
            buckets = sorted([{"key": k, "count": v} for k, v in counts.items()], key=lambda x: -x["count"])[:size]
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
        from watchtower_client import get_watchtower_alerts, get_watchtower_agents
        size = request.args.get("size", 15, type=int)
        min_level, time_from, time_to, agent_name, agent_id, rule_group, exclude_rule_ids = _dashboard_filter_args()
        rule_groups = [rule_group] if rule_group else None
        res = get_alerts_by_agent(
            size=size, min_level=min_level, time_from=time_from, time_to=time_to,
            agent_name=agent_name, agent_id=agent_id, rule_groups=rule_groups, exclude_rule_ids=exclude_rule_ids,
        )
        buckets = _aggregation_buckets(res, "by_agent")
        for b in buckets:
            aid = (b.get("agent_id") or {}).get("buckets") or []
            resolved = aid[0].get("key") if aid else b.get("key")
            b["agent_id"] = resolved
            # Show the PC hostname instead of the raw hex agent id. Keep the id
            # in agent_id for click-through/filtering; surface the label as key.
            b["agent_name"] = _agent_label(resolved)
            b["key"] = b["agent_name"]
        if not buckets:
            wt = get_watchtower_alerts(500)
            agents = get_watchtower_agents()
            amap = {a["id"]: a.get("hostname") or a.get("name") or a["id"] for a in agents if a.get("id")}
            counts = {}
            for a in wt:
                aid = a.get("agent_id", "")
                name = amap.get(aid, aid[:8] + "…" if len(aid) > 8 else aid)
                counts[name] = counts.get(name, 0) + 1
            buckets = sorted([{"key": k, "count": v} for k, v in counts.items()], key=lambda x: -x["count"])[:size]
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
# Services Inventory
# ---------------------------------------------------------------------------

@app.route("/api/inventory/services/summary")
def api_inventory_services_summary():
    try:
        cluster_name = request.args.get("cluster_name", type=str) or None
        return jsonify(get_inventory_services_summary(cluster_name=cluster_name))
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/services/list")
def api_inventory_services_list():
    try:
        size         = request.args.get("size", 15, type=int)
        offset       = request.args.get("offset", 0, type=int)
        service_name = request.args.get("service_name", type=str) or None
        state        = request.args.get("state", type=str) or None
        agent_name   = request.args.get("agent_name", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        return jsonify(get_inventory_services_list(size=size, offset=offset, service_name=service_name,
                                                    state=state, agent_name=agent_name, cluster_name=cluster_name))
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Hotfixes / Patch Status
# ---------------------------------------------------------------------------

@app.route("/api/inventory/hotfixes/summary")
def api_inventory_hotfixes_summary():
    try:
        cluster_name = request.args.get("cluster_name", type=str) or None
        return jsonify(get_inventory_hotfixes_summary(cluster_name=cluster_name))
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/hotfixes/list")
def api_inventory_hotfixes_list():
    try:
        size         = request.args.get("size", 15, type=int)
        offset       = request.args.get("offset", 0, type=int)
        hotfix_id    = request.args.get("hotfix_id", type=str) or None
        agent_name   = request.args.get("agent_name", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        return jsonify(get_inventory_hotfixes_list(size=size, offset=offset, hotfix_id=hotfix_id,
                                                    agent_name=agent_name, cluster_name=cluster_name))
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Ports / Network Services Inventory
# ---------------------------------------------------------------------------

@app.route("/api/inventory/ports/summary")
def api_inventory_ports_summary():
    try:
        cluster_name = request.args.get("cluster_name", type=str) or None
        return jsonify(get_inventory_ports_summary(cluster_name=cluster_name))
    except Exception as e:
        return _api_error(e)


@app.route("/api/inventory/ports/list")
def api_inventory_ports_list():
    try:
        size         = request.args.get("size", 15, type=int)
        offset       = request.args.get("offset", 0, type=int)
        protocol     = request.args.get("protocol", type=str) or None
        state        = request.args.get("state", type=str) or None
        agent_name   = request.args.get("agent_name", type=str) or None
        cluster_name = request.args.get("cluster_name", type=str) or None
        return jsonify(get_inventory_ports_list(size=size, offset=offset, protocol=protocol,
                                                 state=state, agent_name=agent_name, cluster_name=cluster_name))
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Threat Intelligence / IOC
# ---------------------------------------------------------------------------

@app.route("/api/threatintel/summary")
def api_threatintel_summary():
    try:
        return jsonify(get_threatintel_summary())
    except Exception as e:
        return _api_error(e)


@app.route("/api/threatintel/hits")
def api_threatintel_hits():
    try:
        size       = request.args.get("size", 20, type=int)
        offset     = request.args.get("offset", 0, type=int)
        ioc_type   = request.args.get("ioc_type", type=str) or None
        agent_name = request.args.get("agent_name", type=str) or None
        return jsonify(get_threatintel_hits(size=size, offset=offset, ioc_type=ioc_type, agent_name=agent_name))
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# MITRE ATT&CK matrix endpoint
# ---------------------------------------------------------------------------

@app.route("/api/mitre/matrix")
def api_mitre_matrix():
    """MITRE ATT&CK matrix: tactics and techniques from alerts joined with rule MITRE mappings."""
    try:
        from watchtower_client import watchtower_request, get_watchtower_alerts

        # Build rule_id → mitre map from WatchTower rules API
        rules_res = watchtower_request("/api/v1/rules", method="GET", params={"limit": 2000}) or {}
        rule_mitre_map = {}
        for rule in (rules_res.get("data") or []):
            rid = rule.get("id")
            mitre = rule.get("mitre") or []
            if rid and mitre:
                rule_mitre_map[rid] = mitre

        # Try OpenSearch first for technique counts
        techniques_res = get_mitre_techniques(size=50)
        tech_buckets = _aggregation_buckets(techniques_res, "by_technique")
        os_total = sum(b.get("doc_count", 0) for b in tech_buckets)

        if os_total > 0:
            # OpenSearch has MITRE-tagged alerts
            techniques_out = [
                {"technique_id": b.get("key"), "key": b.get("key"),
                 "technique_name": b.get("key"), "count": b.get("doc_count", 0)}
                for b in tech_buckets
            ]
        else:
            # Build from WatchTower alerts + rule MITRE map
            wt_alerts = get_watchtower_alerts(1000)
            tech_counts = {}  # technique_id → {name, tactic, count}
            for alert in wt_alerts:
                rid = alert.get("rule_id")
                mitre_list = rule_mitre_map.get(rid, [])
                for m in mitre_list:
                    tid = m.get("technique_id", "")
                    if not tid:
                        continue
                    if tid not in tech_counts:
                        tech_counts[tid] = {
                            "technique_id": tid,
                            "technique_name": m.get("technique_name", tid),
                            "tactic": m.get("tactic_id", ""),
                            "tactic_name": m.get("tactic_name", ""),
                            "count": 0,
                        }
                    tech_counts[tid]["count"] += 1
            techniques_out = sorted(tech_counts.values(), key=lambda x: -x["count"])

        # Build tactics from techniques
        tactic_counts = {}
        for t in techniques_out:
            tac = t.get("tactic") or t.get("tactic_id") or ""
            tac_name = t.get("tactic_name", tac)
            if tac:
                tactic_counts[tac] = tactic_counts.get(tac, 0) + t.get("count", 0)
        tactics_out = [{"tactic": k, "tactic_name": v, "count": tactic_counts[k]}
                       for k, v in [(k, k) for k in tactic_counts]]

        return jsonify({"tactics": tactics_out, "techniques": techniques_out,
                        "total_techniques": len(techniques_out)})
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

# Windows Security event IDs treated as authentication/audit-trail events.
# Covers logon (4624), failed logon (4625), logoff (4634/4647), explicit-cred
# logon (4648), special privileges (4672), account lifecycle (4720/4722/4723/
# 4724/4725/4726/4738/4740), RDP session (4778/4779), service install (7045),
# system lifecycle (1074 shutdown, 6005/6006 eventlog start/stop, 6008 dirty
# shutdown, 6013 uptime).
WINDOWS_AUTH_EVENT_IDS = [
    4624, 4625, 4634, 4647, 4648, 4672,
    4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740,
    4768, 4769, 4771, 4776,
    4778, 4779,
    7045,
    1074, 6005, 6006, 6008, 6013,
]

WINDOWS_FAIL_EVENT_IDS = [4625, 4771, 4776, 4740]
WINDOWS_SUCCESS_EVENT_IDS = [4624, 4648, 4768, 4769, 4778]


def _audit_should_clauses():
    """Build OpenSearch `should` clauses that match auth/audit events across
    both raw eventlog docs (Windows) and Wazuh-style alert rule_groups (Linux)."""
    return [
        # Windows: raw eventlog records carry win_event_id (int)
        {"terms": {"win_event_id": WINDOWS_AUTH_EVENT_IDS}},
        # Windows: when win_event_id is mapped as keyword, use term-as-string
        {"terms": {"event_id": [str(i) for i in WINDOWS_AUTH_EVENT_IDS]}},
        # Linux/Wazuh: rule_groups markers
        {"match": {"rule_groups": "authentication"}},
        {"match": {"rule_groups": "sshd"}},
        {"match": {"rule_groups": "pam"}},
        {"match": {"rule_groups": "sudo"}},
        {"match_phrase": {"rule_description": "ssh"}},
        {"match_phrase": {"rule_description": "pam"}},
        {"match_phrase": {"rule_description": "sudo"}},
        # journald/syslog-ish hints emitted by linux logs collector
        {"match_phrase": {"unit": "ssh"}},
        {"match_phrase": {"unit": "sshd"}},
        {"match_phrase": {"unit": "systemd-logind"}},
    ]


@app.route("/api/audit/summary")
def api_audit_summary():
    """Auth/audit summary: total auth events, failed/successful logins, sudo events in last 24h.

    Queries the raw events index (watchvault-events-*) so Windows logon/logoff/
    shutdown events from the eventlog collector show up — not just Sigma alerts.
    """
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
                    "should": _audit_should_clauses(),
                    "minimum_should_match": 1,
                }
            },
            "aggs": {
                "failed": {
                    "filter": {"bool": {"should": [
                        {"terms": {"win_event_id": WINDOWS_FAIL_EVENT_IDS}},
                        {"terms": {"event_id": [str(i) for i in WINDOWS_FAIL_EVENT_IDS]}},
                        {"match": {"rule_description": "failed"}},
                        {"match": {"rule_description": "invalid"}},
                        {"match": {"rule_description": "authentication failure"}},
                    ], "minimum_should_match": 1}}
                },
                "successful": {
                    "filter": {"bool": {"should": [
                        {"terms": {"win_event_id": WINDOWS_SUCCESS_EVENT_IDS}},
                        {"terms": {"event_id": [str(i) for i in WINDOWS_SUCCESS_EVENT_IDS]}},
                        {"match_phrase": {"rule_description": "accepted"}},
                        {"match_phrase": {"rule_description": "session opened"}},
                    ], "minimum_should_match": 1}}
                },
                "sudo_events": {
                    "filter": {"bool": {"should": [
                        {"match": {"rule_groups": "sudo"}},
                        {"match": {"rule_description": "sudo"}},
                        {"term": {"win_event_id": 4672}},
                    ], "minimum_should_match": 1}}
                },
            }
        }

        def _search(idx):
            return _os_search(idx, body) or {}

        # Combine events + alerts so we cover both raw telemetry and Sigma matches.
        results = []
        for idx in (f"{INDEX_PREFIX}-events-*", f"{INDEX_PREFIX}-alerts-*"):
            try:
                results.append(_search(idx))
            except Exception:
                pass

        def _agg(results, name):
            return sum(((r.get("aggregations") or {}).get(name) or {}).get("doc_count", 0) for r in results)

        def _total(results):
            t = 0
            for r in results:
                th = (r.get("hits") or {}).get("total") or {}
                t += th.get("value", 0) if isinstance(th, dict) else (th or 0)
            return t

        total_count = _total(results)
        failed_count = _agg(results, "failed")
        successful = _agg(results, "successful") or max(0, total_count - failed_count)
        sudo_count = _agg(results, "sudo_events")

        return jsonify({
            "total": total_count,
            "failed_logins": failed_count,
            "successful_logins": successful,
            "sudo_events": sudo_count,
        })
    except Exception:
        return jsonify({"total": 0, "failed_logins": 0, "successful_logins": 0, "sudo_events": 0})


@app.route("/api/audit/events")
def api_audit_events():
    """Paginated auth/audit events from raw events index plus alerts.

    Supports size, offset, agent_name, time_from, time_to. Returns Windows
    logon/logoff/shutdown events from the eventlog collector as well as
    Wazuh-style Linux auth alerts so SOC analysts see every authentication
    record, not just rule-matched alerts.
    """
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
            must_clauses.append({"bool": {"should": [
                {"match": {"agent_name": agent_name}},
                {"match": {"agent.name": agent_name}},
                {"match": {"computer": agent_name}},
            ], "minimum_should_match": 1}})

        body = {
            "size": size,
            "from": offset,
            "query": {
                "bool": {
                    "must": must_clauses,
                    "should": _audit_should_clauses(),
                    "minimum_should_match": 1,
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        # Query events + alerts and merge so users see both raw eventlog
        # records and any Sigma alerts triggered from them.
        # Apply operator-defined whitelist/exclusion rules so noisy known-good
        # records (e.g. svc accounts, internal scanners) drop out of the view.
        merged_hits = []
        total_count = 0
        for idx in (f"{INDEX_PREFIX}-events-*", f"{INDEX_PREFIX}-alerts-*"):
            scope = "events" if "events" in idx else "alerts"
            scoped_body = json.loads(json.dumps(body))  # deep copy
            _log_filters.apply_to_body(scoped_body, scope=scope)
            try:
                res = _os_search(idx, scoped_body) or {}
            except Exception:
                continue
            raw = (res.get("hits") or {}).get("hits") or []
            for h in raw:
                src = h.get("_source", {}) or {}
                src.setdefault("_index", h.get("_index"))
                merged_hits.append(src)
            th = (res.get("hits") or {}).get("total") or {}
            total_count += th.get("value", 0) if isinstance(th, dict) else (th or 0)

        # Sort merged hits by timestamp desc, then page.
        def _ts(h):
            v = h.get("timestamp")
            if isinstance(v, (int, float)):
                return v
            if isinstance(v, str):
                try:
                    from datetime import datetime as _dt
                    return _dt.fromisoformat(v.replace("Z", "+00:00")).timestamp() * 1000
                except Exception:
                    return 0
            return 0
        merged_hits.sort(key=_ts, reverse=True)
        merged_hits = merged_hits[:size]

        return jsonify({"hits": merged_hits, "total": total_count})
    except Exception:
        return jsonify({"hits": [], "total": 0})


# ---------------------------------------------------------------------------
# Raw Logs / Events Explorer endpoints
#
# Powers the "Logs" page — a SOC analyst's primary investigation surface.
# Returns every event WatchVault has indexed (not just rule-matched alerts),
# so analysts can search/pivot/hunt across raw telemetry the same way they
# would in Wazuh Discover or Kibana.
# ---------------------------------------------------------------------------

# Mapping of UI source filter values → OpenSearch query clauses.
# Keep this stable: the frontend `logsSource` <select> uses these keys.
_LOGS_SOURCE_CLAUSES = {
    "eventlog":   [{"term": {"type": "log.eventlog"}}, {"term": {"tags.source": "eventlog"}}],
    "syslog":     [{"term": {"type": "log.syslog"}},   {"term": {"tags.source": "syslog"}}],
    "journal":    [{"term": {"type": "log.journal"}},  {"term": {"tags.source": "journal"}}],
    "file":       [{"term": {"type": "log.file"}},     {"term": {"tags.source": "file"}}],
    "process":    [{"prefix": {"type": "process"}},    {"term": {"collector": "process"}}],
    "network":    [{"prefix": {"type": "network"}},    {"term": {"collector": "network"}}],
    "fim":        [{"prefix": {"type": "fim"}},        {"term": {"collector": "fim"}}],
    "registry":   [{"prefix": {"type": "registry"}},   {"term": {"collector": "registry"}}],
    "sca":        [{"term": {"collector": "sca"}},     {"term": {"type": "sca"}}],
    "osquery":    [{"prefix": {"type": "osquery"}},    {"term": {"collector": "osquery"}}],
}


@app.route("/api/logs/search")
def api_logs_search():
    """Search raw events for the Logs explorer page.

    Query params:
      - size:        page size (default 50, max 500)
      - offset:      pagination cursor
      - time_from:   ISO-8601, epoch ms, or relative (e.g. "now-24h")
      - time_to:     same
      - agent_name:  fuzzy-match against agent.name / computer
      - source:      one of _LOGS_SOURCE_CLAUSES keys (eventlog/syslog/...)
      - event_id:    exact Windows event id (numeric)
      - q:           Lucene query_string (free text + field:value supported)
      - index:       override default events index pattern
    """
    try:
        from datetime import datetime, timezone, timedelta
        size = min(request.args.get("size", 50, type=int) or 50, 500)
        offset = request.args.get("offset", 0, type=int) or 0
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        agent_name = request.args.get("agent_name", type=str) or None
        source = request.args.get("source", type=str) or None
        event_id = request.args.get("event_id", type=int)
        q = (request.args.get("q", type=str) or "").strip()
        index = request.args.get("index", type=str) or f"{INDEX_PREFIX}-events-*"

        now = datetime.now(timezone.utc)
        start_ms = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end_ms = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)

        must = [{"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}]
        if agent_name:
            must.append({"bool": {"should": [
                {"match": {"agent_name": agent_name}},
                {"match": {"agent.name": agent_name}},
                {"match_phrase_prefix": {"computer": agent_name}},
            ], "minimum_should_match": 1}})
        if event_id is not None:
            must.append({"bool": {"should": [
                {"term": {"win_event_id": event_id}},
                {"term": {"event_id": str(event_id)}},
            ], "minimum_should_match": 1}})
        if source and source in _LOGS_SOURCE_CLAUSES:
            must.append({"bool": {"should": _LOGS_SOURCE_CLAUSES[source], "minimum_should_match": 1}})
        if q:
            must.append({"query_string": {
                "query": q,
                "default_operator": "AND",
                "lenient": True,
            }})

        body = {
            "size": size,
            "from": offset,
            "query": {"bool": {"must": must}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        _log_filters.apply_to_body(body, scope="events")
        res = _os_search(index, body) or {}
        raw_hits = (res.get("hits") or {}).get("hits") or []
        th = (res.get("hits") or {}).get("total") or {}
        total = th.get("value", 0) if isinstance(th, dict) else (th or 0)

        hits = []
        for h in raw_hits:
            src = h.get("_source", {}) or {}
            src.setdefault("_index", h.get("_index"))
            src.setdefault("_id", h.get("_id"))
            hits.append(src)

        return jsonify({"hits": hits, "total": total})
    except Exception as e:
        return _api_error(e)


@app.route("/api/logs/summary")
def api_logs_summary():
    """Aggregate counts for the Logs page header (last 24h by default)."""
    try:
        from datetime import datetime, timezone, timedelta
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        now = datetime.now(timezone.utc)
        start_ms = _to_epoch_ms(time_from) if time_from else int((now - timedelta(hours=24)).timestamp() * 1000)
        end_ms = _to_epoch_ms(time_to) if time_to else int(now.timestamp() * 1000)

        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
            ]}},
            "aggs": {
                "by_type":   {"terms": {"field": "type",        "size": 20, "missing": "(unknown)"}},
                "by_agent":  {"terms": {"field": "agent_name",  "size": 20, "missing": "(unknown)"}},
                "by_evid":   {"terms": {"field": "win_event_id","size": 20}},
                "timeline":  {"date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "30m",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_ms, "max": end_ms},
                }},
            },
        }
        res = _os_search(f"{INDEX_PREFIX}-events-*", body) or {}
        th = (res.get("hits") or {}).get("total") or {}
        total = th.get("value", 0) if isinstance(th, dict) else (th or 0)
        aggs = res.get("aggregations") or {}

        def _buckets(agg):
            return [{"key": b.get("key"), "count": b.get("doc_count", 0)}
                    for b in (agg.get("buckets") or [])]

        return jsonify({
            "total": total,
            "by_type":  _buckets(aggs.get("by_type")  or {}),
            "by_agent": _buckets(aggs.get("by_agent") or {}),
            "by_event_id": _buckets(aggs.get("by_evid") or {}),
            "timeline": _buckets(aggs.get("timeline") or {}),
        })
    except Exception as e:
        return _api_error(e)


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
        from watchtower_client import watchtower_request, get_watchtower_agents
        results = []
        if agent_id:
            target_ids = [agent_id]
        else:
            agents = get_watchtower_agents()
            target_ids = [a["id"] for a in agents if a.get("status") in ("running","streaming","active")]
        for aid in target_ids:
            payload = {"agent_id": aid, "action": "firewall-drop", "parameters": {"ip": ip}}
            res = watchtower_request("/api/v1/active-response", method="POST", json_body=payload)
            results.append({"agent_id": aid, "response": res})
        return jsonify({"ok": True, "ip": ip, "sent_to": len(results), "results": results})
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


@app.route("/api/active-response/isolate", methods=["POST"])
def api_ar_isolate():
    """Isolate (network-quarantine) a specific agent, keeping the manager channel.

    Pass {"agent_id": "...", "release": true} to lift isolation instead.
    """
    _user, role = _check_login() or (None, None)
    if role not in (ROLE_SUPER_ADMIN, "administrator", "admin"):
        return jsonify({"error": "Insufficient permissions"}), 403
    try:
        body = request.get_json(silent=True) or {}
        agent_id = (body.get("agent_id") or "").strip()
        if not agent_id:
            return jsonify({"error": "agent_id required"}), 400
        action = "unisolate-host" if body.get("release") else "isolate-host"
        from watchtower_client import watchtower_request
        payload = {"agent_id": agent_id, "action": action,
                   "parameters": {"reason": (body.get("reason") or "manual SOC action")}}
        res = watchtower_request("/api/v1/active-response", method="POST", json_body=payload)
        return jsonify({"ok": True, "agent_id": agent_id, "action": action, "response": res})
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
        # Stamp who made the change so the case audit trail is accurate.
        body.setdefault("actor", session.get("username", "anonymous"))
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

@app.route("/api/cases/<int:case_id>/history", methods=["GET"])
def api_cases_history_list(case_id):
    """Case audit trail (status/assignee/priority changes, SLA breaches)."""
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/cases/{case_id}/history", method="GET")
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)


# ── Geo Threat Map ────────────────────────────────────────────────────────────

@app.route("/api/geo/map-data", methods=["GET"])
def api_geo_map_data():
    """
    Returns geo-enriched source IP data for the threat map.
    Queries OpenSearch for top source IPs from recent alerts,
    then enriches with geolocation via ip-api.com (cached).
    """
    try:
        from watchtower_client import _os_search, INDEX_PREFIX
        from geo import bulk_lookup

        hours = int(request.args.get("hours", 168))  # default 7 days
        limit = int(request.args.get("limit", 100))

        since_ms = int((_to_epoch_ms(f"now-{hours}h") if hours < 8760
                        else _to_epoch_ms("now-30d")))

        # Aggregate top source IPs from OpenSearch alerts index.
        body = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {"gte": since_ms}
                }
            },
            "aggs": {
                "by_src_ip": {
                    "terms": {
                        "field": "event_data.src_ip",
                        "size": limit,
                        "min_doc_count": 1
                    },
                    "aggs": {
                        "max_level": {"max": {"field": "rule_level"}},
                        "last_seen":  {"max": {"field": "timestamp"}}
                    }
                }
            }
        }

        res = _os_search(f"{INDEX_PREFIX}-alerts-*", body)
        buckets = ((res.get("aggregations") or {})
                   .get("by_src_ip", {})
                   .get("buckets", []))

        # Collect unique IPs from alert data.
        ip_counts = {}
        for b in buckets:
            ip = b.get("key", "")
            if ip:
                ip_counts[ip] = {
                    "count":     b.get("doc_count", 0),
                    "max_level": int((b.get("max_level") or {}).get("value") or 0),
                    "last_seen": int((b.get("last_seen") or {}).get("value") or 0),
                }

        # Geo-enrich all IPs (respects cache + rate limit).
        geo_data = bulk_lookup(list(ip_counts.keys()), max_ips=50)

        # Merge counts with geo.
        points = []
        for ip, geo in geo_data.items():
            counts = ip_counts.get(ip, {})
            points.append({
                **geo,
                "alert_count": counts.get("count", 1),
                "max_level":   counts.get("max_level", 0),
                "last_seen":   counts.get("last_seen", 0),
            })

        # Sort by alert count descending.
        points.sort(key=lambda x: x["alert_count"], reverse=True)

        # Country summary (for the pie/table).
        by_country = {}
        for p in points:
            cc = p.get("country_code") or "XX"
            cn = p.get("country") or "Unknown"
            if cc not in by_country:
                by_country[cc] = {"country": cn, "country_code": cc, "count": 0}
            by_country[cc]["count"] += p["alert_count"]

        countries = sorted(by_country.values(), key=lambda x: x["count"], reverse=True)

        return jsonify({
            "points":    points,
            "countries": countries[:20],
            "total_ips": len(points),
        })

    except Exception as e:
        return _api_error(e)


@app.route("/api/geo/lookup", methods=["GET"])
def api_geo_lookup():
    """Geo-lookup a single IP address."""
    try:
        from geo import lookup
        ip  = request.args.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "ip param required"}), 400
        result = lookup(ip)
        if not result:
            return jsonify({"error": "private or unknown IP"}), 404
        return jsonify({"data": result})
    except Exception as e:
        return _api_error(e)


def _to_epoch_ms(expr) -> int:
    """Convert a time expression to epoch milliseconds. Accepts:
      - relative:  'now', 'now-24h', 'now-7d', 'now-30m', 'now-2w'
      - epoch:     13-digit milliseconds or 10-digit seconds
      - ISO-8601:  '2026-06-02T13:10:37Z' (the dashboard sends this form)
    Falls back to "now" only when the input is empty/unrecognised.
    """
    import re
    from datetime import datetime, timezone
    now_ms = int(_time.time() * 1000)
    if expr is None:
        return now_ms
    s = str(expr).strip()
    if s == "" or s == "now":
        return now_ms
    # Relative: now-<n><unit>
    m = re.match(r'now-(\d+)([hdwm])$', s)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        multipliers = {'h': 3_600_000, 'd': 86_400_000, 'w': 604_800_000, 'm': 2_592_000_000}
        return now_ms - n * multipliers.get(unit, 3_600_000)
    # Raw epoch: 13-digit ms, 10-digit seconds
    if s.isdigit():
        v = int(s)
        return v if v >= 10**12 else v * 1000
    # ISO-8601 (handle trailing 'Z' for Python < 3.11)
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return now_ms


# ── Risk-Based Alerting (RBA) ─────────────────────────────────────────────────

@app.route("/api/rba/entities", methods=["GET"])
def api_rba_entities():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/rba/entities", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rba/entities/<entity_id>", methods=["GET"])
def api_rba_entity(entity_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/rba/entities/{entity_id}", method="GET")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rba/entities/purge-stale", methods=["POST"])
def api_rba_purge_stale():
    """Remove RBA/UEBA risk state for 'ghost' entities.

    A ghost is an agent ID that the risk engine still tracks but that is no
    longer present in /api/agents — typically an old or re-installed node that
    minted a throwaway ID. Those can never resolve to a hostname, so they show
    as raw hex on the risk boards. We keep live agents (they resolve) and
    readable syslog sources (``syslog:<ip>``), and purge the rest.
    """
    try:
        from watchtower_client import watchtower_request
        # 1) Live agent IDs — these resolve to a hostname, so keep them.
        live = set()
        try:
            agents = watchtower_request("/api/v1/agents", method="GET", params={"limit": 5000}) or {}
            for a in (agents.get("data") or []):
                aid = a.get("id") or a.get("agent_id")
                if aid:
                    live.add(str(aid))
        except Exception:
            live = set()
        # Safety: if the manager returned no agents at all, refuse to purge so a
        # transient hiccup can't wipe the whole board.
        if not live:
            return jsonify({"deleted": 0, "stale": [],
                            "error": "no live agents available — refusing to purge"}), 409
        # 2) Collect every entity currently tracked by RBA + UEBA.
        candidates = set()
        for path in ("/api/v1/rba/entities", "/api/v1/ueba/risk-scores"):
            res = watchtower_request(path, method="GET", params={"limit": 5000}) or {}
            for e in (res.get("data") or []):
                eid = e.get("entity_id") or e.get("id")
                if eid:
                    candidates.add(str(eid))
        # 3) Stale = tracked, not a live agent, not a readable syslog source.
        stale = sorted(
            eid for eid in candidates
            if eid not in live and not eid.startswith("syslog:")
        )
        if not stale:
            return jsonify({"deleted": 0, "stale": []})
        res = watchtower_request("/api/v1/rba/entities/purge", method="POST",
                                 json_body={"entity_ids": stale}) or {}
        return jsonify({"deleted": res.get("deleted", 0), "stale": stale})
    except Exception as e:
        return _api_error(e)


@app.route("/api/rba/entities/<entity_id>/threshold", methods=["PUT"])
def api_rba_threshold(entity_id):
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request(f"/api/v1/rba/entities/{entity_id}/threshold", method="PUT", json_body=body)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rba/notables", methods=["GET"])
def api_rba_notables():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/rba/notables", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rba/weights", methods=["GET"])
def api_rba_weights():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/rba/weights", method="GET")
        return jsonify(res or {"data": []})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rba/weights/<int:rule_id>", methods=["PUT"])
def api_rba_set_weight(rule_id):
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request(f"/api/v1/rba/weights/{rule_id}", method="PUT", json_body=body)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/rba/weights/<int:rule_id>", methods=["DELETE"])
def api_rba_delete_weight(rule_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/rba/weights/{rule_id}", method="DELETE")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)


# ── UEBA ──────────────────────────────────────────────────────────────────────

@app.route("/api/ueba/risk-scores", methods=["GET"])
def api_ueba_risk_scores():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/ueba/risk-scores", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/ueba/anomalies", methods=["GET"])
def api_ueba_anomalies():
    try:
        from watchtower_client import watchtower_request
        params = {k: v for k, v in request.args.items()}
        res = watchtower_request("/api/v1/ueba/anomalies", method="GET", params=params)
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)

@app.route("/api/ueba/entity/<entity_id>", methods=["GET"])
def api_ueba_entity(entity_id):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/ueba/entity/{entity_id}", method="GET")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)

@app.route("/api/ueba/analyze", methods=["POST"])
def api_ueba_analyze():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/ueba/analyze", method="POST")
        return jsonify(res or {})
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
        file = request.args.get("file", "").strip()
        version = request.args.get("version", "").strip()
        if not file or not version:
            return jsonify({"error": "both 'file' and 'version' query params are required"}), 400
        res = watchtower_request("/api/v1/rule-versions/content", method="GET",
                                 params={"file": file, "version": version})
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


# ---------------------------------------------------------------------------
# Dashboard user management (super_admin only).
#
# Lets a super_admin create/edit/disable login accounts without redeploying.
# Sits on top of DASHBOARD_USERS env var (which still works as a break-glass).
# All writes go through the audit log middleware so every credential change
# is recorded with the actor's identity.
# ---------------------------------------------------------------------------

def _require_super_admin():
    login = _check_login()
    if login is None:
        return jsonify({"error": "Unauthorized"}), 401
    _, role = login
    if role != ROLE_SUPER_ADMIN:
        return jsonify({"error": "Forbidden", "required_role": ROLE_SUPER_ADMIN}), 403
    return None


@app.route("/api/users", methods=["GET"])
def api_users_list():
    err = _require_super_admin()
    if err is not None:
        return err
    try:
        return jsonify({
            "users": _users.list_users(),
            "total": _users.count(),
            "current_user": session.get("user"),
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/users", methods=["POST"])
def api_users_create():
    err = _require_super_admin()
    if err is not None:
        return err
    try:
        body = request.get_json(silent=True) or {}
        actor = (session.get("user") or "").strip()
        u = _users.create_user(
            username=body.get("username", "").strip(),
            password=body.get("password", ""),
            role=body.get("role", "viewer"),
            full_name=body.get("full_name", ""),
            email=body.get("email", ""),
            enabled=bool(body.get("enabled", True)),
            created_by=actor,
        )
        return jsonify(u), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return _api_error(e)


@app.route("/api/users/<username>", methods=["GET"])
def api_users_get(username):
    err = _require_super_admin()
    if err is not None:
        return err
    u = _users.get_user(username)
    if u is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(u)


@app.route("/api/users/<username>", methods=["PUT", "PATCH"])
def api_users_update(username):
    err = _require_super_admin()
    if err is not None:
        return err
    try:
        body = request.get_json(silent=True) or {}
        # Guard against the only super_admin disabling themselves and locking
        # everyone out.
        if (body.get("enabled") is False or body.get("role") not in (None, ROLE_SUPER_ADMIN)) \
                and username == session.get("user"):
            # Count remaining super_admins after this change.
            others = [
                u for u in _users.list_users()
                if u["username"] != username and u["enabled"] and u["role"] == ROLE_SUPER_ADMIN
            ]
            if not others:
                return jsonify({
                    "error": "Refusing to demote/disable the last super_admin. "
                             "Promote another user first."
                }), 400
        u = _users.update_user(
            username,
            password=body.get("password"),
            role=body.get("role"),
            full_name=body.get("full_name"),
            email=body.get("email"),
            enabled=body.get("enabled"),
        )
        if u is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify(u)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return _api_error(e)


@app.route("/api/users/<username>", methods=["DELETE"])
def api_users_delete(username):
    err = _require_super_admin()
    if err is not None:
        return err
    if username == session.get("user"):
        return jsonify({"error": "You cannot delete your own account while logged in."}), 400
    try:
        if not _users.delete_user(username):
            return jsonify({"error": "Not found"}), 404
        return jsonify({"deleted": username})
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Silent-source monitoring
#
# A scheduler-driven job runs every minute. It pulls the per-agent last-seen
# timestamps from WatchTower, then queries OpenSearch for the youngest event
# per agent_name in the events index. The maximum of the two becomes the
# canonical "last activity" for that source. If the gap exceeds the threshold,
# we open an incident and (optionally) page out via the notifier.
# ---------------------------------------------------------------------------

def _collect_agent_last_seen() -> dict:
    """Returns {source_name: (last_seen_ms, kind)} merging WatchTower agents
    + OpenSearch event-index activity."""
    out: dict[str, tuple[int, str]] = {}

    # 1) WatchTower agent heartbeats (authoritative for endpoint agents)
    try:
        from watchtower_client import get_agents_list
        agents = (get_agents_list() or {}).get("data", []) or []
        for a in agents:
            name = (a.get("name") or a.get("agent_name") or a.get("id") or "").strip()
            if not name:
                continue
            ls = a.get("last_seen") or a.get("last_keep_alive")
            ts = _to_epoch_ms(ls) if isinstance(ls, str) and ls else 0
            if ts:
                out[name] = (ts, "agent")
    except Exception:
        pass

    # 2) OpenSearch — youngest doc per agent_name in events index, last 24h.
    try:
        now_ms = int(_time.time() * 1000)
        body = {
            "size": 0,
            "query": {"range": {"timestamp": {"gte": now_ms - 24 * 3600 * 1000}}},
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent_name", "size": 500, "missing": "(unknown)"},
                    "aggs": {"last": {"max": {"field": "timestamp"}}},
                }
            },
        }
        res = _os_search(f"{INDEX_PREFIX}-events-*", body) or {}
        for b in ((res.get("aggregations") or {}).get("by_agent") or {}).get("buckets") or []:
            name = (b.get("key") or "").strip()
            ts = int(((b.get("last") or {}).get("value") or 0))
            if not name or name == "(unknown)" or not ts:
                continue
            prev = out.get(name)
            if prev is None or ts > prev[0]:
                # Preserve "agent" kind if the source was known via WatchTower.
                kind = prev[1] if prev else "any"
                out[name] = (ts, kind)
    except Exception:
        pass

    return out


def _silent_source_check_job() -> None:
    """Scheduler entry point. Lightweight — bails out silently on errors."""
    try:
        sources = _collect_agent_last_seen()
        for name, (last_seen_ms, kind) in sources.items():
            inc = _silent.record_observation(name, kind, last_seen_ms)
            if inc and not inc["notified"]:
                _notify_silent_incident(inc)
                _silent.mark_notified(inc["id"])
    except Exception as e:
        try:
            _logger.warning("silent-source check failed: %s", e)
        except Exception:
            pass


def _notify_silent_incident(inc: dict) -> None:
    """Send an alert through the existing notifier so silent-source pages
    appear in the same channels (email/slack) as Sigma alerts."""
    try:
        from notifier import notify_alert
        alert = {
            "rule_id": "silent-source-monitor",
            "rule_description": f"Source '{inc['source']}' has been silent for {inc['gap_minutes']} minutes (threshold {inc['threshold_min']}m)",
            "rule_level": {"low": 5, "medium": 8, "high": 11, "critical": 14}.get(inc["severity"], 8),
            "agent_name": inc["source"],
            "severity": inc["severity"],
            "kind": inc["kind"],
            "first_seen_silent_ms": inc["first_seen_silent_ms"],
            "tags": ["silent_source", "availability"],
        }
        notify_alert(alert)
    except Exception:
        pass


# ── Silent-source endpoints ────────────────────────────────────────────────

@app.route("/api/silent-sources", methods=["GET"])
def api_silent_sources_list():
    """Current incidents — open by default."""
    try:
        status = request.args.get("status", "open", type=str)
        size = min(request.args.get("size", 100, type=int) or 100, 500)
        incidents = _silent.list_incidents(status=status, size=size)
        return jsonify({
            "incidents": incidents,
            "stats": _silent.stats(),
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/silent-sources/run-now", methods=["POST"])
def api_silent_sources_run_now():
    """Force-trigger a check (useful after editing thresholds)."""
    try:
        _silent_source_check_job()
        return jsonify({"ok": True, "stats": _silent.stats()})
    except Exception as e:
        return _api_error(e)


@app.route("/api/silent-sources/thresholds", methods=["GET"])
def api_silent_thresholds_list():
    try:
        return jsonify({"thresholds": _silent.list_thresholds()})
    except Exception as e:
        return _api_error(e)


@app.route("/api/silent-sources/thresholds", methods=["POST"])
def api_silent_thresholds_create():
    try:
        body = request.get_json(silent=True) or {}
        user = (session.get("user") or "").strip()
        t = _silent.create_threshold(
            source_pattern=body.get("source_pattern", ""),
            kind=body.get("kind", "agent"),
            minutes=int(body.get("minutes", 15)),
            severity=body.get("severity", "medium"),
            enabled=bool(body.get("enabled", True)),
            notify=bool(body.get("notify", True)),
            reason=body.get("reason", ""),
            created_by=user,
        )
        return jsonify(t), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return _api_error(e)


@app.route("/api/silent-sources/thresholds/<int:tid>", methods=["PUT", "PATCH"])
def api_silent_thresholds_update(tid):
    try:
        body = request.get_json(silent=True) or {}
        t = _silent.update_threshold(tid, **body)
        if t is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify(t)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return _api_error(e)


@app.route("/api/silent-sources/thresholds/<int:tid>", methods=["DELETE"])
def api_silent_thresholds_delete(tid):
    try:
        if not _silent.delete_threshold(tid):
            return jsonify({"error": "Not found"}), 404
        return jsonify({"deleted": tid})
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Stateful correlations (impossible travel / multi-location logon).
# ---------------------------------------------------------------------------

def _correlations_run_job() -> None:
    try:
        new_inc = _corr.run_all(
            os_search=_os_search,
            index_pattern=f"{INDEX_PREFIX}-events-*",
        )
        for inc in new_inc:
            _notify_correlation_incident(inc)
            _corr.mark_notified(inc["id"])
    except Exception as e:
        try:
            _logger.warning("correlations job failed: %s", e)
        except Exception:
            pass


def _notify_correlation_incident(inc: dict) -> None:
    try:
        from notifier import notify_alert
        ev = inc.get("evidence") or {}
        ips = ev.get("distinct_ips") or []
        hosts = ev.get("distinct_hosts") or []
        sources = ", ".join(ips or hosts)[:200]
        sev_level = {"low": 5, "medium": 8, "high": 11, "critical": 14}.get(inc["severity"], 11)
        alert = {
            "rule_id": "correlation-multi-location-logon",
            "rule_description": (
                f"User '{inc['entity']}' logged in from {len(ips)} IP(s) "
                f"and {len(hosts)} workstation(s) within {ev.get('window_minutes', '?')}m"
            ),
            "rule_level": sev_level,
            "agent_name": inc["entity"],
            "severity": inc["severity"],
            "tags": ["correlation", "impossible_travel", "multi_location_logon"],
            "evidence_sources": sources,
            "logon_count": ev.get("logon_count"),
        }
        notify_alert(alert)
    except Exception:
        pass


@app.route("/api/correlations/incidents", methods=["GET"])
def api_correlation_incidents():
    try:
        status = request.args.get("status", "open", type=str)
        detector = request.args.get("detector", type=str) or None
        size = min(request.args.get("size", 100, type=int) or 100, 500)
        return jsonify({
            "incidents": _corr.list_incidents(status=status, detector=detector, size=size),
            "stats": _corr.stats(),
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/correlations/run-now", methods=["POST"])
def api_correlation_run_now():
    try:
        _correlations_run_job()
        return jsonify({"ok": True, "stats": _corr.stats()})
    except Exception as e:
        return _api_error(e)


@app.route("/api/correlations/incidents/<int:inc_id>/resolve", methods=["POST"])
def api_correlation_resolve(inc_id):
    try:
        if not _corr.resolve_incident(inc_id):
            return jsonify({"error": "Not found or already resolved"}), 404
        return jsonify({"resolved": inc_id})
    except Exception as e:
        return _api_error(e)


# ── Scheduled Reports & Cloud Connectors ──────────────────────────────────────

try:
    from scheduler import init_scheduler, list_schedules, create_schedule, delete_schedule, run_now, _scheduler as _bg_scheduler
    init_scheduler()
    # Wire cloud connectors into the same scheduler after it starts.
    try:
        from cloud_connectors.manager import init_cloud_connectors
        init_cloud_connectors(_bg_scheduler)
    except Exception as _ce:
        _logger.warning("Cloud connectors init failed: %s", _ce)
    # Auto-summarize critical alerts every 5 minutes if AI is configured.
    try:
        from ai_summarizer import is_configured as _ai_configured, batch_summarize_critical as _batch_ai
        if _ai_configured():
            def _auto_ai_job():
                try:
                    alerts = get_recent_alerts(size=50) or []
                    _batch_ai(alerts)
                except Exception as _ae:
                    _logger.debug("Auto AI summarize error: %s", _ae)
            _bg_scheduler.add_job(_auto_ai_job, 'interval', minutes=5, id='auto_ai_summarize', replace_existing=True)
    except Exception as _aie:
        _logger.debug("AI auto-summarize scheduler setup skipped: %s", _aie)
    # Silent-source monitor — runs every minute, checks per-agent last_seen
    # against operator-defined thresholds and opens/resolves incidents.
    try:
        _bg_scheduler.add_job(
            _silent_source_check_job, 'interval', minutes=1,
            id='silent_source_check', replace_existing=True,
        )
        _logger.info("Silent-source monitor scheduled (1-min interval)")
    except Exception as _se:
        _logger.warning("Silent-source scheduler setup failed: %s", _se)
    # Stateful correlations — multi-location logon, etc.
    try:
        _bg_scheduler.add_job(
            _correlations_run_job, 'interval', minutes=2,
            id='correlations_run', replace_existing=True,
        )
        _logger.info("Correlation engine scheduled (2-min interval)")
    except Exception as _ce:
        _logger.warning("Correlation scheduler setup failed: %s", _ce)
except Exception as _sched_err:
    _logger.warning("Scheduler init failed: %s", _sched_err)
    def list_schedules(): return []
    def create_schedule(*a, **kw): return {}
    def delete_schedule(i): return False
    def run_now(i): pass


# ── Extended Compliance (ISO 27001 / NIST / SOC 2) ────────────────────────────

# Framework → (rule groups to query, control structure)
_COMPLIANCE_FRAMEWORKS = {
    "iso27001": {
        "name": "ISO 27001:2022",
        "controls": [
            {"id": "A.5",  "name": "Organizational Controls",   "group": "iso27001_A.5"},
            {"id": "A.6",  "name": "People Controls",           "group": "iso27001_A.6"},
            {"id": "A.8",  "name": "Asset Management",          "group": "iso27001_A.8"},
            {"id": "A.9",  "name": "Access Control",            "group": "iso27001_A.9"},
            {"id": "A.10", "name": "Cryptography",              "group": "iso27001_A.10"},
            {"id": "A.12", "name": "Operations Security",       "group": "iso27001_A.12"},
            {"id": "A.13", "name": "Communications Security",   "group": "iso27001_A.13"},
            {"id": "A.14", "name": "System Development",        "group": "iso27001_A.14"},
            {"id": "A.16", "name": "Incident Management",       "group": "iso27001_A.16"},
            {"id": "A.17", "name": "Business Continuity",       "group": "iso27001_A.17"},
        ]
    },
    "nist": {
        "name": "NIST CSF 2.0",
        "controls": [
            {"id": "GV",   "name": "Govern",                    "group": "nist_GV"},
            {"id": "ID",   "name": "Identify",                  "group": "nist_ID"},
            {"id": "PR",   "name": "Protect",                   "group": "nist_PR"},
            {"id": "DE",   "name": "Detect",                    "group": "nist_DE"},
            {"id": "RS",   "name": "Respond",                   "group": "nist_RS"},
            {"id": "RC",   "name": "Recover",                   "group": "nist_RC"},
        ]
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": [
            {"id": "CC1",  "name": "Control Environment",       "group": "soc2_CC1"},
            {"id": "CC2",  "name": "Communication & Info",      "group": "soc2_CC2"},
            {"id": "CC3",  "name": "Risk Assessment",           "group": "soc2_CC3"},
            {"id": "CC4",  "name": "Monitoring Activities",     "group": "soc2_CC4"},
            {"id": "CC5",  "name": "Control Activities",        "group": "soc2_CC5"},
            {"id": "CC6",  "name": "Access Controls",           "group": "soc2_CC6"},
            {"id": "CC7",  "name": "System Operations",         "group": "soc2_CC7"},
            {"id": "CC8",  "name": "Change Management",         "group": "soc2_CC8"},
            {"id": "CC9",  "name": "Risk Mitigation",           "group": "soc2_CC9"},
            {"id": "A1",   "name": "Availability",              "group": "soc2_A1"},
            {"id": "C1",   "name": "Confidentiality",           "group": "soc2_C1"},
        ]
    },
    "hipaa": {
        "name": "HIPAA",
        "controls": [
            {"id": "164.308", "name": "Admin Safeguards",       "group": "hipaa"},
            {"id": "164.312", "name": "Technical Safeguards",   "group": "hipaa"},
        ]
    },
    "pci": {
        "name": "PCI-DSS v4.0",
        "controls": [
            {"id": "Req1",  "name": "Network Security",         "group": "pci_dss"},
            {"id": "Req2",  "name": "Secure Configurations",    "group": "pci_dss"},
            {"id": "Req6",  "name": "Vulnerability Management", "group": "pci_dss"},
            {"id": "Req10", "name": "Logging & Monitoring",     "group": "pci_dss"},
        ]
    },
}


@app.route("/api/compliance/frameworks", methods=["GET"])
def api_compliance_frameworks():
    """Return list of supported compliance frameworks."""
    return jsonify({
        "data": [
            {"id": k, "name": v["name"], "control_count": len(v["controls"])}
            for k, v in _COMPLIANCE_FRAMEWORKS.items()
        ]
    })


@app.route("/api/compliance/<framework>", methods=["GET"])
def api_compliance_detail(framework):
    """
    Return compliance posture for a framework using a single OpenSearch query
    (filters aggregation — one round trip regardless of control count).
    Falls back to a 0-alert baseline if OpenSearch is unavailable.
    """
    if framework not in _COMPLIANCE_FRAMEWORKS:
        return jsonify({"error": f"Unknown framework: {framework}"}), 404

    fw   = _COMPLIANCE_FRAMEWORKS[framework]
    days = int(request.args.get("days", 30))

    # Build a unique list of groups so we don't duplicate queries for shared groups
    controls     = fw["controls"]
    unique_groups = list({c["group"] for c in controls})

    counts_by_group: dict = {}
    try:
        from watchtower_client import _os_search, INDEX_PREFIX
        since = int(time.time() * 1000) - days * 86_400_000

        filters_clauses = {
            g: {"bool": {"must": [
                {"range": {"timestamp": {"gte": since}}},
                {"term":  {"rule_groups": g}},
            ]}}
            for g in unique_groups
        }
        body = {
            "size": 0,
            "aggs": {"by_group": {"filters": {"filters": filters_clauses}}}
        }
        res  = _os_search(f"{INDEX_PREFIX}-alerts-*", body)
        buckets = ((res.get("aggregations") or {}).get("by_group") or {}).get("buckets") or {}
        counts_by_group = {g: (buckets.get(g) or {}).get("doc_count", 0) for g in unique_groups}
    except Exception:
        counts_by_group = {g: 0 for g in unique_groups}

    results       = []
    total_alerts  = 0
    non_compliant = 0
    for control in controls:
        count = counts_by_group.get(control["group"], 0)
        total_alerts += count
        if count > 0:
            non_compliant += 1
        results.append({
            **control,
            "alert_count": count,
            "status":      "non_compliant" if count > 0 else "compliant",
        })

    total_controls = len(controls)
    compliant      = total_controls - non_compliant
    score          = round(compliant / total_controls * 100) if total_controls else 100

    return jsonify({
        "framework":      fw["name"],
        "score":          score,
        "compliance_pct": score,
        "total_controls": total_controls,
        "compliant":      compliant,
        "non_compliant":  non_compliant,
        "total_alerts":   total_alerts,
        "days":           days,
        "controls":       results,
    })


# ── Cloud Monitoring Routes ───────────────────────────────────────────────────

@app.route("/api/cloud/status", methods=["GET"])
def api_cloud_status():
    try:
        from cloud_connectors.manager import get_all_statuses
        return jsonify({"data": get_all_statuses()})
    except Exception as e:
        return _api_error(e)

@app.route("/api/cloud/sync/<provider>", methods=["POST"])
def api_cloud_sync(provider):
    try:
        from cloud_connectors.manager import trigger_sync
        result = trigger_sync(provider)
        return jsonify(result)
    except Exception as e:
        return _api_error(e)

@app.route("/api/cloud/events", methods=["GET"])
def api_cloud_events():
    try:
        import time as _time
        provider = request.args.get("provider", "")
        limit    = int(request.args.get("limit", 50))
        hours    = int(request.args.get("hours", 24))
        since_ms = int(_time.time() * 1000) - hours * 3600 * 1000
        index_pattern = f"watchvault-cloud-{provider}-*" if provider else "watchvault-cloud-*"
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"range": {"timestamp": {"gte": since_ms}}},
        }
        from watchtower_client import opensearch_request
        res = opensearch_request(
            f"/{index_pattern}/_search?ignore_unavailable=true&allow_no_indices=true",
            method="POST", json_body=body
        )
        hits = (res.get("hits") or {}).get("hits") or []
        events = [h.get("_source", {}) for h in hits]
        return jsonify({"data": events, "total": len(events)})
    except Exception as e:
        return _api_error(e)


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


# ---------------------------------------------------------------------------
# AI Alert Summaries
# ---------------------------------------------------------------------------
@app.route("/api/ai/status", methods=["GET"])
def api_ai_status():
    try:
        from ai_summarizer import is_configured
        return jsonify({"configured": is_configured()})
    except ImportError:
        return jsonify({"configured": False})


@app.route("/api/ai/summarize", methods=["POST"])
def api_ai_summarize():
    data = request.get_json(force=True, silent=True) or {}
    alert = data.get("alert")
    if not alert:
        return jsonify({"error": "alert field required"}), 400
    try:
        from ai_summarizer import summarize_alert, get_cached_summary
        alert_id = str(alert.get("id", ""))
        cached = get_cached_summary(alert_id) if alert_id else None
        if cached:
            cached["cached"] = True
            return jsonify(cached)
        related = data.get("related_alerts", [])
        result = summarize_alert(alert, related_alerts=related)
        return jsonify(result)
    except Exception as exc:
        return _api_error(exc)


@app.route("/api/ai/summarize/batch", methods=["POST"])
def api_ai_summarize_batch():
    """Auto-summarize all critical (level>=10) alerts from the recent list."""
    try:
        from ai_summarizer import batch_summarize_critical
        alerts = get_recent_alerts(size=50) or []
        results = batch_summarize_critical(alerts)
        return jsonify({"summaries": results, "count": len(results)})
    except Exception as exc:
        return _api_error(exc)


# ── Syslog Decoder Management ─────────────────────────────────────────────────

@app.route("/api/decoders/syslog", methods=["GET"])
def api_syslog_decoders_list():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/decoders/syslog", method="GET")
        return jsonify(res or {"data": [], "total": 0})
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders/syslog", methods=["POST"])
def api_syslog_decoders_create():
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request("/api/v1/decoders/syslog", method="POST", json_body=body)
        return jsonify(res or {}), 201
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders/syslog/<name>", methods=["DELETE"])
def api_syslog_decoders_delete(name):
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request(f"/api/v1/decoders/syslog/{name}", method="DELETE")
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders/syslog/test", methods=["POST"])
def api_syslog_decoders_test():
    try:
        from watchtower_client import watchtower_request
        body = request.get_json(force=True) or {}
        res = watchtower_request("/api/v1/decoders/syslog/test", method="POST", json_body=body)
        return jsonify(res or {})
    except Exception as e:
        return _api_error(e)


@app.route("/api/decoders/syslog/reload", methods=["POST"])
def api_syslog_decoders_reload():
    try:
        from watchtower_client import watchtower_request
        res = watchtower_request("/api/v1/decoders/syslog/reload", method="POST")
        return jsonify(res or {"message": "reload triggered"})
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Log-filter (whitelist / intentional-drop) endpoints.
#
# Operators define rules here to hide noisy known-good events from search
# results. Rules are applied as ``must_not`` clauses in the Logs explorer and
# audit endpoints. The underlying documents stay in OpenSearch so the filter
# can be reversed by toggling the rule off.
# ---------------------------------------------------------------------------

@app.route("/api/admin/filters", methods=["GET"])
def api_filters_list():
    try:
        scope = request.args.get("scope", type=str) or None
        only_enabled = (request.args.get("only_enabled", "") or "").lower() in ("1", "true", "yes")
        rules = _log_filters.list_rules(scope=scope, only_enabled=only_enabled)
        return jsonify({"rules": rules, "total": len(rules)})
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/filters", methods=["POST"])
def api_filters_create():
    try:
        body = request.get_json(silent=True) or {}
        user = (session.get("user") or "").strip()
        rule = _log_filters.create(
            name=body.get("name", ""),
            scope=body.get("scope", "both"),
            match_field=body.get("match_field", ""),
            match_op=body.get("match_op", "equals"),
            match_value=body.get("match_value", ""),
            reason=body.get("reason", ""),
            enabled=bool(body.get("enabled", True)),
            created_by=user,
        )
        return jsonify(rule), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/filters/<int:rule_id>", methods=["GET"])
def api_filters_get(rule_id):
    try:
        r = _log_filters.get_rule(rule_id)
        if r is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify(r)
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/filters/<int:rule_id>", methods=["PUT", "PATCH"])
def api_filters_update(rule_id):
    try:
        body = request.get_json(silent=True) or {}
        r = _log_filters.update(rule_id, **body)
        if r is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify(r)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/filters/<int:rule_id>", methods=["DELETE"])
def api_filters_delete(rule_id):
    try:
        if not _log_filters.delete(rule_id):
            return jsonify({"error": "Not found"}), 404
        return jsonify({"deleted": rule_id})
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/filters/<int:rule_id>/toggle", methods=["POST"])
def api_filters_toggle(rule_id):
    try:
        r = _log_filters.toggle(rule_id)
        if r is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify(r)
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Configuration audit-log endpoints (super_admin only).
# Records every write-action against rules, decoders, dashboards, users, etc.
# ---------------------------------------------------------------------------

@app.route("/api/admin/audit-log", methods=["GET"])
def api_admin_audit_log():
    """Paginated audit-log entries.

    Query params: size, offset, user, target_prefix, action, time_from,
    time_to, only_failures.
    """
    try:
        size = min(request.args.get("size", 100, type=int) or 100, 500)
        offset = request.args.get("offset", 0, type=int) or 0
        user_f = request.args.get("user", type=str) or None
        target_pref = request.args.get("target_prefix", type=str) or None
        action = request.args.get("action", type=str) or None
        only_failures = (request.args.get("only_failures", "") or "").lower() in ("1", "true", "yes")
        time_from = request.args.get("time_from", type=str) or None
        time_to = request.args.get("time_to", type=str) or None
        t_from_ms = _to_epoch_ms(time_from) if time_from else None
        t_to_ms = _to_epoch_ms(time_to) if time_to else None
        rows, total = _audit_log.query(
            size=size, offset=offset, user=user_f,
            target_prefix=target_pref, action=action,
            time_from_ms=t_from_ms, time_to_ms=t_to_ms,
            only_failures=only_failures,
        )
        return jsonify({"hits": rows, "total": total})
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/audit-log/stats", methods=["GET"])
def api_admin_audit_log_stats():
    """Summary stats for the audit-log page header (last 24h by default)."""
    try:
        window = request.args.get("window_hours", 24, type=int) or 24
        return jsonify(_audit_log.stats(window_hours=window))
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Pipeline health — drop counters + queue depth.
#
# Surfaces WatchTower's Prometheus /metrics endpoint as a friendly JSON
# object so the Stack Status page can show DLQ depth, dropped events, and
# agent connectivity counts at a glance — the things that matter when an
# operator suspects logs are being lost.
# ---------------------------------------------------------------------------

_PROM_LINE_RE = re.compile(r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\s+(?P<value>[\-+0-9eE.]+)\s*$")


def _parse_prom_text(text: str) -> dict:
    """Minimal Prometheus text exposition parser — only the bare-metric
    form WatchTower emits (no labels). Returns {metric_name: float}."""
    out: dict[str, float] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _PROM_LINE_RE.match(line)
        if not m:
            continue
        try:
            out[m.group("name")] = float(m.group("value"))
        except ValueError:
            continue
    return out


@app.route("/api/pipeline/health", methods=["GET"])
def api_pipeline_health():
    """Read /metrics from WatchTower and return a structured digest."""
    try:
        from watchtower_client import watchtower_request
        # watchtower_request returns parsed JSON on success; metrics is plaintext
        # so we have to do a raw fetch — use the same base URL.
        import requests
        from config import WATCHTOWER_URL
        url = f"{WATCHTOWER_URL.rstrip('/')}/metrics"
        r = requests.get(url, timeout=5, verify=False)
        r.raise_for_status()
        metrics = _parse_prom_text(r.text)

        def g(name, default=0):
            v = metrics.get(name)
            return float(v) if v is not None else default

        digest = {
            "uptime_seconds": g("watchtower_uptime_seconds"),
            "agents": {
                "total":        g("watchtower_agents_total"),
                "active":       g("watchtower_agents_active"),
                "disconnected": g("watchtower_agents_disconnected"),
            },
            "alerts_total": g("watchtower_alerts_total"),
            "forwarder": {
                "dropped_events": g("watchtower_forwarder_dropped_events_total"),
                "dropped_alerts": g("watchtower_forwarder_dropped_alerts_total"),
                "dlq_depth":      g("watchtower_forwarder_dlq_depth"),
            },
            "memory_bytes": g("watchtower_memory_alloc_bytes"),
            "_raw": metrics,
        }
        # Health signal — green if no drops & DLQ < 100; otherwise warn.
        drops = digest["forwarder"]["dropped_events"] + digest["forwarder"]["dropped_alerts"]
        dlq   = digest["forwarder"]["dlq_depth"]
        if drops > 0 or dlq > 1000:
            digest["status"] = "degraded"
        elif dlq > 100:
            digest["status"] = "warning"
        else:
            digest["status"] = "healthy"
        return jsonify(digest)
    except Exception as e:
        return jsonify({"error": str(e), "status": "unknown"}), 200


# ---------------------------------------------------------------------------
# Retention policy — visibility + on-demand purge (super_admin only).
#
# WatchVault already has a daily scheduler that deletes indices older than
# its configured retention_days. This UI surfaces:
#   - what's stored right now, grouped by index family + age
#   - a one-shot "purge indices older than N days" action for cases where
#     the scheduler hasn't yet run or retention was just shortened
# Both operations require super_admin and are recorded in the config audit log.
# ---------------------------------------------------------------------------

_DATE_SUFFIX_RE = re.compile(r"-(\d{4})\.(\d{2})\.(\d{2})$")


def _parse_index_date(name: str):
    m = _DATE_SUFFIX_RE.search(name or "")
    if not m:
        return None
    try:
        from datetime import datetime, timezone
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                        tzinfo=timezone.utc)
    except Exception:
        return None


def _index_family(name: str) -> str:
    """watchvault-events-2025.05.20 → 'events' ; watchvault-alerts-* → 'alerts'."""
    if not name:
        return "other"
    body = _DATE_SUFFIX_RE.sub("", name)
    parts = body.split("-", 1)
    return parts[1] if len(parts) > 1 else parts[0]


@app.route("/api/admin/retention", methods=["GET"])
def api_retention_overview():
    """Return effective retention + per-family index inventory with ages."""
    try:
        from watchtower_client import opensearch_request
        # Per-index stats. _cat/indices is cheaper and already wrapped.
        cat = opensearch_request(f"/_cat/indices/{INDEX_PREFIX}-*?format=json&bytes=b") or []
        if not isinstance(cat, list):
            cat = []

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        families: dict[str, dict] = {}
        items: list[dict] = []
        for row in cat:
            name = row.get("index") or ""
            if not name:
                continue
            dt = _parse_index_date(name)
            age_days = int((now - dt).total_seconds() // 86400) if dt else None
            size_b = int(row.get("store.size") or row.get("pri.store.size") or 0)
            docs = int(row.get("docs.count") or 0)
            fam = _index_family(name)
            entry = {
                "name": name,
                "family": fam,
                "age_days": age_days,
                "size_bytes": size_b,
                "docs": docs,
                "health": row.get("health"),
                "status": row.get("status"),
            }
            items.append(entry)
            f = families.setdefault(fam, {"indices": 0, "size_bytes": 0, "docs": 0,
                                          "oldest_days": 0, "youngest_days": None})
            f["indices"]   += 1
            f["size_bytes"] += size_b
            f["docs"]      += docs
            if age_days is not None:
                if age_days > f["oldest_days"]:
                    f["oldest_days"] = age_days
                if f["youngest_days"] is None or age_days < f["youngest_days"]:
                    f["youngest_days"] = age_days

        items.sort(key=lambda x: (x["family"], -(x["age_days"] or 0)))
        family_list = [{"family": k, **v} for k, v in sorted(families.items())]

        # Effective retention_days — env hint; not authoritative since it lives
        # in WatchVault config. We surface it so the operator can spot drift.
        cfg_retention = os.getenv("WATCHVAULT_RETENTION_DAYS", "")
        return jsonify({
            "configured_retention_days": int(cfg_retention) if cfg_retention.isdigit() else None,
            "families": family_list,
            "indices": items,
            "total_indices": len(items),
            "total_size_bytes": sum(i["size_bytes"] for i in items),
            "total_docs": sum(i["docs"] for i in items),
        })
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/retention/purge", methods=["POST"])
def api_retention_purge():
    """Delete indices older than ``older_than_days`` for one or more families.

    Body: {"older_than_days": 90, "families": ["events", "fim"], "dry_run": false}
    """
    try:
        from watchtower_client import opensearch_request
        body = request.get_json(silent=True) or {}
        days = int(body.get("older_than_days", 0))
        if days < 1:
            return jsonify({"error": "older_than_days must be ≥ 1"}), 400
        wanted = set(body.get("families") or [])  # empty = all families
        dry_run = bool(body.get("dry_run", False))

        cat = opensearch_request(f"/_cat/indices/{INDEX_PREFIX}-*?format=json") or []
        if not isinstance(cat, list):
            cat = []

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        to_delete: list[dict] = []
        for row in cat:
            name = row.get("index") or ""
            dt = _parse_index_date(name)
            if not name or not dt:
                continue
            age = (now - dt).total_seconds() / 86400
            if age < days:
                continue
            fam = _index_family(name)
            if wanted and fam not in wanted:
                continue
            to_delete.append({"name": name, "family": fam, "age_days": int(age)})

        deleted, failed = [], []
        if not dry_run:
            for entry in to_delete:
                try:
                    opensearch_request(f"/{entry['name']}", method="DELETE")
                    deleted.append(entry)
                except Exception as ex:
                    failed.append({**entry, "error": str(ex)})
        return jsonify({
            "dry_run": dry_run,
            "older_than_days": days,
            "families": sorted(wanted),
            "matched": len(to_delete),
            "would_delete": to_delete if dry_run else [],
            "deleted": deleted,
            "failed": failed,
        })
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# System Logs viewer (super_admin only).
#
# Wraps system_logs.read_logs() so an operator can pull recent WatchTower /
# WatchVault / OpenSearch / dashboard output from inside the UI without SSH.
# ---------------------------------------------------------------------------

@app.route("/api/admin/system-logs/services", methods=["GET"])
def api_system_logs_services():
    try:
        import system_logs as _sl
        return jsonify({"services": _sl.list_services()})
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/system-logs", methods=["GET"])
def api_system_logs_read():
    try:
        import system_logs as _sl
        service = request.args.get("service", type=str) or "watchtower"
        lines = request.args.get("lines", 200, type=int) or 200
        return jsonify(_sl.read_logs(service, lines=lines))
    except Exception as e:
        return _api_error(e)


# ---------------------------------------------------------------------------
# Backup & restore endpoints (super_admin only).
#
# The Python endpoint shells out to the same scripts/sentinel-backup.sh used
# from the command line so there's a single source of truth for what gets
# packaged. Downloads stream the resulting tarball directly to the browser.
# ---------------------------------------------------------------------------

_BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")
_BACKUP_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "sentinel-backup.sh")


@app.route("/api/admin/backup/list", methods=["GET"])
def api_backup_list():
    """Return the list of backup archives already on disk."""
    try:
        abs_dir = os.path.abspath(_BACKUP_DIR)
        if not os.path.isdir(abs_dir):
            return jsonify({"backups": [], "dir": abs_dir})
        items = []
        for name in sorted(os.listdir(abs_dir), reverse=True):
            if not name.startswith("sentinel-") or not name.endswith(".tar.gz"):
                continue
            full = os.path.join(abs_dir, name)
            try:
                st = os.stat(full)
                items.append({
                    "name": name,
                    "size_bytes": st.st_size,
                    "created_at_ms": int(st.st_mtime * 1000),
                })
            except Exception:
                pass
        return jsonify({"backups": items, "dir": abs_dir})
    except Exception as e:
        return _api_error(e)


@app.route("/api/admin/backup/download", methods=["POST"])
def api_backup_download():
    """Create a fresh backup and stream it to the browser.

    This is a write action: it produces a new archive on disk *and* returns
    its bytes. The after_request audit hook records the request so we know
    when a super-admin exported configs.
    """
    import subprocess
    from flask import send_file
    try:
        abs_script = os.path.abspath(_BACKUP_SCRIPT)
        abs_dir = os.path.abspath(_BACKUP_DIR)
        if not os.path.isfile(abs_script):
            return jsonify({"error": "backup script missing", "path": abs_script}), 500
        os.makedirs(abs_dir, exist_ok=True)
        proc = subprocess.run(
            ["/bin/bash", abs_script, abs_dir],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            return jsonify({
                "error": "backup script failed",
                "returncode": proc.returncode,
                "stderr": proc.stderr[-2000:],
            }), 500
        # Find the newest archive in the dir.
        archives = [
            f for f in os.listdir(abs_dir)
            if f.startswith("sentinel-") and f.endswith(".tar.gz")
        ]
        if not archives:
            return jsonify({"error": "no archive produced"}), 500
        archives.sort(key=lambda f: os.path.getmtime(os.path.join(abs_dir, f)), reverse=True)
        latest = os.path.join(abs_dir, archives[0])
        return send_file(
            latest,
            mimetype="application/gzip",
            as_attachment=True,
            download_name=os.path.basename(latest),
        )
    except Exception as e:
        return _api_error(e)


@app.route("/healthz", methods=["GET"])
def healthz():
    """Liveness probe — process is up and Flask is responding."""
    return jsonify({"status": "ok"}), 200


@app.route("/readyz", methods=["GET"])
def readyz():
    """Readiness probe — local SQLite DBs are reachable. Returns 503 if any
    fail so a load balancer can drain this instance."""
    checks = {}
    ok_overall = True
    for name, mod in (
        ("audit_log", _audit_log), ("log_filters", _log_filters),
        ("users", _users), ("silent_sources", _silent),
        ("correlations", _corr),
    ):
        try:
            mod._conn().close()
            checks[name] = "ok"
        except Exception as e:
            checks[name] = f"fail: {e}"
            ok_overall = False
    return jsonify({"status": "ok" if ok_overall else "degraded", "checks": checks}), 200 if ok_overall else 503


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5050))
    # Never enable debug in production — exposes an interactive debugger shell (RCE).
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)
