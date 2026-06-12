"""Configuration for CoreNest Dashboard (WatchTower + WatchVault)."""
import os
import sys
import warnings
from dotenv import load_dotenv

load_dotenv()

# bcrypt is optional — if installed, hashed passwords are supported.
# Install with: pip install bcrypt
try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False


def _verify_password(plain: str, stored: str) -> bool:
    """Return True if plain matches stored credential.

    stored may be:
      - a bcrypt hash starting with $2b$ or $2a$ (preferred)
      - a plaintext string (accepted but emits a deprecation warning)
    """
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        if not _BCRYPT_AVAILABLE:
            warnings.warn(
                "bcrypt hashes configured but bcrypt package not installed. "
                "Run: pip install bcrypt",
                RuntimeWarning,
                stacklevel=3,
            )
            return False
        return _bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
    # Plaintext fallback — warn in production.
    if os.getenv("FLASK_ENV", "production") != "development":
        warnings.warn(
            "Plaintext password detected. Store bcrypt hashes in DASHBOARD_USERS "
            "or DASHBOARD_*_PASSWORD env vars for production deployments.",
            RuntimeWarning,
            stacklevel=3,
        )
    return plain == stored

# WatchTower (Manager) REST API — default port 9400
# SOC home location for the Threat Map "Your SOC" marker (the convergence point
# of the attack arcs). Set SOC_LAT / SOC_LNG to your operations centre's
# coordinates; leave unset to hide the marker rather than show a wrong spot.
def _opt_float(name):
    v = os.getenv(name, "").strip()
    try:
        return float(v) if v != "" else None
    except ValueError:
        return None
SOC_LAT = _opt_float("SOC_LAT")
SOC_LNG = _opt_float("SOC_LNG")
SOC_LABEL = os.getenv("SOC_LABEL", "Your SOC")

WATCHTOWER_URL = os.getenv("WATCHTOWER_URL", "http://localhost:9400")
WATCHTOWER_API_KEY = os.getenv("WATCHTOWER_API_KEY", "")

# WatchVault (Indexer) REST API — default port 9500
WATCHVAULT_URL = os.getenv("WATCHVAULT_URL", "http://localhost:9500")
WATCHVAULT_API_KEY = os.getenv("WATCHVAULT_API_KEY", "")

# OpenSearch (backing store for WatchVault) — used for direct index queries
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")

# Verify SSL — defaults True; set VERIFY_SSL=false only for self-signed dev certs.
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() in ("true", "1", "yes")

# Request timeout in seconds
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))

# Index prefix used by WatchVault (all indices are watchvault-{type}-{date})
INDEX_PREFIX = os.getenv("INDEX_PREFIX", "watchvault")

# Dashboard login (two accounts: super_admin sees all config/settings; admin sees operational views only)
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
DASHBOARD_SUPER_ADMIN_USER = os.getenv("DASHBOARD_SUPER_ADMIN_USER", "superadmin")
DASHBOARD_SUPER_ADMIN_PASSWORD = os.getenv("DASHBOARD_SUPER_ADMIN_PASSWORD", "superadmin")
DASHBOARD_ADMIN_USER = os.getenv("DASHBOARD_ADMIN_USER", "admin")
DASHBOARD_ADMIN_PASSWORD = os.getenv("DASHBOARD_ADMIN_PASSWORD", "admin")

# Role names (Phase 6.3)
ROLE_SUPER_ADMIN = "super_admin"
ROLE_ADMIN = "admin"
ROLE_ADMINISTRATOR = "administrator"
ROLE_SECURITY_ANALYST = "security_analyst"
ROLE_COMPLIANCE_OFFICER = "compliance_officer"
ROLE_VIEWER = "viewer"  # Read-only access

# Role hierarchy — used for permission checks
# Higher index = more privileged
ROLE_HIERARCHY = [
    ROLE_VIEWER,
    ROLE_COMPLIANCE_OFFICER,
    ROLE_SECURITY_ANALYST,
    ROLE_ADMIN,
    ROLE_ADMINISTRATOR,
    ROLE_SUPER_ADMIN,
]


def role_has_level(role, required_role):
    """Returns True if the given role meets or exceeds the required role level."""
    try:
        return ROLE_HIERARCHY.index(role) >= ROLE_HIERARCHY.index(required_role)
    except ValueError:
        return False


# ── Granular section access (Phase 7 — least privilege) ──────────────────────
# Minimum role required to *view* a dashboard section. Pages not listed are
# visible to every authenticated user (viewer+). This lets operators run a
# least-privilege model — e.g. an IT/helpdesk account as `viewer` sees only
# logs, alerts and dashboards, while detection content, threat-intel and admin
# tooling stay with analysts (engineers) and admins (leads).
#
# Keys are dashboard page ids (the nav `data-page` value). The client mirrors
# this via /api/me to hide nav + block navigation; the server independently
# enforces the matching API prefixes (READ_PROTECTED_PREFIXES) so a hidden
# page's data can never be fetched directly — hiding the nav is never the only
# control.
PAGE_MIN_ROLE = {
    # Detection engineering / content — analysts (engineers) and up
    "rules":          ROLE_SECURITY_ANALYST,
    "decoders":       ROLE_SECURITY_ANALYST,
    "rule-versions":  ROLE_SECURITY_ANALYST,
    "reference-sets": ROLE_SECURITY_ANALYST,
    "playbooks":      ROLE_SECURITY_ANALYST,
    # Threat intel & advanced detection — analysts and up
    "threat-intel":   ROLE_SECURITY_ANALYST,
    "threat-hunting": ROLE_SECURITY_ANALYST,
    "ueba":           ROLE_SECURITY_ANALYST,
    "rba":            ROLE_SECURITY_ANALYST,
    "correlations":   ROLE_SECURITY_ANALYST,
    # Platform / integrations — admins (leads) and up
    "cloud-monitoring": ROLE_ADMIN,
    "identity":         ROLE_ADMIN,
    "ticketing":        ROLE_ADMIN,
    "notifications":    ROLE_ADMIN,
    "integrations":     ROLE_ADMIN,
    # Super-admin-only platform pages
    "users":         ROLE_SUPER_ADMIN,
    "api-keys":      ROLE_SUPER_ADMIN,
    "log-filters":   ROLE_SUPER_ADMIN,
    "silent-sources": ROLE_SUPER_ADMIN,
    "retention":     ROLE_SUPER_ADMIN,
    "system-logs":   ROLE_SUPER_ADMIN,
    "config-audit":  ROLE_SUPER_ADMIN,
    "stack":         ROLE_SUPER_ADMIN,
    "data-sources":  ROLE_SUPER_ADMIN,
    "advanced":      ROLE_SUPER_ADMIN,
}

# API GET/read prefixes gated by minimum role, mirroring PAGE_MIN_ROLE at the
# data layer. Longest-prefix wins is not needed — the prefixes are disjoint.
# Endpoints used by the shared Overview (/api/dashboard/*, /api/alerts/*,
# /api/agents/*, /api/logs/*, /api/me) are deliberately NOT listed so every
# authenticated role keeps a working landing page.
READ_PROTECTED_PREFIXES = {
    "/api/rules":          ROLE_SECURITY_ANALYST,
    "/api/decoders":       ROLE_SECURITY_ANALYST,
    "/api/rule-versions":  ROLE_SECURITY_ANALYST,
    "/api/reference-sets": ROLE_SECURITY_ANALYST,
    "/api/playbooks":      ROLE_SECURITY_ANALYST,
    "/api/threatintel":    ROLE_SECURITY_ANALYST,
    "/api/ueba":           ROLE_SECURITY_ANALYST,
    "/api/rba":            ROLE_SECURITY_ANALYST,
    "/api/correlations":   ROLE_SECURITY_ANALYST,
    "/api/cloud":          ROLE_ADMIN,
    "/api/identity":       ROLE_ADMIN,
    "/api/tickets":        ROLE_ADMIN,
    "/api/notifications":  ROLE_ADMIN,
    "/api/integrations":   ROLE_ADMIN,
    "/api/api-keys":       ROLE_SUPER_ADMIN,
}


def restricted_pages_for(role):
    """List of page ids the given role may NOT view. The client uses this to
    hide nav items and block navigation."""
    return [page for page, req in PAGE_MIN_ROLE.items() if not role_has_level(role, req)]

# Ticketing integration
# TICKETING_PROVIDER = jira | servicenow | none
TICKETING_PROVIDER = os.getenv("TICKETING_PROVIDER", "none")

# Jira Cloud/Server
JIRA_URL          = os.getenv("JIRA_URL", "")
JIRA_EMAIL        = os.getenv("JIRA_EMAIL", "")
JIRA_TOKEN        = os.getenv("JIRA_TOKEN", "")
JIRA_PROJECT      = os.getenv("JIRA_PROJECT", "SEC")
JIRA_ISSUE_TYPE   = os.getenv("JIRA_ISSUE_TYPE", "Task")

# ServiceNow
SNOW_INSTANCE_URL = os.getenv("SNOW_INSTANCE_URL", "")
SNOW_USERNAME     = os.getenv("SNOW_USERNAME", "")
SNOW_PASSWORD     = os.getenv("SNOW_PASSWORD", "")
SNOW_TABLE        = os.getenv("SNOW_TABLE", "incident")

# Roles that can save dashboard filters (Phase 6.3)
ROLES_CAN_SAVE_DASHBOARD = (ROLE_SUPER_ADMIN, ROLE_ADMINISTRATOR, ROLE_ADMIN)


def get_dashboard_users():
    """Return dict: username -> (stored_credential, role).

    Credentials may be bcrypt hashes (starting with $2b$) or plaintext (dev only).
    Supports DASHBOARD_USERS=user:credential:role,... for multi-user config.
    """
    raw = os.getenv("DASHBOARD_USERS", "").strip()
    if raw:
        users = {}
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(":", 2)
            if len(tokens) >= 3:
                u, p, r = tokens[0].strip(), tokens[1], tokens[2].strip().lower()
                if u:
                    role = r if r in (ROLE_SUPER_ADMIN, ROLE_ADMINISTRATOR, ROLE_ADMIN, ROLE_SECURITY_ANALYST, ROLE_COMPLIANCE_OFFICER) else ROLE_ADMIN
                    users[u] = (p, role)
        if users:
            return users

    _warn_default_credentials()
    return {
        DASHBOARD_SUPER_ADMIN_USER: (DASHBOARD_SUPER_ADMIN_PASSWORD, ROLE_SUPER_ADMIN),
        DASHBOARD_ADMIN_USER: (DASHBOARD_ADMIN_PASSWORD, ROLE_ADMIN),
    }


def _warn_default_credentials():
    defaults = {
        "superadmin": DASHBOARD_SUPER_ADMIN_PASSWORD,
        "admin": DASHBOARD_ADMIN_PASSWORD,
    }
    for user, pw in defaults.items():
        if pw in (user, "admin", "superadmin", "password", "password123", ""):
            print(
                f"WARNING: Default/weak password detected for dashboard user '{user}'. "
                "Set strong credentials via DASHBOARD_SUPER_ADMIN_PASSWORD / "
                "DASHBOARD_ADMIN_PASSWORD or DASHBOARD_USERS env vars.",
                file=sys.stderr,
            )


def get_display_config():
    """Return config safe for UI (URLs only, no passwords)."""
    return {
        "watchtower_url": WATCHTOWER_URL,
        "watchvault_url": WATCHVAULT_URL,
        "opensearch_url": OPENSEARCH_URL,
        "opensearch_user": OPENSEARCH_USER,
        "verify_ssl": VERIFY_SSL,
        "request_timeout": REQUEST_TIMEOUT,
        "index_prefix": INDEX_PREFIX,
    }
