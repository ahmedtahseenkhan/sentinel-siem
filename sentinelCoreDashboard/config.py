"""Configuration for Sentinel Core Dashboard (WatchTower + WatchVault)."""
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
