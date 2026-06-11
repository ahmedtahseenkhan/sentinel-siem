"""
Native ticketing for Sentinel SIEM.

Tickets are first-class records backed by the built-in WatchTower case system —
no external ITSM (Jira/ServiceNow) required. Creating a ticket opens a
WatchTower case (which carries priority, SLA, auto-assignment, status workflow,
comments, and an audit trail); a lightweight reference is also kept in a local
JSON store so the Ticketing page can list/filter quickly and link back to the
originating alert/case.
"""
import json
import logging
import os
import threading
import uuid as _uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

TICKETS_FILE = os.getenv("TICKETS_FILE", "/tmp/sentinel_tickets.json")
_lock = threading.Lock()

NATIVE_PRIORITIES = {"critical", "high", "medium", "low"}

# Provider is always the built-in native system. Kept as a function so callers
# and the UI have a stable, single source of truth.
PROVIDER = "native"


def get_provider():
    return PROVIDER


def is_configured():
    # The built-in ticket queue needs no external credentials — always ready.
    return True


def get_config_status():
    """Return ticketing status for the UI (native, no external secrets)."""
    try:
        from config import WATCHTOWER_URL
    except Exception:
        WATCHTOWER_URL = ""
    return {
        "provider": "native",
        "configured": True,
        "url": WATCHTOWER_URL,
    }


# ── Native ticket creation (built-in WatchTower case) ──────────────────────────

def _native_create(summary: str, description: str, priority: str = "medium",
                    alert_id: int = None, created_by: str = "system") -> dict:
    """Open a WatchTower case as the ticket. The case carries priority, SLA,
    auto-assignment, status, comments, and audit — we just open it and return a
    dashboard deep-link."""
    from watchtower_client import watchtower_request

    pr = (priority or "medium").lower()
    if pr not in NATIVE_PRIORITIES:
        pr = "medium"

    payload = {
        "title":       summary,
        "description": description,
        "priority":    pr,
        "created_by":  created_by,
        "tags":        ["ticket"],
        "alert_ids":   [alert_id] if alert_id else [],
    }
    res = watchtower_request("/api/v1/cases", method="POST", json_body=payload)
    data = (res or {}).get("data", {}) or {}
    case_id = data.get("id")
    return {
        "ticket_id":  f"CASE-{case_id}" if case_id else "CASE-?",
        "ticket_url": "/#cases",
        "case_id":    case_id,
        "assignee":   data.get("assignee", ""),
        "status":     data.get("status", "open"),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def create_ticket(summary: str, description: str, priority: str = "medium",
                  alert_id: int = None, case_id: int = None,
                  created_by: str = "system") -> dict:
    """Create a native ticket (a WatchTower case). Returns the saved record."""
    result = _native_create(summary, description, priority,
                            alert_id=alert_id, created_by=created_by)
    # The created case *is* the ticket — link the record to it.
    if result.get("case_id") is not None:
        case_id = result["case_id"]

    ticket = {
        "id":         str(_uuid.uuid4())[:8],
        "provider":   "native",
        "ticket_id":  result["ticket_id"],
        "ticket_url": result["ticket_url"],
        "summary":    summary,
        "priority":   priority,
        "alert_id":   alert_id,
        "case_id":    case_id,
        "assignee":   result.get("assignee", ""),
        "created_by": created_by,
        "created_at": datetime.utcnow().isoformat(),
        "status":     result.get("status", "open"),
    }

    with _lock:
        tickets = _load_tickets()
        tickets.insert(0, ticket)
        _save_tickets(tickets)

    logger.info("Ticket created: %s (native case %s)", result["ticket_id"], case_id)
    return ticket


def list_tickets(alert_id: int = None, case_id: int = None, limit: int = 100) -> list:
    tickets = _load_tickets()
    if alert_id is not None:
        tickets = [t for t in tickets if t.get("alert_id") == alert_id]
    if case_id is not None:
        tickets = [t for t in tickets if t.get("case_id") == case_id]
    return tickets[:limit]


def _load_tickets() -> list:
    try:
        with open(TICKETS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_tickets(tickets: list):
    Path(TICKETS_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(TICKETS_FILE, "w") as f:
        json.dump(tickets, f, indent=2)
