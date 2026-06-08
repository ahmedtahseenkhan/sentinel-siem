"""
Ticketing integration for Sentinel SIEM.
Supports a built-in "native" provider (creates a WatchTower case — no external
ITSM required), Jira (Cloud/Server), and ServiceNow.
Ticket references are persisted in a local JSON store.

The default provider is "native" so a fresh deployment has a working ticket
queue out of the box; set TICKETING_PROVIDER=jira|servicenow to push to an
external system instead.
"""
import json
import logging
import os
import threading
import uuid as _uuid
from datetime import datetime
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

TICKETS_FILE = os.getenv("TICKETS_FILE", "/tmp/sentinel_tickets.json")
_lock = threading.Lock()

# ── Config (from environment) ─────────────────────────────────────────────────

def _jira_cfg():
    return {
        "url":         os.getenv("JIRA_URL", "").rstrip("/"),
        "email":       os.getenv("JIRA_EMAIL", ""),
        "token":       os.getenv("JIRA_TOKEN", ""),
        "project":     os.getenv("JIRA_PROJECT", "SEC"),
        "issue_type":  os.getenv("JIRA_ISSUE_TYPE", "Task"),
    }

def _snow_cfg():
    return {
        "url":      os.getenv("SNOW_INSTANCE_URL", "").rstrip("/"),
        "username": os.getenv("SNOW_USERNAME", ""),
        "password": os.getenv("SNOW_PASSWORD", ""),
        "table":    os.getenv("SNOW_TABLE", "incident"),
    }

def get_provider():
    return os.getenv("TICKETING_PROVIDER", "native").lower()

def is_configured():
    p = get_provider()
    if p == "native":
        return True  # built-in cases need no external credentials
    if p == "jira":
        cfg = _jira_cfg()
        return bool(cfg["url"] and cfg["email"] and cfg["token"])
    if p == "servicenow":
        cfg = _snow_cfg()
        return bool(cfg["url"] and cfg["username"] and cfg["password"])
    return False

def get_config_status():
    """Return provider config for the settings UI (no secrets)."""
    p = get_provider()
    if p == "native":
        try:
            from config import WATCHTOWER_URL
        except Exception:
            WATCHTOWER_URL = ""
        return {
            "provider": "native",
            "configured": True,
            "url": WATCHTOWER_URL,
        }
    if p == "jira":
        cfg = _jira_cfg()
        return {
            "provider": "jira",
            "configured": is_configured(),
            "url": cfg["url"],
            "email": cfg["email"],
            "project": cfg["project"],
            "issue_type": cfg["issue_type"],
        }
    if p == "servicenow":
        cfg = _snow_cfg()
        return {
            "provider": "servicenow",
            "configured": is_configured(),
            "url": cfg["url"],
            "username": cfg["username"],
            "table": cfg["table"],
        }
    return {"provider": "none", "configured": False}


# ── Jira client ───────────────────────────────────────────────────────────────

JIRA_PRIORITY_MAP = {
    "critical": "Highest",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
}

def _jira_create(summary: str, description: str, priority: str = "medium") -> dict:
    cfg = _jira_cfg()
    if not cfg["url"] or not cfg["email"] or not cfg["token"]:
        raise ValueError("Jira not configured — set JIRA_URL, JIRA_EMAIL, JIRA_TOKEN")

    jira_priority = JIRA_PRIORITY_MAP.get(priority.lower(), "Medium")

    payload = {
        "fields": {
            "project":     {"key": cfg["project"]},
            "summary":     summary,
            "description": {
                "type":    "doc",
                "version": 1,
                "content": [{
                    "type":    "paragraph",
                    "content": [{"type": "text", "text": description}]
                }]
            },
            "issuetype": {"name": cfg["issue_type"]},
            "priority":  {"name": jira_priority},
            "labels":    ["sentinel-siem", "security"],
        }
    }

    resp = requests.post(
        f"{cfg['url']}/rest/api/3/issue",
        json=payload,
        auth=(cfg["email"], cfg["token"]),
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    key = data["key"]
    return {
        "ticket_id":  key,
        "ticket_url": f"{cfg['url']}/browse/{key}",
    }


# ── ServiceNow client ─────────────────────────────────────────────────────────

SNOW_PRIORITY_MAP = {"critical": "1", "high": "2", "medium": "3", "low": "4"}

def _snow_create(summary: str, description: str, priority: str = "medium") -> dict:
    cfg = _snow_cfg()
    if not cfg["url"] or not cfg["username"] or not cfg["password"]:
        raise ValueError("ServiceNow not configured — set SNOW_INSTANCE_URL, SNOW_USERNAME, SNOW_PASSWORD")

    payload = {
        "short_description": summary,
        "description":       description,
        "priority":          SNOW_PRIORITY_MAP.get(priority.lower(), "3"),
        "category":          "security",
        "subcategory":       "incident",
    }

    resp = requests.post(
        f"{cfg['url']}/api/now/table/{cfg['table']}",
        json=payload,
        auth=(cfg["username"], cfg["password"]),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    result = resp.json().get("result", {})
    sys_id = result.get("sys_id", "")
    number = result.get("number", "")
    return {
        "ticket_id":  number,
        "ticket_url": f"{cfg['url']}/nav_to.do?uri={cfg['table']}.do?sys_id={sys_id}",
    }


# ── Native provider (built-in WatchTower case) ─────────────────────────────────

NATIVE_PRIORITIES = {"critical", "high", "medium", "low"}

def _native_create(summary: str, description: str, priority: str = "medium",
                   alert_id: int = None, created_by: str = "system") -> dict:
    """Create a WatchTower case as a ticket — no external ITSM required.

    The case priority/SLA and (optional) auto-escalation are handled by
    WatchTower; here we just open the case and return a dashboard deep-link.
    """
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
    }


# ── Public API ────────────────────────────────────────────────────────────────

def create_ticket(summary: str, description: str, priority: str = "medium",
                  alert_id: int = None, case_id: int = None,
                  created_by: str = "system") -> dict:
    """
    Create a ticket in the configured provider.
    Returns the ticket record saved to local store.
    """
    p = get_provider()
    if p == "native":
        result = _native_create(summary, description, priority,
                                alert_id=alert_id, created_by=created_by)
        # The created case *is* the ticket — link the record to it.
        if result.get("case_id") is not None:
            case_id = result["case_id"]
    elif p == "jira":
        result = _jira_create(summary, description, priority)
    elif p == "servicenow":
        result = _snow_create(summary, description, priority)
    else:
        raise ValueError(f"No ticketing provider configured (TICKETING_PROVIDER={p})")

    ticket = {
        "id":         str(_uuid.uuid4())[:8],
        "provider":   p,
        "ticket_id":  result["ticket_id"],
        "ticket_url": result["ticket_url"],
        "summary":    summary,
        "priority":   priority,
        "alert_id":   alert_id,
        "case_id":    case_id,
        "created_by": created_by,
        "created_at": datetime.utcnow().isoformat(),
        "status":     "open",
    }

    with _lock:
        tickets = _load_tickets()
        tickets.insert(0, ticket)
        _save_tickets(tickets)

    logger.info("Ticket created: %s (%s)", result["ticket_id"], p)
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
