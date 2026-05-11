"""
Azure Activity Log connector for Sentinel SIEM.
Uses the Azure Monitor REST API directly (no Azure SDK required).

Required env vars:
  AZURE_TENANT_ID
  AZURE_CLIENT_ID
  AZURE_CLIENT_SECRET
  AZURE_SUBSCRIPTION_ID
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

CHECKPOINT_FILE   = os.getenv("AZURE_CHECKPOINT_FILE", "/tmp/sentinel_azure_checkpoint.json")
CLOUD_INDEX       = "watchvault-cloud"
AZURE_AUTH_URL    = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
AZURE_MONITOR_URL = ("https://management.azure.com/subscriptions/{sub_id}"
                     "/providers/microsoft.insights/eventtypes/management/values"
                     "?api-version=2015-04-01&$filter=eventTimestamp ge '{start_time}'")
_token_cache = {"token": None, "expires_at": 0}


def is_configured() -> bool:
    return all(os.getenv(k) for k in (
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"
    ))


def get_status() -> dict:
    checkpoint = _load_checkpoint()
    return {
        "provider":       "azure",
        "configured":     is_configured(),
        "subscription":   os.getenv("AZURE_SUBSCRIPTION_ID", "")[:8] + "…" if os.getenv("AZURE_SUBSCRIPTION_ID") else "",
        "last_sync":      checkpoint.get("last_sync"),
        "events_indexed": checkpoint.get("events_indexed", 0),
    }


def run_sync(opensearch_client) -> int:
    if not is_configured():
        logger.info("azure connector: not configured — skipping")
        return 0
    try:
        token      = _get_token()
        checkpoint = _load_checkpoint()
        start_time = _parse_checkpoint_time(checkpoint.get("last_sync"))
        events     = _fetch_activity_log(token, start_time)
        count      = _index_events(events, opensearch_client)

        checkpoint["last_sync"]      = datetime.now(timezone.utc).isoformat()
        checkpoint["events_indexed"] = checkpoint.get("events_indexed", 0) + count
        _save_checkpoint(checkpoint)

        logger.info("azure connector: indexed %d events", count)
        return count
    except Exception as e:
        logger.error("azure connector: sync failed: %s", e)
        return 0


def _get_token() -> str:
    global _token_cache
    if _token_cache["token"] and time.time() < _token_cache["expires_at"] - 60:
        return _token_cache["token"]

    resp = requests.post(
        AZURE_AUTH_URL.format(tenant_id=os.getenv("AZURE_TENANT_ID")),
        data={
            "grant_type":    "client_credentials",
            "client_id":     os.getenv("AZURE_CLIENT_ID"),
            "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
            "scope":         "https://management.azure.com/.default",
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache = {
        "token":      data["access_token"],
        "expires_at": time.time() + int(data.get("expires_in", 3600)),
    }
    return _token_cache["token"]


def _fetch_activity_log(token: str, start_time: datetime) -> list:
    url = AZURE_MONITOR_URL.format(
        sub_id     = os.getenv("AZURE_SUBSCRIPTION_ID"),
        start_time = start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    events = []
    while url:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning("azure connector: HTTP %d", resp.status_code)
            break
        data = resp.json()
        events.extend(data.get("value", []))
        url = data.get("nextLink")
        if len(events) >= 200:
            break
    return events


def _index_events(events: list, os_client) -> int:
    if not events:
        return 0

    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index    = f"{CLOUD_INDEX}-azure-{date_str}"
    lines    = []

    for ev in events:
        try:
            ev_time = ev.get("eventTimestamp", "")
            ts_ms   = int(datetime.fromisoformat(ev_time.replace("Z", "+00:00")).timestamp() * 1000) if ev_time else 0
            caller  = ev.get("caller", "")
            op      = ev.get("operationName", {})
            op_name = op.get("localizedValue") or op.get("value", "")
            status  = ev.get("status", {}).get("value", "")

            doc = {
                "timestamp":      ts_ms,
                "event_type":     f"azure.activity.{status.lower()}",
                "agent_id":       "azure-monitor",
                "agent_name":     "Azure Activity Log",
                "cloud_provider": "azure",
                "operation_name": op_name,
                "caller":         caller,
                "resource_id":    ev.get("resourceId", ""),
                "resource_group": ev.get("resourceGroupName", ""),
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID", ""),
                "status":         status,
                "level":          ev.get("level", ""),
                "correlation_id": ev.get("correlationId", ""),
                "description":    ev.get("description", ""),
                "tags": {
                    "source":         "azure-activity-log",
                    "cloud_provider": "azure",
                },
            }
            event_id = ev.get("eventDataId", "")
            lines.append(json.dumps({"index": {"_index": index, "_id": event_id}}))
            lines.append(json.dumps(doc))
        except Exception as e:
            logger.warning("azure connector: parse error: %s", e)

    if not lines:
        return 0

    try:
        os_client.bulk(body="\n".join(lines) + "\n")
        return len(lines) // 2
    except Exception as e:
        logger.error("azure connector: bulk index failed: %s", e)
        return 0


def _parse_checkpoint_time(ts) -> datetime:
    if ts:
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            pass
    return datetime.now(timezone.utc) - timedelta(hours=1)


def _load_checkpoint() -> dict:
    try:
        with open(CHECKPOINT_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_checkpoint(data: dict):
    Path(CHECKPOINT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(data, f)
