"""
GCP Cloud Logging connector for Sentinel SIEM.
Uses the Cloud Logging REST API with service account authentication.

Required env vars:
  GCP_PROJECT_ID
  GCP_SERVICE_ACCOUNT_JSON  — full JSON content of service account key file
                              (or set GOOGLE_APPLICATION_CREDENTIALS path)
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

CHECKPOINT_FILE  = os.getenv("GCP_CHECKPOINT_FILE", "/tmp/sentinel_gcp_checkpoint.json")
CLOUD_INDEX      = "watchvault-cloud"
GCP_LOGGING_URL  = "https://logging.googleapis.com/v2/entries:list"
_token_cache     = {"token": None, "expires_at": 0}


def is_configured() -> bool:
    return bool(os.getenv("GCP_PROJECT_ID") and (
        os.getenv("GCP_SERVICE_ACCOUNT_JSON") or
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    ))


def get_status() -> dict:
    checkpoint = _load_checkpoint()
    return {
        "provider":       "gcp",
        "configured":     is_configured(),
        "project":        os.getenv("GCP_PROJECT_ID", ""),
        "last_sync":      checkpoint.get("last_sync"),
        "events_indexed": checkpoint.get("events_indexed", 0),
    }


def run_sync(opensearch_client) -> int:
    if not is_configured():
        logger.info("gcp connector: not configured — skipping")
        return 0
    try:
        token      = _get_token()
        checkpoint = _load_checkpoint()
        start_time = _parse_checkpoint_time(checkpoint.get("last_sync"))
        entries    = _fetch_log_entries(token, start_time)
        count      = _index_entries(entries, opensearch_client)

        checkpoint["last_sync"]      = datetime.now(timezone.utc).isoformat()
        checkpoint["events_indexed"] = checkpoint.get("events_indexed", 0) + count
        _save_checkpoint(checkpoint)

        logger.info("gcp connector: indexed %d entries", count)
        return count
    except Exception as e:
        logger.error("gcp connector: sync failed: %s", e)
        return 0


def _get_token() -> str:
    global _token_cache
    if _token_cache["token"] and time.time() < _token_cache["expires_at"] - 60:
        return _token_cache["token"]

    # Try google-auth library first.
    try:
        import google.auth
        import google.auth.transport.requests as google_requests
        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/logging.read"]
        )
        creds.refresh(google_requests.Request())
        _token_cache = {"token": creds.token, "expires_at": time.time() + 3500}
        return creds.token
    except Exception:
        pass

    # Fall back to service account JSON + JWT.
    sa_json = os.getenv("GCP_SERVICE_ACCOUNT_JSON")
    if not sa_json:
        path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
        if path:
            with open(path) as f:
                sa_json = f.read()
    if not sa_json:
        raise ValueError("GCP service account credentials not found")

    sa = json.loads(sa_json)
    return _jwt_token(sa)


def _jwt_token(sa: dict) -> str:
    try:
        import jwt as pyjwt
    except ImportError:
        raise ImportError("PyJWT required for GCP auth: pip install PyJWT cryptography")

    now = int(time.time())
    claim = {
        "iss":   sa["client_email"],
        "scope": "https://www.googleapis.com/auth/logging.read",
        "aud":   "https://oauth2.googleapis.com/token",
        "exp":   now + 3600,
        "iat":   now,
    }
    signed = pyjwt.encode(claim, sa["private_key"], algorithm="RS256")
    resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": signed},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache = {"token": data["access_token"], "expires_at": now + int(data.get("expires_in", 3600))}
    return data["access_token"]


def _fetch_log_entries(token: str, start_time: datetime) -> list:
    project_id  = os.getenv("GCP_PROJECT_ID")
    filter_str  = (
        f'timestamp>="{start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}" '
        'logName=~"cloudaudit.googleapis.com"'
    )
    body = {
        "resourceNames": [f"projects/{project_id}"],
        "filter":        filter_str,
        "orderBy":       "timestamp desc",
        "pageSize":      100,
    }
    entries, page_token = [], None
    for _ in range(3):  # max 3 pages
        if page_token:
            body["pageToken"] = page_token
        resp = requests.post(
            GCP_LOGGING_URL,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning("gcp connector: HTTP %d: %s", resp.status_code, resp.text[:200])
            break
        data = resp.json()
        entries.extend(data.get("entries", []))
        page_token = data.get("nextPageToken")
        if not page_token or len(entries) >= 200:
            break
    return entries


def _index_entries(entries: list, os_client) -> int:
    if not entries:
        return 0

    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index    = f"{CLOUD_INDEX}-gcp-{date_str}"
    lines    = []

    for entry in entries:
        try:
            ts_str  = entry.get("timestamp", "")
            ts_ms   = int(datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp() * 1000) if ts_str else 0
            log_name = entry.get("logName", "")
            proto_payload = entry.get("protoPayload", {})
            method  = proto_payload.get("methodName", "")
            caller  = proto_payload.get("authenticationInfo", {}).get("principalEmail", "")

            doc = {
                "timestamp":      ts_ms,
                "event_type":     f"gcp.audit.{method.lower().replace('.', '_')}",
                "agent_id":       "gcp-cloud-logging",
                "agent_name":     f"GCP/{os.getenv('GCP_PROJECT_ID', '')}",
                "cloud_provider": "gcp",
                "log_name":       log_name,
                "method_name":    method,
                "service_name":   proto_payload.get("serviceName", ""),
                "resource_name":  proto_payload.get("resourceName", ""),
                "caller":         caller,
                "src_ip":         proto_payload.get("requestMetadata", {}).get("callerIp", ""),
                "severity":       entry.get("severity", ""),
                "project_id":     os.getenv("GCP_PROJECT_ID", ""),
                "tags": {
                    "source":         "gcp-cloud-logging",
                    "cloud_provider": "gcp",
                },
            }
            insert_id = entry.get("insertId", "")
            lines.append(json.dumps({"index": {"_index": index, "_id": insert_id}}))
            lines.append(json.dumps(doc))
        except Exception as e:
            logger.warning("gcp connector: parse error: %s", e)

    if not lines:
        return 0

    try:
        os_client.bulk(body="\n".join(lines) + "\n")
        return len(lines) // 2
    except Exception as e:
        logger.error("gcp connector: bulk index failed: %s", e)
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
