"""
AWS CloudTrail connector for Sentinel SIEM.
Polls CloudTrail management events and indexes them into OpenSearch.

Required env vars:
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_REGION              (default: us-east-1)
  AWS_ACCOUNT_ALIAS       (optional: friendly name shown in dashboard)
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

CHECKPOINT_FILE = os.getenv("AWS_CHECKPOINT_FILE", "/tmp/sentinel_aws_checkpoint.json")
CLOUD_INDEX     = "watchvault-cloud"


def is_configured() -> bool:
    return bool(os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))


def get_status() -> dict:
    checkpoint = _load_checkpoint()
    return {
        "provider":    "aws",
        "configured":  is_configured(),
        "region":      os.getenv("AWS_REGION", "us-east-1"),
        "account":     os.getenv("AWS_ACCOUNT_ALIAS", "default"),
        "last_sync":   checkpoint.get("last_sync"),
        "events_indexed": checkpoint.get("events_indexed", 0),
    }


def run_sync(opensearch_client) -> int:
    """Pull new CloudTrail events and index into OpenSearch. Returns count ingested."""
    if not is_configured():
        logger.info("aws connector: not configured — skipping")
        return 0

    try:
        import boto3
    except ImportError:
        logger.warning("aws connector: boto3 not installed — run: pip install boto3")
        return 0

    try:
        client = boto3.client(
            "cloudtrail",
            aws_access_key_id     = os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name           = os.getenv("AWS_REGION", "us-east-1"),
        )

        checkpoint  = _load_checkpoint()
        start_time  = _parse_checkpoint_time(checkpoint.get("last_sync"))
        events      = _fetch_events(client, start_time)
        count       = _index_events(events, opensearch_client)

        checkpoint["last_sync"]      = datetime.now(timezone.utc).isoformat()
        checkpoint["events_indexed"] = checkpoint.get("events_indexed", 0) + count
        _save_checkpoint(checkpoint)

        logger.info("aws connector: indexed %d events", count)
        return count

    except Exception as e:
        logger.error("aws connector: sync failed: %s", e)
        return 0


def _fetch_events(client, start_time: datetime) -> list:
    events = []
    kwargs = {
        "StartTime": start_time,
        "MaxResults": 50,
    }
    try:
        response = client.lookup_events(**kwargs)
        events.extend(response.get("Events", []))
        # Follow pagination once (avoid huge backlog on first run)
        next_token = response.get("NextToken")
        if next_token:
            resp2 = client.lookup_events(**kwargs, NextToken=next_token)
            events.extend(resp2.get("Events", []))
    except Exception as e:
        logger.warning("aws connector: lookup_events failed: %s", e)
    return events


def _index_events(events: list, os_client) -> int:
    if not events:
        return 0

    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index    = f"{CLOUD_INDEX}-aws-{date_str}"
    docs     = []

    for ev in events:
        try:
            ct_event = {}
            if ev.get("CloudTrailEvent"):
                ct_event = json.loads(ev["CloudTrailEvent"])

            doc = {
                "timestamp":    int(ev["EventTime"].timestamp() * 1000),
                "event_type":   f"cloudtrail.{ev.get('EventName', 'unknown').lower()}",
                "agent_id":     "aws-cloudtrail",
                "agent_name":   f"AWS/{os.getenv('AWS_REGION','us-east-1')}",
                "cloud_provider": "aws",
                "event_name":   ev.get("EventName", ""),
                "event_source": ev.get("EventSource", ""),
                "username":     ev.get("Username", ""),
                "src_ip":       ct_event.get("sourceIPAddress", ""),
                "user_agent":   ct_event.get("userAgent", ""),
                "request_id":   ev.get("EventId", ""),
                "resources":    [
                    {"type": r.get("ResourceType"), "name": r.get("ResourceName")}
                    for r in ev.get("Resources", [])
                ],
                "error_code":    ct_event.get("errorCode", ""),
                "error_message": ct_event.get("errorMessage", ""),
                "raw":           ev.get("CloudTrailEvent", ""),
                "tags": {
                    "source":        "cloudtrail",
                    "cloud_provider":"aws",
                    "region":        os.getenv("AWS_REGION", "us-east-1"),
                },
            }
            docs.append({"index": {"_index": index, "_id": ev.get("EventId")}, "doc": doc})
        except Exception as e:
            logger.warning("aws connector: event parse error: %s", e)

    if not docs:
        return 0

    # Bulk index.
    try:
        bulk_body = "\n".join(
            json.dumps(d["index"]) + "\n" + json.dumps(d["doc"])
            for d in docs
        ) + "\n"
        os_client.bulk(body=bulk_body)
        return len(docs)
    except Exception as e:
        logger.error("aws connector: bulk index failed: %s", e)
        return 0


def _parse_checkpoint_time(ts: str | None) -> datetime:
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
