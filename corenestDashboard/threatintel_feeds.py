"""
threatintel_feeds.py — Operator registry for WatchTower threat-intel feed sources.

WatchTower ingests IOC feeds configured via env/YAML (WATCHTOWER_THREATINTEL_SOURCES
for the feed list, plus enrich.virustotal for VirusTotal enrichment). There is no
live config-write API on the manager, so this module is a *dashboard-side registry*:
operators record which feeds they want and their API keys here, and the Threat
Intelligence page renders the exact env block to apply to the WatchTower deployment.

This keeps the page honest — it never claims to hot-reconfigure the manager — while
giving a single place to manage feed credentials and see what's enabled.

One table:
  feeds — one row per known source type, with enabled flag + api_key + optional url.
          Pre-seeded with the source types WatchTower's threatintel.Manager supports
          (abuseipdb / otx / plaintext / feodotracker / abusech_hash / urlhaus / misp)
          plus virustotal (alert enrichment).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

DB_PATH = os.path.join(os.path.dirname(__file__), "threatintel_feeds.db")
_LOCK = threading.Lock()

# Catalog of feeds WatchTower can consume. `type` matches the switch in
# WatchTower/internal/threatintel/manager.go (or "virustotal" for the enricher).
#   requires_key — feed needs an API key to function
#   requires_url — feed needs a custom endpoint URL (plaintext / misp)
#   kind         — primary IOC category surfaced, for the UI
FEED_CATALOG: list[dict[str, Any]] = [
    {"type": "virustotal",   "label": "VirusTotal",        "kind": "enrichment", "requires_key": True,  "requires_url": False,
     "doc": "File/URL/IP reputation enrichment attached to alerts.", "free": False},
    {"type": "abuseipdb",    "label": "AbuseIPDB",         "kind": "ip",         "requires_key": True,  "requires_url": False,
     "doc": "Top abusive source IPs (free tier with API key).", "free": False},
    {"type": "otx",          "label": "AlienVault OTX",    "kind": "ip+domain",  "requires_key": True,  "requires_url": False,
     "doc": "OTX pulses — malicious IP and domain indicators.", "free": False},
    {"type": "misp",         "label": "MISP",              "kind": "ip+domain+hash+url", "requires_key": True, "requires_url": True,
     "doc": "MISP REST search; splits into typed IP/domain/hash/url lists.", "free": False},
    {"type": "feodotracker", "label": "Feodo Tracker",     "kind": "ip",         "requires_key": False, "requires_url": False,
     "doc": "abuse.ch botnet C2 IP blocklist (free, no key).", "free": True},
    {"type": "abusech_hash", "label": "MalwareBazaar",     "kind": "hash",       "requires_key": False, "requires_url": False,
     "doc": "abuse.ch MalwareBazaar recent malware hashes (free).", "free": True},
    {"type": "urlhaus",      "label": "URLhaus",           "kind": "domain+url", "requires_key": False, "requires_url": False,
     "doc": "abuse.ch URLhaus malicious URLs/domains (free, no key).", "free": True},
    {"type": "plaintext",    "label": "Custom plaintext feed", "kind": "custom", "requires_key": False, "requires_url": True,
     "doc": "Any HTTP feed with one IOC per line.", "free": True},
]

_CATALOG_BY_TYPE = {f["type"]: f for f in FEED_CATALOG}


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS feeds (
                type        TEXT    PRIMARY KEY,
                enabled     INTEGER NOT NULL DEFAULT 0,
                api_key     TEXT    NOT NULL DEFAULT '',
                url         TEXT    NOT NULL DEFAULT '',
                updated_by  TEXT    NOT NULL DEFAULT '',
                updated_at  INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # Seed any catalog feeds that don't have a row yet.
        for f in FEED_CATALOG:
            c.execute(
                "INSERT OR IGNORE INTO feeds (type, enabled, api_key, url, updated_at) VALUES (?,0,'','',?)",
                (f["type"], int(time.time())),
            )


def _mask(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "••••"
    return key[:4] + "•" * 6 + key[-4:]


def list_feeds(reveal: bool = False) -> list[dict[str, Any]]:
    """Return the merged catalog + stored state. Keys are masked unless reveal=True."""
    init_db()
    rows: dict[str, sqlite3.Row] = {}
    with _LOCK, _conn() as c:
        for r in c.execute("SELECT * FROM feeds").fetchall():
            rows[r["type"]] = r
    out = []
    for f in FEED_CATALOG:
        r = rows.get(f["type"])
        api_key = (r["api_key"] if r else "") or ""
        out.append({
            "type": f["type"],
            "label": f["label"],
            "kind": f["kind"],
            "doc": f["doc"],
            "free": f["free"],
            "requires_key": f["requires_key"],
            "requires_url": f["requires_url"],
            "enabled": bool(r["enabled"]) if r else False,
            "has_key": bool(api_key),
            "api_key": api_key if reveal else _mask(api_key),
            "url": (r["url"] if r else "") or "",
            "updated_by": (r["updated_by"] if r else "") or "",
            "updated_at": (r["updated_at"] if r else 0) or 0,
            # Configured = enabled AND (has key if required) AND (has url if required)
            "configured": bool(r["enabled"]) if r else False,
        })
    # Refine "configured" to account for missing required fields.
    for o in out:
        ok = o["enabled"]
        if o["requires_key"] and not o["has_key"]:
            ok = False
        if o["requires_url"] and not o["url"]:
            ok = False
        o["configured"] = ok
    return out


def upsert_feed(ftype: str, enabled: bool, api_key: str | None, url: str | None, user: str) -> dict[str, Any]:
    """Create/update a feed's stored config. api_key=None leaves the existing key untouched
    (so the masked value round-tripping from the UI doesn't clobber the real key)."""
    if ftype not in _CATALOG_BY_TYPE:
        raise ValueError(f"unknown feed type: {ftype}")
    init_db()
    with _LOCK, _conn() as c:
        cur = c.execute("SELECT api_key, url FROM feeds WHERE type=?", (ftype,)).fetchone()
        existing_key = (cur["api_key"] if cur else "") or ""
        existing_url = (cur["url"] if cur else "") or ""
        new_key = existing_key if api_key is None else api_key.strip()
        new_url = existing_url if url is None else url.strip()
        c.execute(
            """
            INSERT INTO feeds (type, enabled, api_key, url, updated_by, updated_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(type) DO UPDATE SET
                enabled=excluded.enabled,
                api_key=excluded.api_key,
                url=excluded.url,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (ftype, 1 if enabled else 0, new_key, new_url, user, int(time.time())),
        )
    for f in list_feeds():
        if f["type"] == ftype:
            return f
    raise RuntimeError("feed vanished after upsert")


def env_block() -> dict[str, Any]:
    """Generate the WatchTower env vars that realise the currently-enabled feeds.

    Returns the JSON for WATCHTOWER_THREATINTEL_SOURCES (all enabled non-VT feeds),
    plus VirusTotal enrichment vars, and a flat list of `KEY=value` lines an operator
    can paste into a compose `environment:` block or an .env file.
    """
    feeds = list_feeds(reveal=True)
    sources = []
    lines: list[str] = []
    vt = None
    for f in feeds:
        if not f["enabled"]:
            continue
        if f["type"] == "virustotal":
            vt = f
            continue
        src: dict[str, Any] = {"type": f["type"], "enabled": True}
        if f["api_key"]:
            src["api_key"] = f["api_key"]
        if f["url"]:
            src["url"] = f["url"]
        sources.append(src)

    if sources:
        lines.append("WATCHTOWER_THREATINTEL_ENABLED=true")
        lines.append("WATCHTOWER_THREATINTEL_SOURCES=" + json.dumps(sources, separators=(",", ":")))

    # VirusTotal is enrichment config, not a feed source. WatchTower reads it from
    # enrich.virustotal in the YAML; surface the key so the operator can wire it.
    if vt and vt.get("api_key"):
        lines.append("# VirusTotal is enrichment config (enrich.virustotal in watchtower.yaml):")
        lines.append("#   enrich:\n#     virustotal:\n#       enabled: true\n#       api_key: " + vt["api_key"])

    return {
        "sources": sources,
        "virustotal_enabled": bool(vt and vt.get("enabled")),
        "env": "\n".join(lines),
        "source_count": len(sources),
    }
