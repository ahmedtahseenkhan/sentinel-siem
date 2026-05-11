"""
IP Geolocation for Sentinel SIEM Threat Maps.

Uses ip-api.com (free, no key, 45 req/min) with a persistent JSON cache
to avoid re-fetching the same IPs. Private/reserved IPs are skipped.
"""
import ipaddress
import json
import logging
import os
import threading
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

GEO_CACHE_FILE = os.getenv("GEO_CACHE_FILE", "/tmp/sentinel_geo_cache.json")
GEO_CACHE_TTL  = 60 * 60 * 24 * 30  # 30 days in seconds
GEO_API_URL    = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,region,lat,lon,isp,org,query"
GEO_TIMEOUT    = 5  # seconds per request
GEO_RATE_DELAY = 1.4  # seconds between requests (45/min limit = 1.33s)

_lock     = threading.Lock()
_cache    = {}   # ip → {geo data, fetched_at}
_last_req = 0.0  # timestamp of last API request


def _load_cache():
    global _cache
    try:
        with open(GEO_CACHE_FILE) as f:
            _cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _cache = {}


def _save_cache():
    Path(GEO_CACHE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(GEO_CACHE_FILE, "w") as f:
        json.dump(_cache, f)


# Load cache at import time.
_load_cache()


def is_private(ip: str) -> bool:
    """Return True for RFC1918, loopback, link-local, and other non-routable IPs."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    except ValueError:
        return True


def lookup(ip: str) -> dict | None:
    """
    Return geolocation dict for ip, or None if ip is private/invalid.
    Dict keys: ip, country, country_code, city, region, lat, lng, isp
    """
    if not ip or is_private(ip):
        return None

    global _last_req

    with _lock:
        # Check cache.
        entry = _cache.get(ip)
        if entry and (time.time() - entry.get("fetched_at", 0)) < GEO_CACHE_TTL:
            return entry.get("data")

        # Rate-limit: wait if needed.
        elapsed = time.time() - _last_req
        if elapsed < GEO_RATE_DELAY:
            time.sleep(GEO_RATE_DELAY - elapsed)

        try:
            resp = requests.get(GEO_API_URL.format(ip=ip), timeout=GEO_TIMEOUT)
            _last_req = time.time()
            data = resp.json()
        except Exception as e:
            logger.warning("geo: lookup failed for %s: %s", ip, e)
            return None

        if data.get("status") != "success":
            return None

        result = {
            "ip":           ip,
            "country":      data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "city":         data.get("city", ""),
            "region":       data.get("region", ""),
            "lat":          data.get("lat", 0),
            "lng":          data.get("lon", 0),
            "isp":          data.get("isp") or data.get("org", ""),
        }

        _cache[ip] = {"data": result, "fetched_at": time.time()}
        _save_cache()
        return result


def bulk_lookup(ips: list, max_ips: int = 50) -> dict:
    """
    Geo-enrich a list of IPs. Returns dict: ip → geo_dict.
    Skips private IPs. Limits to max_ips to avoid excessive API calls.
    """
    results = {}
    seen    = set()
    count   = 0

    for ip in ips:
        if ip in seen or is_private(ip):
            continue
        seen.add(ip)
        if count >= max_ips:
            break

        geo = lookup(ip)
        if geo:
            results[ip] = geo
            count += 1

    return results
