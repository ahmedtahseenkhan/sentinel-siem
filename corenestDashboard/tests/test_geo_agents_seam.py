"""
Seam tests for two dashboard↔indexer contracts that broke the same way FIM did
(a field/shape mismatch with no test catching it, surfacing as an empty UI):

  1. /api/geo/map-data — alert source IPs live under event_data.fields.* (raddr,
     src_ip, IpAddress, ...), NOT event_data.src_ip. The Threat Map was empty
     because the agg targeted a field that doesn't exist.
  2. /api/agents — returns the {data:{affected_items:[...]}} envelope; the
     Discover agent dropdown reads data.affected_items. If the shape drifts, the
     dropdown silently empties.

Stdlib unittest (no pytest):
    cd corenestDashboard && python3 tests/test_geo_agents_seam.py
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as appmod          # noqa: E402
import watchtower_client as wtc  # noqa: E402
import geo                     # noqa: E402


def _login(client):
    with client.session_transaction() as sess:
        sess["user"] = "tester"
        sess["role"] = "super_admin"
    return client


# ── /api/geo/map-data ─────────────────────────────────────────────────────────

class GeoMapDataTest(unittest.TestCase):
    def setUp(self):
        self.client = _login(appmod.app.test_client())
        self._captured = []
        self._os = wtc._os_search
        self._bulk = geo.bulk_lookup
        wtc._os_search = self._fake_search
        geo.bulk_lookup = self._fake_bulk
        self.addCleanup(lambda: setattr(wtc, "_os_search", self._os))
        self.addCleanup(lambda: setattr(geo, "bulk_lookup", self._bulk))

    def _fake_search(self, index, body):
        self._captured.append((index, body))
        # A public source IP surfaced via event_data.fields.raddr (ip_2), exactly
        # how WatchVault indexes a network alert.
        return {
            "aggregations": {
                "ip_2": {"buckets": [{
                    "key": "8.8.8.8",
                    "doc_count": 5,
                    "max_level": {"value": 11.0},
                    "last_seen": {"value": 1_700_000_000_000},
                }]},
            }
        }

    def _fake_bulk(self, ips, max_ips=50):
        return {ip: {
            "ip": ip, "country": "United States", "country_code": "US",
            "city": "Ashburn", "region": "VA", "lat": 39.03, "lng": -77.5,
            "isp": "Google LLC",
        } for ip in ips if ip == "8.8.8.8"}

    def test_geo_returns_points_from_alert_ips(self):
        data = self.client.get("/api/geo/map-data?hours=168").get_json()
        self.assertEqual(data["total_ips"], 1)
        p = data["points"][0]
        self.assertEqual(p["ip"], "8.8.8.8")
        self.assertEqual(p["lat"], 39.03)
        self.assertEqual(p["lng"], -77.5)          # geo.py maps lon→lng
        self.assertEqual(p["alert_count"], 5)
        self.assertEqual(p["max_level"], 11)
        self.assertTrue(any(c["country_code"] == "US" for c in data["countries"]))

    def test_geo_aggregates_event_data_fields_not_src_ip(self):
        """Regression guard: aggregate the nested event_data.fields.* source-IP
        fields, never the non-existent event_data.src_ip."""
        self.client.get("/api/geo/map-data")
        body_str = json.dumps(self._captured[0][1])
        self.assertIn("event_data.fields.raddr", body_str)
        self.assertIn("event_data.fields.src_ip", body_str)
        self.assertNotIn('"event_data.src_ip"', body_str)


# ── /api/agents ───────────────────────────────────────────────────────────────

class AgentsEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.client = _login(appmod.app.test_client())
        self._req = wtc.watchtower_request
        wtc.watchtower_request = self._fake_request
        self.addCleanup(lambda: setattr(wtc, "watchtower_request", self._req))

    def _fake_request(self, path, *a, **k):
        # WatchTower agent registry response.
        return {"data": [{
            "id": "4e53a73d28e250beb50df9ef8c311dce",
            "hostname": "DESKTOP-NGB1C7N",
            "status": "active",
            "last_heartbeat": 1_700_000_000_000,
            "registered_at": 1_700_000_000_000,
        }], "total": 1}

    def test_agents_returns_affected_items_envelope(self):
        """Pins the {data:{affected_items:[list]}} contract the Discover agent
        dropdown depends on. If this drifts, the dropdown silently empties."""
        data = self.client.get("/api/agents?limit=200").get_json()
        items = data["data"]["affected_items"]
        self.assertIsInstance(items, list)
        self.assertEqual(len(items), 1)
        a = items[0]
        self.assertTrue(a.get("id"))
        self.assertTrue(a.get("hostname") or a.get("name"))


if __name__ == "__main__":
    unittest.main()
