"""
Seam tests for the File Integrity (FIM) dashboard endpoints.

These pin the contract between what the WatchNode FIM collector emits and what
the dashboard queries for. The WatchVault pipeline indexes FIM events as:

    event_type = "fim.<action>"   (lowercase keyword; modified/added/deleted/...)
    path, sha256, ...             (top-level — Data is flattened by eventToDoc)

The collector sets NO separate `action`/`fim_action` field. This broke once:
the handlers used `match: {event_type: "fim"}` (exact, matches nothing on a
keyword) and aggregated on a non-existent `action` field, so the page read zero
while events flowed. These tests fail loudly if that regresses.

Stdlib unittest (the project has no pytest); run with:
    cd corenestDashboard && python3 tests/test_fim.py
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as appmod  # noqa: E402


def _query_str(body):
    """Serialise a search body so we can assert on the clauses it contains."""
    return json.dumps(body)


def _login(client):
    """Give the test client a logged-in session (all /api/* routes are gated by
    the _api_auth before_request hook)."""
    with client.session_transaction() as sess:
        sess["user"] = "tester"
        sess["role"] = "super_admin"
    return client


class FimSummaryTest(unittest.TestCase):
    def setUp(self):
        self.client = _login(appmod.app.test_client())
        self._captured = []
        self._orig = appmod._os_search
        appmod._os_search = self._fake
        self.addCleanup(lambda: setattr(appmod, "_os_search", self._orig))

    def _fake(self, index, body):
        self._captured.append((index, body))
        # Realistic events-index response: total + by_type term agg whose keys
        # are the "fim.<action>" event_type values the collector emits.
        return {
            "hits": {"total": {"value": 6}},
            "aggregations": {
                "by_type": {"buckets": [
                    {"key": "fim.modified", "doc_count": 3},
                    {"key": "fim.added", "doc_count": 2},
                    {"key": "fim.deleted", "doc_count": 1},
                ]},
                "by_hour": {"buckets": [
                    {"key": 1_700_000_000_000, "doc_count": 4},
                    {"key": 1_700_003_600_000, "doc_count": 2},
                ]},
            },
        }

    def test_summary_derives_actions_from_event_type_suffix(self):
        resp = self.client.get("/api/fim/summary")
        data = resp.get_json()
        self.assertEqual(data["total"], 6)
        self.assertEqual(data["added"], 2)
        self.assertEqual(data["modified"], 3)
        self.assertEqual(data["deleted"], 1)
        self.assertEqual(len(data["timeline"]), 2)

    def test_summary_uses_event_type_prefix_not_exact_match(self):
        """Regression guard: the discriminator must be a prefix on event_type.
        An exact `match: {event_type: "fim"}` matches none of the fim.<action>
        keyword values and silently empties the page."""
        self.client.get("/api/fim/summary")
        body_str = _query_str(self._captured[0][1])
        self.assertIn('"prefix"', body_str)
        self.assertIn('"event_type": "fim"', body_str)
        self.assertNotIn('{"match": {"event_type": "fim"}}', body_str)


class FimPermissionChangedTest(unittest.TestCase):
    def setUp(self):
        self.client = _login(appmod.app.test_client())
        self._orig = appmod._os_search
        appmod._os_search = lambda index, body: {
            "hits": {"total": {"value": 3}},
            "aggregations": {"by_type": {"buckets": [
                {"key": "fim.modified", "doc_count": 1},
                {"key": "fim.permission_changed", "doc_count": 2},
            ]}},
        }
        self.addCleanup(lambda: setattr(appmod, "_os_search", self._orig))

    def test_permission_changed_counts_as_modified(self):
        data = self.client.get("/api/fim/summary").get_json()
        self.assertEqual(data["modified"], 3)  # 1 modified + 2 permission_changed


class FimEventsNormalizeTest(unittest.TestCase):
    def setUp(self):
        self.client = _login(appmod.app.test_client())
        self._orig = appmod._os_search
        appmod._os_search = self._fake
        self.addCleanup(lambda: setattr(appmod, "_os_search", self._orig))

    def _fake(self, index, body):
        # One raw FIM doc exactly as WatchVault indexes it: action lives in the
        # event_type suffix, path is top-level, no `action`/`file_path` fields.
        return {
            "hits": {
                "total": {"value": 1},
                "hits": [{"_source": {
                    "timestamp": 1_700_000_000_000,
                    "event_type": "fim.modified",
                    "agent_name": "web01",
                    "path": "/etc/passwd",
                    "sha256": "deadbeef",
                }}],
            }
        }

    def test_events_normalize_action_and_path(self):
        data = self.client.get("/api/fim/events").get_json()
        self.assertEqual(data["total"], 1)
        hit = data["hits"][0]
        # Derived for the table from the event_type suffix + top-level path.
        self.assertEqual(hit["action"], "modified")
        self.assertEqual(hit["file_path"], "/etc/passwd")


if __name__ == "__main__":
    unittest.main()
