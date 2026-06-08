"""
Unit tests for the XDR correlation layer — entity normalization, the four
cross-domain detectors, and the response orchestrator.

Stdlib unittest (the project has no pytest); run with:
    cd sentinelCoreDashboard && python3 tests/test_xdr.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import entities  # noqa: E402
import correlations as corr  # noqa: E402
import response_orchestrator as ro  # noqa: E402


# ── fake OpenSearch ─────────────────────────────────────────────────────────────

def _bucket(key, count, *, first=1000, last=2000, sub=None):
    b = {"key": key, "doc_count": count, "first": {"value": first}, "last": {"value": last}}
    if sub:
        for k, vals in sub.items():
            b[k] = {"buckets": [{"key": v} for v in vals]}
    return b


def make_fake(spec):
    """spec: {(index_substr, field): [buckets]} for by_entity aggs.
    Returns a fake os_search(index, body) that mimics each source populating
    exactly one entity field."""
    def fake(index, body):
        aggs = body.get("aggs", {})
        if "by_entity" in aggs:
            field = aggs["by_entity"]["terms"]["field"]
            for (idx_sub, f), buckets in spec.items():
                if idx_sub in index and f == field:
                    return {"aggregations": {"by_entity": {"buckets": buckets}}}
            return {"aggregations": {"by_entity": {"buckets": []}}}
        return {}
    return fake


class _TmpDB(unittest.TestCase):
    """Point correlations at a throwaway SQLite DB for each test."""
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        corr.DB_PATH = self._tmp.name
        corr.init_db()

    def tearDown(self):
        os.unlink(self._tmp.name)


# ── entity normalization ────────────────────────────────────────────────────────

class TestEntities(unittest.TestCase):
    def test_user_forms_collapse(self):
        self.assertEqual(entities.normalize("user", "CORP\\Alice"), "alice")
        self.assertEqual(entities.normalize("user", "alice@corp.com"), "alice")
        self.assertEqual(entities.normalize("user", "ALICE"), "alice")

    def test_machine_and_noise_dropped(self):
        self.assertEqual(entities.normalize("user", "WS01$"), "")
        self.assertEqual(entities.normalize("user", "SYSTEM"), "")
        self.assertEqual(entities.normalize("user", "ANONYMOUS LOGON"), "")
        self.assertEqual(entities.normalize("user", ""), "")

    def test_host_short_name(self):
        self.assertEqual(entities.normalize("host", "WS01.corp.local"), "ws01")
        self.assertEqual(entities.normalize("host", "WS01"), "ws01")

    def test_field_value_prefers_aliases(self):
        self.assertEqual(entities.field_value({"userPrincipalName": "bob@x.io"}, "user"), "bob")
        self.assertEqual(entities.field_value({"src_ip": "1.2.3.4"}, "ip"), "1.2.3.4")
        self.assertEqual(entities.field_value({"nope": "x"}, "user"), "")


# ── detectors ───────────────────────────────────────────────────────────────────

class TestCompromisedIdentity(_TmpDB):
    def test_fires_only_when_two_domains(self):
        fake = make_fake({
            ("alerts", "TargetUserName"): [_bucket("CORP\\alice", 3)],   # endpoint
            ("events", "TargetUserName"): [_bucket("alice@corp.com", 5)],  # identity
            # bob appears in a single domain only → must NOT fire
            ("cloud",  "userPrincipalName"): [_bucket("bob", 9)],
        })
        new = corr.detect_compromised_identity(
            os_search=fake, events_idx="watchvault-events-*",
            alerts_idx="watchvault-alerts-*", cloud_idx="watchvault-cloud-*", now_ms=5000)
        entities_fired = {i["entity"] for i in new}
        self.assertIn("alice", entities_fired)
        self.assertNotIn("bob", entities_fired)
        alice = [i for i in new if i["entity"] == "alice"][0]
        self.assertGreaterEqual(len(alice["domains"]), 2)
        self.assertIn("endpoint", alice["domains"])
        self.assertIn("identity", alice["domains"])


class TestLateralMovement(_TmpDB):
    def test_fires_on_host_fanout(self):
        many = ["h1", "h2", "h3", "h4", "h5", "h6"]
        fake = make_fake({
            ("events", "TargetUserName"): [_bucket("carol", 6, sub={"dest_hosts": many})],
        })
        new = corr.detect_lateral_movement(
            os_search=fake, events_idx="watchvault-events-*", now_ms=5000)
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["entity"], "carol")
        self.assertEqual(new[0]["evidence"]["host_count"], 6)

    def test_below_threshold_no_fire(self):
        fake = make_fake({
            ("events", "TargetUserName"): [_bucket("dan", 2, sub={"dest_hosts": ["h1", "h2"]})],
        })
        new = corr.detect_lateral_movement(
            os_search=fake, events_idx="watchvault-events-*", now_ms=5000)
        self.assertEqual(new, [])


class TestDataExfil(_TmpDB):
    def test_requires_both_domains(self):
        fake = make_fake({
            ("events", "TargetUserName"): [_bucket("dave", 500)],   # endpoint mass-read
            ("cloud",  "userPrincipalName"): [_bucket("dave", 80)],  # cloud egress
        })
        new = corr.detect_data_exfiltration(
            os_search=fake, events_idx="watchvault-events-*",
            cloud_idx="watchvault-cloud-*", now_ms=5000)
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["entity"], "dave")
        self.assertEqual(sorted(new[0]["domains"]), ["cloud", "endpoint"])


class TestRecordIncidentDedup(_TmpDB):
    def test_repeat_refreshes_not_duplicates(self):
        first = corr._record_incident(detector="x", entity="alice", severity="high",
                                      first_seen_ms=1, last_seen_ms=2, evidence={})
        self.assertIsNotNone(first)
        again = corr._record_incident(detector="x", entity="alice", severity="high",
                                      first_seen_ms=1, last_seen_ms=9, evidence={})
        self.assertIsNone(again)  # refresh, not a new incident
        self.assertEqual(len(corr.list_incidents(status="open")), 1)


# ── response orchestrator ───────────────────────────────────────────────────────

class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self._orig = entities.hosts_for_user
        entities.hosts_for_user = lambda user, **kw: ["agent-1"]

    def tearDown(self):
        entities.hosts_for_user = self._orig
        for k in ("XDR_AUTO_RESPONSE", "XDR_AUTO_RESPONSE_MIN_SEVERITY"):
            os.environ.pop(k, None)

    def test_bundle_compromised_identity(self):
        inc = {"id": 1, "detector": "compromised_identity", "entity": "alice",
               "entity_type": "user", "severity": "critical", "evidence": {}}
        actions = ro.bundle_for(inc)
        names = {a["action"] for a in actions}
        self.assertIn("disable-account", names)
        self.assertIn("isolate-host", names)
        self.assertTrue(all(a["agent_id"] == "agent-1" for a in actions))

    def test_auto_response_gating(self):
        inc = {"id": 1, "detector": "x", "entity": "a", "severity": "critical"}
        self.assertFalse(ro.should_auto_respond(inc))            # off by default
        os.environ["XDR_AUTO_RESPONSE"] = "true"
        self.assertTrue(ro.should_auto_respond(inc))             # critical passes
        inc["severity"] = "high"
        self.assertFalse(ro.should_auto_respond(inc))            # below min (critical)


if __name__ == "__main__":
    unittest.main(verbosity=2)
