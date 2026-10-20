import unittest
from datetime import datetime, timezone

from globalban.agent.router import AgentRouter, TOOL_NAMES, choose_tools
from globalban.agent.tools import AllowlistedTools
from globalban.models.decisions import BehaviorSignal, DetectionAlert
from globalban.models.events import EventSource, EventType, SecurityEvent
from globalban.threat_intel import LocalIntelRecord, LocalThreatIntel


class RouterTests(unittest.TestCase):
    def test_routes_only_named_read_only_tools(self):
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="Review signal",
            evidence_event_ids=("one", "two"),
            failure_count=5,
            confidence=0.65,
            baseline_context="local only",
        )
        router = AgentRouter()
        self.assertEqual(router.route("alert_summary", alert)["failure_count"], 5)
        self.assertEqual(router.route("advisory_payload", alert)["alert"]["source_ip"], "8.8.8.0/24")

    def test_rejects_unknown_tool_and_non_alert_input(self):
        router = AgentRouter()
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            router.route("run_command", None)
        with self.assertRaisesRegex(TypeError, "DetectionAlert"):
            router.route("alert_summary", None)

    def test_planner_uses_fixed_tool_catalog_and_never_executes_tools(self):
        event = SecurityEvent(
            "fixture-event",
            datetime(2025, 1, 1, tzinfo=timezone.utc),
            EventSource.WINDOWS,
            EventType.WINDOWS_ACTIVITY,
            windows_event_id=4698,
            host="fixture-host",
        )
        plan = choose_tools([event], risk_score=95)
        self.assertEqual(len(TOOL_NAMES), 12)
        self.assertTrue(set(plan.tools).issubset(set(TOOL_NAMES)))
        self.assertIn("T1053.005", plan.mitre_attack)
        self.assertTrue(plan.requires_approval)
        self.assertNotIn("run_command", plan.tools)

    def test_planner_rejects_invalid_risk_scores(self):
        with self.assertRaisesRegex(ValueError, "integer from 0 to 100"):
            choose_tools([], risk_score=True)
        with self.assertRaisesRegex(ValueError, "integer from 0 to 100"):
            choose_tools([], risk_score=101)

    def test_router_threat_lookup_uses_only_an_operator_supplied_local_feed(self):
        intel = LocalThreatIntel(
            {
                "8.8.8.8": LocalIntelRecord(
                    "8.8.8.8", "synthetic-feed", "fixture record"
                )
            }
        )
        router = AgentRouter(AllowlistedTools(intel))
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="Review signal",
            evidence_event_ids=("one",),
            failure_count=3,
            confidence=0.5,
            baseline_context="local",
        )
        result = router.route("threat_intelligence_lookup", alert)
        self.assertEqual(result["source"], "synthetic-feed")
        self.assertEqual(result["note"], "fixture record")

    def test_router_can_build_a_privacy_safe_advisory_for_windows_sequences(self):
        signal = BehaviorSignal(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            host="private-host",
            score=75,
            event_ids=(4624, 4688, 4698),
            evidence_event_ids=("private-id",),
            explanation="local detail",
            confidence=0.55,
        )
        router = AgentRouter()
        payload = router.route("advisory_payload", signal)
        self.assertEqual(payload["alert"]["event_ids"], (4624, 4688, 4698))
        self.assertNotIn("private-host", str(payload))
        self.assertNotIn("private-id", str(payload))


if __name__ == "__main__":
    unittest.main()
