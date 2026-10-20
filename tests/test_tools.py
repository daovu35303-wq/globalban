import unittest
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from globalban.agent.tools import (
    AllowlistedTools,
    TOOL_SPECS,
    empty_registry,
)
from globalban.config import AppConfig
from globalban.models.decisions import DetectionAlert
from globalban.policy.gate import PolicyGate


class ToolsTests(unittest.TestCase):
    def test_tools_are_read_only_and_payload_is_minimized(self):
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source_ip="192.0.2.10",
            rule_id="AUTH-FAILURE-BURST",
            explanation="review",
            evidence_event_ids=("e1",),
            failure_count=3,
            confidence=0.65,
            baseline_context="local",
        )
        tools = AllowlistedTools()
        self.assertEqual(tools.alert_summary(alert)["evidence_count"], 1)
        self.assertEqual(tools.advisory_payload(alert)["alert"]["source_ip"], "192.0.2.0/24")
        self.assertFalse(hasattr(tools, "execute"))
        self.assertFalse(hasattr(tools, "block_ip"))

    def test_policy_gate_defaults_to_audited_dry_run(self):
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="review",
            evidence_event_ids=("one", "two"),
            failure_count=5,
            confidence=0.65,
            baseline_context="local",
        )
        with tempfile.TemporaryDirectory() as directory:
            gate = PolicyGate(
                AppConfig(),
                audit_path=Path(directory) / "audit.jsonl",
            )
            self.assertEqual(gate.request_block(alert).status, "denied")
            result = gate.request_block(alert, approved=True)
        self.assertEqual(result.status, "dry_run")

    def test_full_tool_catalog_is_not_wired_to_execute_actions(self):
        registry = empty_registry()
        self.assertEqual(len(registry.specs()), 12)
        self.assertFalse(registry.invoke("unknown_tool", {}).ok)
        self.assertEqual(
            registry.invoke("action_enforcer", {}).error,
            "explicit approval is required",
        )
        result = registry.invoke("action_enforcer", {}, approved=True)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "tool handler is not wired")
        self.assertTrue(
            next(spec for spec in TOOL_SPECS if spec.name == "action_enforcer").requires_approval
        )


if __name__ == "__main__":
    unittest.main()
