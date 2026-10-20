import unittest
from datetime import datetime, timezone

from globalban.models.decisions import DetectionAlert
from globalban.privacy.egress_check import validate_advisory_payload
from globalban.privacy.masking import mask_ip
from globalban.privacy.payload_builder import build_advisory_payload


class MaskingTests(unittest.TestCase):
    def test_masks_ipv4_and_ipv6(self):
        self.assertEqual(mask_ip("192.0.2.13"), "192.0.2.0/24")
        self.assertEqual(mask_ip("2001:db8::1234"), "2001:db8::/48")

    def test_advisory_payload_is_minimized_and_validated(self):
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, 12, 34, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="review signal",
            evidence_event_ids=("one", "two"),
            failure_count=5,
            confidence=0.65,
            baseline_context="local only",
        )
        payload = build_advisory_payload(alert)
        validate_advisory_payload(payload)
        self.assertEqual(payload["alert"]["source_ip"], "8.8.8.0/24")
        self.assertNotIn("explanation", payload["alert"])
        self.assertNotIn("evidence_event_ids", payload["alert"])

    def test_egress_rejects_unmasked_ip_and_unapproved_fields(self):
        payload = {
            "schema_version": 1,
            "alert": {
                "rule_id": "AUTH-FAILURE-BURST",
                "source_ip": "8.8.8.8",
                "hour_utc": "2025-01-01T12:00:00+00:00",
                "failure_count": 5,
                "evidence_count": 2,
                "confidence": 0.65,
            },
        }
        with self.assertRaisesRegex(ValueError, "masked"):
            validate_advisory_payload(payload)
        payload["alert"]["source_ip"] = "8.8.8.0/24"
        payload["alert"]["raw_log"] = "secret"
        with self.assertRaisesRegex(ValueError, "privacy allowlist"):
            validate_advisory_payload(payload)


if __name__ == "__main__":
    unittest.main()