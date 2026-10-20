import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from globalban.models.decisions import DetectionAlert
from globalban.notifications.whatsapp import WhatsAppNotifier, build_whatsapp_message


class WhatsAppTests(unittest.TestCase):
    def test_message_contains_masked_address_and_no_raw_evidence(self):
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="local explanation",
            evidence_event_ids=("private-id",),
            failure_count=5,
            confidence=0.65,
            baseline_context="local only",
        )
        message = build_whatsapp_message(alert)
        self.assertIn("8.8.8.0/24", message["text"])
        self.assertNotIn("private-id", message["text"])
        self.assertNotIn("local explanation", message["text"])

    def test_explicit_send_uses_only_the_masked_alert_message(self):
        alert = DetectionAlert(
            alert_id="alert",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="local explanation",
            evidence_event_ids=("private-id",),
            failure_count=5,
            confidence=0.65,
            baseline_context="local only",
        )
        notifier = WhatsAppNotifier(
            account_sid="AC" + "a" * 32,
            auth_token="test-token",
            sender="whatsapp:+14155238886",
            recipient="whatsapp:+12025550123",
        )
        response = MagicMock()
        response.status = 201
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch("globalban.notifications.whatsapp.build_opener", return_value=opener):
            notifier.send_alert(alert)
        request = opener.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://api.twilio.com/"))
        self.assertIn(b"8.8.8.0%2F24", request.data)
        self.assertNotIn(b"private-id", request.data)
        self.assertNotIn(b"local+explanation", request.data)

    def test_rejects_invalid_twilio_endpoint_identifiers(self):
        with self.assertRaisesRegex(ValueError, "account SID"):
            WhatsAppNotifier(
                account_sid="not-a-sid",
                auth_token="token",
                sender="whatsapp:+14155238886",
                recipient="whatsapp:+12025550123",
            )


if __name__ == "__main__":
    unittest.main()