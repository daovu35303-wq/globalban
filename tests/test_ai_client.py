import unittest
import json
from unittest.mock import MagicMock, patch

from globalban.ai.client import request_advisory


class AIClientTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "schema_version": 1,
            "alert": {
                "rule_id": "AUTH-FAILURE-BURST",
                "source_ip": "8.8.8.0/24",
                "hour_utc": "2025-01-01T00:00:00+00:00",
                "failure_count": 5,
                "evidence_count": 4,
                "confidence": 0.65,
            },
        }

    def test_requires_https_before_network_access(self):
        with patch("globalban.ai.client.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                request_advisory("http://example.invalid", {})
        opener.assert_not_called()

    def test_rejects_known_provider_endpoints_to_prevent_proxy_bypass(self):
        with patch("globalban.ai.client.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "privacy-proxy"):
                request_advisory(
                    "https://api.openai.com/v1/chat/completions",
                    self.payload,
                )
        opener.assert_not_called()

    def test_rejects_invalid_payload_before_network_access(self):
        with patch("globalban.ai.client.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "unsupported shape"):
                request_advisory("https://proxy.example.invalid/advisory", {})
        opener.assert_not_called()

    def test_rejects_non_finite_timeout(self):
        with self.assertRaisesRegex(ValueError, "timeout"):
            request_advisory(
                "https://proxy.example.invalid/advisory",
                self.payload,
                float("nan"),
            )

    def test_adds_client_token_only_for_the_configured_proxy_request(self):
        response = MagicMock()
        response.read.return_value = json.dumps(
            {
                "summary": "Review activity.",
                "hypotheses": [],
                "caveats": ["Not proof."],
            }
        ).encode()
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with (
            patch("globalban.ai.client.build_opener", return_value=opener),
        ):
            advisory = request_advisory(
                "https://proxy.example.invalid/advisory",
                self.payload,
                authorization_token="t" * 40,
            )
        self.assertEqual(advisory.summary, "Review activity.")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), f"Bearer {'t' * 40}")
        self.assertNotIn(b"raw", request.data)

    def test_environment_token_is_not_sent_without_explicit_argument(self):
        response = MagicMock()
        response.read.return_value = json.dumps(
            {
                "summary": "Review activity.",
                "hypotheses": [],
                "caveats": ["Not proof."],
            }
        ).encode()
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with (
            patch("globalban.ai.client.build_opener", return_value=opener),
            patch.dict(
                "os.environ",
                {"GLOBALBAN_PROXY_CLIENT_TOKEN": "t" * 40},
            ),
        ):
            request_advisory(
                "https://proxy.example.invalid/advisory",
                self.payload,
            )
        request = opener.open.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
