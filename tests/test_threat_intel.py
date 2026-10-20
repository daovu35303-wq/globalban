import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from globalban.threat_intel import LocalThreatIntel, ThreatIntelClient


class ThreatIntelTests(unittest.TestCase):
    def test_reads_explicit_local_feed_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "address": "8.8.8.8",
                            "source": "synthetic-fixture",
                            "note": "example only",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            intel = LocalThreatIntel.from_json(path)
        self.assertEqual(intel.lookup("8.8.8.8").source, "synthetic-fixture")
        self.assertIsNone(intel.lookup("1.1.1.1"))
        self.assertFalse(hasattr(intel, "block"))

    def test_rejects_invalid_or_duplicate_feed_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            path.write_text(
                json.dumps(
                    [
                        {"address": "8.8.8.8", "source": "fixture", "note": ""},
                        {"address": "8.8.8.8", "source": "fixture", "note": ""},
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                LocalThreatIntel.from_json(path)

    def test_rejects_malformed_address(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            path.write_text(
                '[{"address":"invalid","source":"fixture","note":"x"}]',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Invalid IP"):
                LocalThreatIntel.from_json(path)

    def test_remote_lookup_is_disabled_by_default_and_requires_approval(self):
        intel = ThreatIntelClient(
            endpoint_template="https://intel.example/v1/ip/{indicator}",
            allowed_host="intel.example",
        )
        self.assertEqual(intel.lookup_ip("8.8.8.8").source, "disabled")
        enabled = ThreatIntelClient(
            endpoint_template="https://intel.example/v1/ip/{indicator}",
            allowed_host="intel.example",
            enabled=True,
        )
        with self.assertRaisesRegex(PermissionError, "explicit operator approval"):
            enabled.lookup_ip("8.8.8.8")

    def test_remote_configuration_from_environment_stays_disabled_by_default(self):
        with patch.dict(
            "os.environ",
            {
                "GLOBALBAN_TI_ENABLED": "false",
                "GLOBALBAN_TI_ENDPOINT": "",
                "GLOBALBAN_TI_ALLOWED_HOST": "",
            },
        ):
            client = ThreatIntelClient.from_environment()
        self.assertEqual(client.lookup_ip("8.8.8.8").source, "disabled")
        with patch.dict(
            "os.environ",
            {
                "GLOBALBAN_TI_ENABLED": "true",
                "GLOBALBAN_TI_ENDPOINT": "",
                "GLOBALBAN_TI_ALLOWED_HOST": "",
            },
        ):
            with self.assertRaisesRegex(ValueError, "requires an endpoint"):
                ThreatIntelClient.from_environment()

    def test_explicit_remote_lookup_sends_only_indicator_and_validates_response(self):
        intel = ThreatIntelClient(
            endpoint_template="https://intel.example/v1/ip/{indicator}",
            allowed_host="intel.example",
            api_key="fixture-api-key",
            enabled=True,
        )
        response = MagicMock()
        response.read.return_value = json.dumps(
            {"malicious": False, "confidence": 0.25, "details": "fixture response"}
        ).encode()
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch("globalban.threat_intel.build_opener", return_value=opener):
            result = intel.lookup_ip("8.8.8.8", approved=True)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://intel.example/v1/ip/8.8.8.8")
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture-api-key")
        self.assertFalse(result.malicious)
        self.assertEqual(result.confidence, 0.25)

    def test_remote_lookup_rejects_redirect_and_untrusted_host(self):
        intel = ThreatIntelClient(
            endpoint_template="https://intel.example/v1/ip/{indicator}",
            allowed_host="intel.example",
            enabled=True,
        )
        error = HTTPError(
            "https://intel.example/v1/ip/8.8.8.8",
            302,
            "redirect",
            {},
            None,
        )
        opener = MagicMock()
        opener.open.side_effect = error
        with patch("globalban.threat_intel.build_opener", return_value=opener):
            with self.assertRaisesRegex(RuntimeError, "HTTP 302"):
                intel.lookup_ip("8.8.8.8", approved=True)
        with self.assertRaisesRegex(ValueError, "explicitly allowed host"):
            ThreatIntelClient(
                endpoint_template="https://intel.example/v1/ip/{indicator}",
                allowed_host="other.example",
                enabled=True,
            )


if __name__ == "__main__":
    unittest.main()
