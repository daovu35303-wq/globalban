import unittest
from datetime import datetime, timezone
import json
import socket
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from globalban.models.decisions import DetectionAlert
from globalban.models.decisions import BehaviorSignal
from globalban.privacy.egress_check import validate_advisory_payload
from globalban.privacy.payload_builder import build_advisory_payload
from globalban.proxy import (
    PrivacyProxy,
    ProxyServerConfig,
    _ProxyHTTPServer,
    _build_upstream_request,
)


class ProxyTests(unittest.TestCase):
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

    def test_only_sends_filtered_alert_payload(self):
        alert = DetectionAlert(
            alert_id="internal-id",
            timestamp=datetime(2025, 1, 1, 12, 30, tzinfo=timezone.utc),
            source_ip="8.8.8.8",
            rule_id="AUTH-FAILURE-BURST",
            explanation="local detail",
            evidence_event_ids=("private-event-id",),
            failure_count=5,
            confidence=0.65,
            baseline_context="local-only",
        )
        with patch("globalban.proxy.request_advisory", return_value="advisory") as request:
            result = PrivacyProxy("https://proxy.example.invalid").request(alert)
        self.assertEqual(result, "advisory")
        payload = request.call_args.args[1]
        self.assertEqual(payload["alert"]["source_ip"], "8.8.8.0/24")
        self.assertNotIn("explanation", payload["alert"])
        self.assertNotIn("evidence_event_ids", payload["alert"])
        self.assertNotIn("baseline_context", payload["alert"])

    def test_environment_factory_requires_explicit_endpoint(self):
        with patch.dict("os.environ", {"GLOBALBAN_PROXY_URL": ""}):
            with self.assertRaisesRegex(ValueError, "not configured"):
                PrivacyProxy.from_environment()
        with patch.dict(
            "os.environ",
            {
                "GLOBALBAN_PROXY_URL": "https://proxy.example.invalid/advisory",
                "GLOBALBAN_PROXY_CLIENT_TOKEN": "c" * 40,
            },
        ):
            proxy = PrivacyProxy.from_environment()
            self.assertEqual(proxy.endpoint, "https://proxy.example.invalid/advisory")
            self.assertEqual(proxy.client_token, "c" * 40)

    def test_server_rejects_upstreams_outside_fixed_https_allowlist(self):
        with self.assertRaisesRegex(ValueError, "fixed provider allowlist"):
            ProxyServerConfig(
                bind_host="127.0.0.1",
                port=8443,
                upstream_base_url="https://attacker.example/v1",
                model="test",
                client_token="c" * 40,
                upstream_api_key="key",
                certificate_file="cert.pem",
                private_key_file="key.pem",
            )

    def test_server_injects_fixed_prompt_and_does_not_forward_client_credentials(self):
        request = _build_upstream_request(
            self.payload,
            system_prompt="fixed advisory prompt",
            model="gpt-4o-mini",
            upstream_base_url="https://api.openai.com/v1",
            api_key="provider-secret",
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer provider-secret")
        request_body = json.loads(request.data)
        self.assertEqual(request_body["messages"][0]["content"], "fixed advisory prompt")
        self.assertEqual(
            json.loads(request_body["messages"][1]["content"]),
            self.payload,
        )
        self.assertNotIn("client-token", request.data.decode("utf-8"))

    def test_windows_behavior_payload_is_minimized_and_validated(self):
        signal = BehaviorSignal(
            timestamp=datetime(2025, 1, 1, 12, 45, tzinfo=timezone.utc),
            host="private-hostname",
            score=75,
            event_ids=(4624, 4688, 4698),
            evidence_event_ids=("private-event-1", "private-event-2"),
            explanation="local-only explanation",
            confidence=0.55,
            reasons=("static detection reason",),
        )
        payload = build_advisory_payload(signal)
        validate_advisory_payload(payload)
        serialized = json.dumps(payload)
        self.assertIn("WINDOWS-SEQUENCE-REVIEW", serialized)
        self.assertNotIn("private-hostname", serialized)
        self.assertNotIn("private-event", serialized)
        self.assertNotIn("local-only explanation", serialized)

    def test_server_authenticates_client_and_returns_only_schema_validated_advisory(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = ProxyServerConfig(
            bind_host="127.0.0.1",
            port=port,
            upstream_base_url="https://api.openai.com/v1",
            model="gpt-4o-mini",
            client_token="client-token-" + "x" * 40,
            upstream_api_key="provider-secret",
            certificate_file="test-cert.pem",
            private_key_file="test-key.pem",
        )
        upstream = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "severity": "low",
                                "summary": "Review activity.",
                                "confidence": 0.4,
                                "evidence": ["A small number of failures."],
                                "hypotheses": [],
                                "caveats": ["Not proof."],
                                "mitre_attack": [],
                                "missing_data": [],
                                "recommended_actions": [],
                            }
                        )
                    }
                }
            ]
        }
        server = _ProxyHTTPServer(("127.0.0.1", port), config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            unauthorized = Request(
                f"http://127.0.0.1:{port}/advisory",
                data=json.dumps(self.payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with patch("globalban.proxy._request_upstream") as call_upstream:
                with self.assertRaises(HTTPError) as error:
                    urlopen(unauthorized, timeout=2)
                self.assertEqual(error.exception.code, 401)
                error.exception.close()
                call_upstream.assert_not_called()

            authorized = Request(
                f"http://127.0.0.1:{port}/advisory",
                data=json.dumps(self.payload).encode(),
                headers={
                    "Authorization": f"Bearer {config.client_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with patch(
                "globalban.proxy._request_upstream",
                return_value=json.dumps(upstream).encode(),
            ) as call_upstream:
                with urlopen(authorized, timeout=2) as response:
                    result = json.loads(response.read())
                self.assertEqual(response.status, 200)
                outbound = call_upstream.call_args.args[0]
                self.assertEqual(
                    outbound.get_header("Authorization"),
                    "Bearer provider-secret",
                )
            self.assertEqual(result["summary"], "Review activity.")
            self.assertEqual(result["severity"], "low")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
