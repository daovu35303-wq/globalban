from __future__ import annotations

import hmac
import json
import os
import ssl
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from globalban.ai.client import request_advisory
from globalban.ai.schemas import AIAdvisory
from globalban.models.decisions import BehaviorSignal, DetectionAlert
from globalban.privacy.egress_check import validate_advisory_payload
from globalban.privacy.payload_builder import build_advisory_payload

_MAX_PROXY_BODY_BYTES = 64 * 1024
_MAX_UPSTREAM_RESPONSE_BYTES = 64 * 1024
_ALLOWED_UPSTREAM_HOSTS = {
    "api.openai.com",
    "generativelanguage.googleapis.com",
}


class PrivacyProxy:
    """Optional advisory client that only sends the privacy-filtered alert schema."""

    def __init__(
        self,
        endpoint: str,
        timeout: float = 10.0,
        client_token: str | None = None,
    ) -> None:
        if client_token is not None and any(character in client_token for character in "\r\n"):
            raise ValueError("Proxy client token contains invalid header characters")
        self.endpoint = endpoint
        self.timeout = timeout
        self.client_token = client_token

    @classmethod
    def from_environment(cls) -> PrivacyProxy:
        endpoint = os.environ.get("GLOBALBAN_PROXY_URL", "").strip()
        if not endpoint:
            raise ValueError("GLOBALBAN_PROXY_URL is not configured")
        return cls(
            endpoint,
            client_token=os.environ.get("GLOBALBAN_PROXY_CLIENT_TOKEN") or None,
        )

    def request(self, alert: DetectionAlert | BehaviorSignal) -> AIAdvisory:
        payload: dict[str, Any] = build_advisory_payload(alert)
        return request_advisory(
            self.endpoint,
            payload,
            timeout=self.timeout,
            authorization_token=self.client_token,
        )


@dataclass(frozen=True, slots=True)
class ProxyServerConfig:
    bind_host: str
    port: int
    upstream_base_url: str
    model: str
    client_token: str
    upstream_api_key: str
    certificate_file: str
    private_key_file: str

    def __post_init__(self) -> None:
        parsed = urlparse(self.upstream_base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_UPSTREAM_HOSTS
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("upstream must be an HTTPS URL on the fixed provider allowlist")
        if not 1 <= self.port <= 65535:
            raise ValueError("proxy port must be between 1 and 65535")
        if not self.model or len(self.model) > 100 or any(c in self.model for c in "\r\n"):
            raise ValueError("proxy model must be a non-empty short identifier")
        if len(self.client_token) < 32 or any(c in self.client_token for c in "\r\n"):
            raise ValueError("proxy client token must contain at least 32 characters")
        if not self.upstream_api_key or any(c in self.upstream_api_key for c in "\r\n"):
            raise ValueError("upstream API key is required")
        if not self.certificate_file or not self.private_key_file:
            raise ValueError("proxy TLS certificate and private key paths are required")

    @classmethod
    def from_environment(cls) -> ProxyServerConfig:
        required = {
            "GLOBALBAN_PROXY_CLIENT_TOKEN": os.environ.get(
                "GLOBALBAN_PROXY_CLIENT_TOKEN", ""
            ),
            "GLOBALBAN_AI_API_KEY": os.environ.get("GLOBALBAN_AI_API_KEY", ""),
            "GLOBALBAN_PROXY_TLS_CERT": os.environ.get(
                "GLOBALBAN_PROXY_TLS_CERT", ""
            ),
            "GLOBALBAN_PROXY_TLS_KEY": os.environ.get(
                "GLOBALBAN_PROXY_TLS_KEY", ""
            ),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(
                "Missing privacy proxy configuration: " + ", ".join(missing)
            )
        try:
            port = int(os.environ.get("GLOBALBAN_PROXY_PORT", "8443"))
        except ValueError as exc:
            raise ValueError("GLOBALBAN_PROXY_PORT must be an integer") from exc
        return cls(
            bind_host=os.environ.get("GLOBALBAN_PROXY_BIND", "127.0.0.1"),
            port=port,
            upstream_base_url=os.environ.get(
                "GLOBALBAN_PROXY_UPSTREAM", "https://api.openai.com/v1"
            ),
            model=os.environ.get("GLOBALBAN_PROXY_MODEL", "gpt-4o-mini"),
            client_token=required["GLOBALBAN_PROXY_CLIENT_TOKEN"],
            upstream_api_key=required["GLOBALBAN_AI_API_KEY"],
            certificate_file=required["GLOBALBAN_PROXY_TLS_CERT"],
            private_key_file=required["GLOBALBAN_PROXY_TLS_KEY"],
        )


def _build_upstream_request(
    payload: dict[str, Any],
    *,
    system_prompt: str,
    model: str,
    upstream_base_url: str,
    api_key: str,
) -> Request:
    validate_advisory_payload(payload)
    body = json.dumps(
        {
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(payload, separators=(",", ":")),
                },
            ],
            "response_format": {"type": "json_object"},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return Request(
        f"{upstream_base_url.rstrip('/')}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )


class _RejectUpstreamRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        del request, fp, code, message, headers, new_url
        return None


def _request_upstream(
    request: Request, *, timeout_seconds: float = 30.0
) -> bytes:
    opener = build_opener(_RejectUpstreamRedirects())
    with opener.open(request, timeout=timeout_seconds) as response:
        body = response.read(_MAX_UPSTREAM_RESPONSE_BYTES + 1)
    if len(body) > _MAX_UPSTREAM_RESPONSE_BYTES:
        raise ValueError("AI provider response exceeded the 64 KB limit")
    return body


class _ProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: ProxyServerConfig) -> None:
        self.proxy_config = config
        super().__init__(address, _ProxyRequestHandler)


class _ProxyRequestHandler(BaseHTTPRequestHandler):
    server_version = "GlobalBanPrivacyProxy/1.0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10.0)

    def do_POST(self) -> None:
        config = self.server.proxy_config  # type: ignore[attr-defined]
        if self.path != "/advisory":
            self.send_error(404, "endpoint is not allowlisted")
            return
        expected_authorization = f"Bearer {config.client_token}"
        if not hmac.compare_digest(
            self.headers.get("Authorization", ""), expected_authorization
        ):
            self.send_error(401, "proxy authentication required")
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_error(400, "transfer-encoded request bodies are not accepted")
            return
        if self.headers.get_content_type() != "application/json":
            self.send_error(415, "application/json is required")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= content_length <= _MAX_PROXY_BODY_BYTES:
                raise ValueError("request body is missing or exceeds 64 KB")
            body = self.rfile.read(content_length)
            if len(body) != content_length:
                raise ValueError("request body is incomplete")
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            validate_advisory_payload(payload)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_error(400, str(exc))
            return

        try:
            system_prompt = Path(__file__).with_name("ai").joinpath("prompt.txt").read_text(
                encoding="utf-8"
            )
        except OSError:
            self.send_error(500, "advisory prompt is unavailable")
            return
        if not system_prompt.strip():
            self.send_error(500, "advisory prompt is empty")
            return
        upstream_request = _build_upstream_request(
            payload,
            system_prompt=system_prompt,
            model=config.model,
            upstream_base_url=config.upstream_base_url,
            api_key=config.upstream_api_key,
        )
        try:
            upstream_body = _request_upstream(upstream_request)
            provider_result = json.loads(upstream_body)
            content = provider_result["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("AI provider returned non-text advisory content")
            advisory = json.loads(content)
            from globalban.ai.schemas import parse_advisory_response

            parsed_advisory = parse_advisory_response(advisory)
            response_body = json.dumps(
                {
                    "summary": parsed_advisory.summary,
                    "hypotheses": parsed_advisory.hypotheses,
                    "caveats": parsed_advisory.caveats,
                    "severity": parsed_advisory.severity,
                    "confidence": parsed_advisory.confidence,
                    "evidence": parsed_advisory.evidence,
                    "mitre_attack": parsed_advisory.mitre_attack,
                    "missing_data": parsed_advisory.missing_data,
                    "recommended_actions": parsed_advisory.recommended_actions,
                },
                separators=(",", ":"),
            ).encode("utf-8")
        except (HTTPError, URLError, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            self.send_error(502, f"AI advisory unavailable ({type(exc).__name__})")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: object) -> None:
        if self.path == "/advisory":
            super().log_message("advisory request processed")
        else:
            super().log_message(format, *args)


def serve(config: ProxyServerConfig) -> None:
    """Run an opt-in TLS proxy; never forwards client-supplied credentials upstream."""
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(config.certificate_file, config.private_key_file)
    server = _ProxyHTTPServer((config.bind_host, config.port), config)
    try:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
    finally:
        server.server_close()


def main() -> None:
    serve(ProxyServerConfig.from_environment())


if __name__ == "__main__":
    main()
