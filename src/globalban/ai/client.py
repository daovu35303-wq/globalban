from __future__ import annotations

import json
import math
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from typing import Any

from globalban.ai.schemas import AIAdvisory, parse_advisory_response
from globalban.privacy.egress_check import validate_advisory_payload


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, _msg, headers, _newurl):
        del _msg, _newurl
        raise HTTPError(
            request.full_url,
            code,
            "Privacy proxy redirects are not allowed",
            headers,
            fp,
        )


def request_advisory(
    endpoint: str,
    payload: dict[str, Any],
    timeout: float = 10.0,
    authorization_token: str | None = None,
) -> AIAdvisory:
    """Send a privacy-checked advisory request over HTTPS; no tools or action API are exposed."""
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("AI endpoint must be an HTTPS URL without embedded credentials")
    if parsed.hostname in {"api.openai.com", "generativelanguage.googleapis.com"}:
        raise ValueError("AI requests must use a privacy-proxy endpoint, not a provider")
    if (
        not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > 60
    ):
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")
    validate_advisory_payload(payload)
    token = authorization_token
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        if len(token) < 32 or any(character in token for character in "\r\n"):
            raise ValueError("Proxy token must contain at least 32 valid characters")
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        endpoint,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        opener = build_opener(_RejectRedirects)
        with opener.open(request, timeout=timeout) as response:
            body = response.read(64_001)
    except HTTPError as exc:
        raise RuntimeError(f"AI advisory endpoint returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"AI advisory endpoint could not be reached: {exc.reason}") from exc
    if len(body) > 64_000:
        raise ValueError("AI advisory response exceeded the 64 KB limit")
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("AI advisory endpoint returned invalid JSON") from exc
    return parse_advisory_response(decoded)