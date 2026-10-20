from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

_MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ThreatIntelResult:
    indicator: str
    source: str
    malicious: bool | None
    confidence: float
    details: str


@dataclass(frozen=True, slots=True)
class LocalIntelRecord:
    address: str
    source: str
    note: str


class LocalThreatIntel:
    """Read-only lookup against an explicitly supplied local JSON feed."""

    def __init__(self, records: dict[str, LocalIntelRecord] | None = None) -> None:
        self._records = dict(records or {})

    @classmethod
    def from_json(cls, path: str | Path) -> LocalThreatIntel:
        feed_path = Path(path)
        try:
            raw = json.loads(feed_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to read local intelligence feed {feed_path}: {exc}") from exc
        if not isinstance(raw, list):
            raise ValueError("Local intelligence feed must be a list of records")
        records: dict[str, LocalIntelRecord] = {}
        for index, entry in enumerate(raw):
            if (
                not isinstance(entry, dict)
                or set(entry) != {"address", "source", "note"}
                or not all(isinstance(entry[key], str) for key in ("address", "source", "note"))
            ):
                raise ValueError(f"Invalid local intelligence record at index {index}")
            try:
                address = str(ip_address(entry["address"]))
            except ValueError as exc:
                raise ValueError(f"Invalid IP address in local intelligence record {index}") from exc
            if not entry["source"].strip() or len(entry["note"]) > 500:
                raise ValueError(f"Invalid source or note in local intelligence record {index}")
            if address in records:
                raise ValueError(f"Duplicate IP in local intelligence feed at index {index}")
            records[address] = LocalIntelRecord(address, entry["source"], entry["note"])
        return cls(records)

    def lookup(self, address: str) -> LocalIntelRecord | None:
        try:
            normalized = str(ip_address(address))
        except ValueError as exc:
            raise ValueError("Threat-intelligence lookup requires a valid IP address") from exc
        return self._records.get(normalized)


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        del request, fp, code, message, headers, new_url
        return None


class ThreatIntelClient:
    """Explicit HTTPS indicator lookup; never called automatically by detection."""

    def __init__(
        self,
        *,
        endpoint_template: str | None = None,
        allowed_host: str | None = None,
        api_key: str | None = None,
        enabled: bool = False,
        timeout_seconds: float = 5.0,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError("timeout_seconds must be greater than 0 and at most 30")
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        if enabled and (not endpoint_template or not allowed_host):
            raise ValueError("enabled remote lookup requires an endpoint and allowed host")
        if bool(endpoint_template) != bool(allowed_host):
            raise ValueError("endpoint_template and allowed_host must be supplied together")
        if endpoint_template and allowed_host:
            parsed = urlparse(endpoint_template)
            try:
                if parsed.hostname is not None:
                    ip_address(parsed.hostname)
                    is_ip_host = True
                else:
                    is_ip_host = True
            except ValueError:
                is_ip_host = False
            if (
                endpoint_template.count("{indicator}") != 1
                or "{" in endpoint_template.replace("{indicator}", "")
                or "}" in endpoint_template.replace("{indicator}", "")
                or parsed.scheme != "https"
                or not parsed.hostname
                or is_ip_host
                or parsed.hostname.casefold() != allowed_host.casefold()
                or parsed.username
                or parsed.password
                or parsed.port not in (None, 443)
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "threat-intelligence endpoint must be HTTPS on its explicitly allowed host"
                )
        key = api_key or os.environ.get("GLOBALBAN_TI_API_KEY")
        if key and any(character in key for character in "\r\n"):
            raise ValueError("Threat-intelligence API key contains invalid header characters")
        self._endpoint_template = endpoint_template
        self._allowed_host = allowed_host.casefold() if allowed_host else None
        self._api_key = key
        self._enabled = enabled
        self._timeout_seconds = timeout_seconds

    @classmethod
    def from_environment(cls) -> ThreatIntelClient:
        enabled_value = os.environ.get("GLOBALBAN_TI_ENABLED", "false").strip().casefold()
        if enabled_value not in {"true", "false"}:
            raise ValueError("GLOBALBAN_TI_ENABLED must be true or false")
        return cls(
            endpoint_template=os.environ.get("GLOBALBAN_TI_ENDPOINT") or None,
            allowed_host=os.environ.get("GLOBALBAN_TI_ALLOWED_HOST") or None,
            enabled=enabled_value == "true",
        )

    def lookup_ip(
        self, indicator: str, *, approved: bool = False
    ) -> ThreatIntelResult:
        if not self._enabled:
            return ThreatIntelResult(indicator, "disabled", None, 0.0, "lookup disabled")
        if not approved:
            raise PermissionError(
                "explicit operator approval is required before sending an IP to a provider"
            )
        try:
            normalized = str(ip_address(indicator))
        except ValueError as exc:
            raise ValueError("Threat-intelligence lookup requires a valid IP address") from exc

        if self._endpoint_template is None or self._allowed_host is None:
            raise RuntimeError("enabled threat-intelligence endpoint is not configured")
        url = self._endpoint_template.replace(
            "{indicator}", quote(normalized, safe="")
        )
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        request = Request(url, headers=headers, method="GET")
        opener = build_opener(_RejectRedirects())
        try:
            with opener.open(request, timeout=self._timeout_seconds) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise RuntimeError(
                f"Threat-intelligence provider returned HTTP {exc.code}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"Threat-intelligence provider could not be reached: {exc.reason}"
            ) from exc
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ValueError("Threat-intelligence response exceeded the 64 KB limit")
        try:
            data = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Threat-intelligence provider returned invalid JSON") from exc
        if (
            not isinstance(data, dict)
            or not {"malicious", "confidence"}.issubset(data)
            or set(data) - {"malicious", "confidence", "details"}
        ):
            raise ValueError("Threat-intelligence response contains unsupported fields")
        malicious = data["malicious"]
        confidence = data["confidence"]
        details = data.get("details", "")
        if (
            not isinstance(malicious, bool)
            or isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
            or not isinstance(details, str)
            or len(details) > 500
        ):
            raise ValueError("Threat-intelligence response has invalid values")
        return ThreatIntelResult(
            normalized,
            self._allowed_host,
            malicious,
            float(confidence),
            details,
        )
