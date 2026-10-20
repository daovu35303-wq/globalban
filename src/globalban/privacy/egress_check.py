from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_network
from typing import Any

_PAYLOAD_FIELDS = {
    "schema_version",
    "alert",
}
_AUTH_ALERT_FIELDS = {
    "rule_id",
    "source_ip",
    "hour_utc",
    "failure_count",
    "evidence_count",
    "confidence",
}
_WINDOWS_ALERT_FIELDS = _AUTH_ALERT_FIELDS | {"event_ids", "score"}


def validate_advisory_payload(payload: dict[str, Any]) -> None:
    """Reject unknown fields and unmasked addresses at the outbound-data boundary."""
    version = payload.get("schema_version")
    if (
        set(payload) != _PAYLOAD_FIELDS
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version != 1
    ):
        raise ValueError("Advisory payload has an unsupported shape or schema version")
    alert = payload.get("alert")
    if not isinstance(alert, dict):
        raise ValueError("Advisory payload contains fields outside the privacy allowlist")
    rule_id = alert.get("rule_id")
    expected_fields = (
        _AUTH_ALERT_FIELDS
        if rule_id == "AUTH-FAILURE-BURST"
        else _WINDOWS_ALERT_FIELDS
        if rule_id == "WINDOWS-SEQUENCE-REVIEW"
        else set()
    )
    if not expected_fields or set(alert) != expected_fields:
        raise ValueError("Advisory payload contains fields outside the privacy allowlist")
    source_network = alert.get("source_ip")
    if rule_id == "AUTH-FAILURE-BURST" or source_network is not None:
        if not isinstance(source_network, str):
            raise ValueError("Advisory source_ip must be a masked CIDR network")
        try:
            network = ip_network(source_network, strict=True)
        except ValueError as exc:
            raise ValueError("Advisory source_ip must be a masked CIDR network") from exc
        expected_prefix = 24 if network.version == 4 else 48
        if network.prefixlen != expected_prefix:
            raise ValueError("Advisory source_ip is not masked to the approved prefix")
    elif rule_id != "WINDOWS-SEQUENCE-REVIEW":
        raise ValueError("Advisory source_ip must be a masked CIDR network")
    hour_utc = alert.get("hour_utc")
    if not isinstance(hour_utc, str):
        raise ValueError("Advisory hour_utc must be an hourly UTC timestamp")
    try:
        parsed_hour = datetime.fromisoformat(hour_utc)
    except ValueError as exc:
        raise ValueError("Advisory hour_utc must be an hourly UTC timestamp") from exc
    if (
        parsed_hour.tzinfo is None
        or parsed_hour.utcoffset() != timezone.utc.utcoffset(parsed_hour)
        or parsed_hour.minute != 0
        or parsed_hour.second != 0
        or parsed_hour.microsecond != 0
    ):
        raise ValueError("Advisory hour_utc must be an hourly UTC timestamp")
    for field in ("failure_count", "evidence_count"):
        if (
            not isinstance(alert.get(field), int)
            or isinstance(alert[field], bool)
            or alert[field] < 0
            or alert[field] > 10_000_000
        ):
            raise ValueError(f"Advisory {field} must be a non-negative integer")
    confidence = alert.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ValueError("Advisory confidence must be between 0 and 1")
    if rule_id == "WINDOWS-SEQUENCE-REVIEW":
        event_ids = alert.get("event_ids")
        if (
            not isinstance(event_ids, (list, tuple))
            or not 1 <= len(event_ids) <= 20
            or any(
                not isinstance(event_id, int)
                or isinstance(event_id, bool)
                or event_id < 1
                for event_id in event_ids
            )
        ):
            raise ValueError("Advisory event_ids must be a short list of positive integers")
        score = alert.get("score")
        if (
            not isinstance(score, int)
            or isinstance(score, bool)
            or not 0 <= score <= 100
        ):
            raise ValueError("Advisory score must be an integer from 0 to 100")