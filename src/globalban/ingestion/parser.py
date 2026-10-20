from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from globalban.models.events import EventSource, EventType, SecurityEvent

_IP = r"[0-9A-Fa-f:.]+"
_SYSLOG_TIME = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s"
)
_PAM_FAILURES = re.compile(
    rf"PAM (?P<count>\d+) more authentication failures; rhost=(?P<ip>{_IP})(?: user=(?P<user>\S+))?"
)
_FAILED_LOGIN = re.compile(
    rf"Failed (?:password|publickey|keyboard-interactive/pam) for "
    rf"(?:(?:invalid user) )?(?P<user>\S+) from (?P<ip>{_IP})(?:\s|$)"
)
_ACCEPTED_LOGIN = re.compile(
    rf"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    rf"(?P<user>\S+) from (?P<ip>{_IP})(?:\s|$)"
)
_WINDOWS_EVENT_TYPES = {
    4624: EventType.LOGIN_SUCCEEDED,
    4625: EventType.LOGIN_FAILED,
    4771: EventType.LOGIN_FAILED,
    4776: EventType.LOGIN_FAILED,
}
_WINDOWS_ACTIVITY_IDS = {
    1102,
    1116,
    1117,
    4104,
    4688,
    4698,
    4702,
    4719,
    4720,
    4728,
    4732,
    4756,
    7045,
}
_WINDOWS_FIELD_ALLOWLIST = {
    "TargetUserName",
    "SubjectUserName",
    "IpAddress",
    "ClientAddress",
    "NewProcessName",
    "CreatorProcessName",
    "ProcessName",
    "ServiceName",
    "ServiceFileName",
    "TaskName",
    "TargetFilename",
}
_WINDOWS_INDICATOR_INPUTS = {
    "NewProcessName",
    "CreatorProcessName",
    "ProcessName",
    "ServiceName",
    "ServiceFileName",
    "TaskName",
    "TargetFilename",
    "CommandLine",
}


def _aware_timestamp(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return timestamp


def parse_ssh_log(line: str, timestamp: datetime | None = None) -> SecurityEvent | None:
    """Parse supported OpenSSH/PAM auth messages; unrelated lines are ignored."""
    if len(line) > 65_536:
        raise ValueError("SSH log line exceeds the 64 KiB limit")
    observed_at = _aware_timestamp(timestamp) if timestamp is not None else _ssh_timestamp(line)
    match = _PAM_FAILURES.search(line)
    if match:
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=observed_at,
            source=EventSource.SSH,
            event_type=EventType.LOGIN_FAILED,
            source_ip=match.group("ip"),
            username=match.group("user"),
            count=int(match.group("count")),
        )
    for pattern, event_type in (
        (_FAILED_LOGIN, EventType.LOGIN_FAILED),
        (_ACCEPTED_LOGIN, EventType.LOGIN_SUCCEEDED),
    ):
        match = pattern.search(line)
        if match:
            return SecurityEvent(
                event_id=str(uuid.uuid4()),
                timestamp=observed_at,
                source=EventSource.SSH,
                event_type=event_type,
                source_ip=match.group("ip"),
                username=match.group("user"),
            )
    return None


def _ssh_timestamp(line: str) -> datetime:
    now = datetime.now().astimezone()
    match = _SYSLOG_TIME.match(line)
    if match is None:
        return now
    try:
        candidate = datetime(
            now.year,
            datetime.strptime(match.group("month"), "%b").month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=now.tzinfo,
        )
    except ValueError as exc:
        raise ValueError("Invalid syslog timestamp") from exc
    if candidate - now > timedelta(days=183):
        candidate = candidate.replace(year=candidate.year - 1)
    return candidate


def parse_windows_event_fields(
    fields: Mapping[str, str], timestamp: datetime | None = None
) -> SecurityEvent | None:
    """Normalize a small allowlist of Windows Security event IDs and fields."""
    event_id_text = fields.get("EventID")
    if event_id_text is None or not event_id_text.isdecimal():
        return None
    windows_event_id = int(event_id_text)
    event_type = _WINDOWS_EVENT_TYPES.get(windows_event_id)
    if event_type is None:
        return None
    source_ip = _normalize_windows_ip(
        fields.get("IpAddress") or fields.get("ClientAddress")
    )
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=_aware_timestamp(timestamp),
        source=EventSource.WINDOWS,
        event_type=event_type,
        source_ip=source_ip,
        username=fields.get("TargetUserName") or fields.get("SubjectUserName"),
        windows_event_id=windows_event_id,
        windows_fields=_allowed_windows_fields(fields),
        behavioral_indicators=_windows_behavioral_indicators(fields),
    )


def parse_windows_event_xml(xml_text: str) -> SecurityEvent | None:
    """Parse an exported Windows Event XML record without retaining its raw XML."""
    if len(xml_text) > 1_048_576:
        raise ValueError("Windows Event XML record exceeds the 1 MiB limit")
    if "<!DOCTYPE" in xml_text.upper():
        raise ValueError("Windows Event XML document types are not accepted")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Windows Event XML: {exc}") from exc
    fields: dict[str, str] = {}
    timestamp: datetime | None = None
    provider: str | None = None
    host: str | None = None
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name == "EventID" and element.text:
            fields["EventID"] = element.text.strip()
        elif local_name == "Provider":
            provider = element.attrib.get("Name") or None
        elif local_name == "Computer" and element.text:
            host = element.text.strip() or None
        elif local_name == "Data" and element.text:
            field_name = element.attrib.get("Name")
            if field_name in (_WINDOWS_FIELD_ALLOWLIST | {"CommandLine"}):
                value = element.text.strip()
                if len(value) > 8192:
                    value = value[:8192]
                fields[field_name] = value
        elif local_name == "TimeCreated":
            raw_timestamp = element.attrib.get("SystemTime")
            if raw_timestamp:
                normalized = raw_timestamp.replace("Z", "+00:00")
                try:
                    timestamp = datetime.fromisoformat(normalized)
                except ValueError as exc:
                    raise ValueError("Invalid Windows event SystemTime") from exc
    auth_event = parse_windows_event_fields(fields, timestamp)
    if auth_event is not None:
        return _with_windows_metadata(auth_event, provider, host)

    event_id_text = fields.get("EventID")
    if event_id_text is None or not event_id_text.isdecimal():
        return None
    windows_event_id = int(event_id_text)
    if windows_event_id not in _WINDOWS_ACTIVITY_IDS:
        return None
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=_aware_timestamp(timestamp),
        source=EventSource.WINDOWS,
        event_type=EventType.WINDOWS_ACTIVITY,
        source_ip=_normalize_windows_ip(
            fields.get("IpAddress") or fields.get("ClientAddress")
        ),
        username=fields.get("TargetUserName") or fields.get("SubjectUserName"),
        windows_event_id=windows_event_id,
        windows_provider=provider,
        host=host,
        windows_fields=_allowed_windows_fields(fields),
        behavioral_indicators=_windows_behavioral_indicators(fields),
    )


def _allowed_windows_fields(fields: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value[:1024]
        for name, value in fields.items()
        if name in _WINDOWS_FIELD_ALLOWLIST
    }


def _windows_behavioral_indicators(fields: Mapping[str, str]) -> tuple[str, ...]:
    observed = " ".join(fields.get(name, "") for name in _WINDOWS_INDICATOR_INPUTS).lower()
    indicators: list[str] = []
    if any(token in observed for token in ("-enc", "encodedcommand", "invoke-expression")):
        indicators.append("encoded_or_obfuscated_script_marker")
    if any(
        token in observed
        for token in ("downloadstring", "invoke-webrequest", "curl", "bitsadmin")
    ):
        indicators.append("download_or_transfer_marker")
    if any(token in observed for token in ("\\temp\\", "\\appdata\\", "\\public\\", "\\downloads\\")):
        indicators.append("user_writable_or_staging_path_marker")
    if any(token in observed for token in ("schtasks", "scheduled task", "service")):
        indicators.append("task_or_service_marker")
    if any(token in observed for token in ("lsass", "sam", "ntds.dit", "credential", "password")):
        indicators.append("credential_related_text_marker")
    if any(token in observed for token in ("wevtutil", "clear-eventlog", "auditpol")):
        indicators.append("audit_or_log_management_marker")
    return tuple(indicators)


def _normalize_windows_ip(value: str | None) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)


def _with_windows_metadata(
    event: SecurityEvent, provider: str | None, host: str | None
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        source_ip=event.source_ip,
        username=event.username,
        windows_event_id=event.windows_event_id,
        count=event.count,
        windows_provider=provider,
        host=host,
        windows_fields=event.windows_fields,
        behavioral_indicators=event.behavioral_indicators,
    )