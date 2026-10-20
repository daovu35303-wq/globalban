from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
from types import MappingProxyType


class EventSource(str, Enum):
    SSH = "ssh"
    WINDOWS = "windows"


class EventType(str, Enum):
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCEEDED = "login_succeeded"
    WINDOWS_ACTIVITY = "windows_activity"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: EventSource
    event_type: EventType
    source_ip: str | None = None
    username: str | None = None
    windows_event_id: int | None = None
    count: int = 1
    windows_provider: str | None = None
    host: str | None = None
    windows_fields: Mapping[str, str] | None = None
    behavioral_indicators: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id or len(self.event_id) > 256:
            raise ValueError("event_id must not be empty")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if (
            not isinstance(self.count, int)
            or isinstance(self.count, bool)
            or self.count < 1
        ):
            raise ValueError("count must be positive")
        if self.username is not None and (
            not isinstance(self.username, str) or len(self.username) > 256
        ):
            raise ValueError("username must be text of at most 256 characters")
        if self.host is not None and len(self.host) > 255:
            raise ValueError("host must not exceed 255 characters")
        if self.windows_provider is not None and len(self.windows_provider) > 255:
            raise ValueError("windows_provider must not exceed 255 characters")
        if self.source_ip is not None:
            ip_address(self.source_ip)
        if self.windows_event_id is not None:
            if (
                not isinstance(self.windows_event_id, int)
                or isinstance(self.windows_event_id, bool)
                or self.windows_event_id < 1
            ):
                raise ValueError("windows_event_id must be a positive integer")
            if self.source is not EventSource.WINDOWS:
                raise ValueError("windows_event_id is only valid for Windows events")
        if self.windows_fields is not None:
            if not all(
                isinstance(name, str)
                and len(name) <= 128
                and isinstance(value, str)
                and len(value) <= 1024
                for name, value in self.windows_fields.items()
            ):
                raise ValueError(
                    "windows_fields must contain bounded text keys and values"
                )
            object.__setattr__(
                self, "windows_fields", MappingProxyType(dict(self.windows_fields))
            )
        if not isinstance(self.behavioral_indicators, tuple) or not all(
            isinstance(indicator, str) and len(indicator) <= 128
            for indicator in self.behavioral_indicators
        ):
            raise ValueError("behavioral_indicators must be a tuple of bounded strings")

    @property
    def timestamp_utc(self) -> datetime:
        return self.timestamp.astimezone(timezone.utc)