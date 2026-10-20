from __future__ import annotations

import json
import re
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path

_WINDOWS_CHANNEL_NAME = re.compile(r"^[A-Za-z0-9._/ -]{1,128}$")


@dataclass(frozen=True, slots=True)
class AppConfig:
    failure_threshold: int = 5
    correlation_window_seconds: int = 300
    max_actions_per_hour: int = 3
    allowlist: tuple[str, ...] = ()
    baseline_path: str | None = "~/.globalban/baseline.json"
    windows_baseline_path: str | None = "~/.globalban/windows-baseline.json"
    baseline_warmup_events: int = 20
    dry_run: bool = True
    execution_enabled: bool = False
    windows_event_channels: tuple[str, ...] = ("Security",)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.failure_threshold, int)
            or isinstance(self.failure_threshold, bool)
            or self.failure_threshold < 2
        ):
            raise ValueError("failure_threshold must be an integer of at least 2")
        if (
            not isinstance(self.correlation_window_seconds, int)
            or isinstance(self.correlation_window_seconds, bool)
            or self.correlation_window_seconds < 1
        ):
            raise ValueError("correlation_window_seconds must be a positive integer")
        if (
            not isinstance(self.max_actions_per_hour, int)
            or isinstance(self.max_actions_per_hour, bool)
            or self.max_actions_per_hour < 1
        ):
            raise ValueError("max_actions_per_hour must be a positive integer")
        if not isinstance(self.allowlist, tuple) or not all(
            isinstance(entry, str) for entry in self.allowlist
        ):
            raise ValueError("allowlist must be a tuple of IP addresses or CIDR networks")
        for entry in self.allowlist:
            try:
                ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid allowlist entry: {entry}") from exc
        if self.baseline_path is not None and not isinstance(self.baseline_path, str):
            raise ValueError("baseline_path must be a path string or None")
        if self.windows_baseline_path is not None and not isinstance(
            self.windows_baseline_path, str
        ):
            raise ValueError("windows_baseline_path must be a path string or None")
        if (
            not isinstance(self.baseline_warmup_events, int)
            or isinstance(self.baseline_warmup_events, bool)
            or self.baseline_warmup_events < 1
        ):
            raise ValueError("baseline_warmup_events must be a positive integer")
        if not isinstance(self.dry_run, bool) or not isinstance(self.execution_enabled, bool):
            raise ValueError("dry_run and execution_enabled must be booleans")
        if self.execution_enabled and self.dry_run:
            raise ValueError("execution_enabled cannot be combined with dry_run")
        if (
            not isinstance(self.windows_event_channels, tuple)
            or not 1 <= len(self.windows_event_channels) <= 10
            or any(
                not isinstance(channel, str)
                or not _WINDOWS_CHANNEL_NAME.fullmatch(channel)
                or channel != channel.strip()
                for channel in self.windows_event_channels
            )
        ):
            raise ValueError("windows_event_channels must contain 1 to 10 valid channel names")


def load_config(path: str | Path) -> AppConfig:
    """Load the documented JSON-compatible YAML configuration without dependencies."""
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read configuration {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Configuration must be a JSON/YAML mapping")
    allowed_keys = {
        "failure_threshold",
        "correlation_window_seconds",
        "max_actions_per_hour",
        "allowlist",
        "baseline_path",
        "windows_baseline_path",
        "baseline_warmup_events",
        "dry_run",
        "execution_enabled",
        "windows_event_channels",
    }
    unknown = set(raw) - allowed_keys
    if unknown:
        raise ValueError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    allowlist = raw.get("allowlist", [])
    if not isinstance(allowlist, list) or not all(isinstance(item, str) for item in allowlist):
        raise ValueError("allowlist must be a list of IP addresses or CIDR networks")
    for key in (
        "failure_threshold",
        "correlation_window_seconds",
        "max_actions_per_hour",
        "baseline_warmup_events",
    ):
        if key in raw and (not isinstance(raw[key], int) or isinstance(raw[key], bool)):
            raise ValueError(f"{key} must be an integer")
    for key in ("dry_run", "execution_enabled"):
        if key in raw and not isinstance(raw[key], bool):
            raise ValueError(f"{key} must be a boolean")
    baseline_path = raw.get("baseline_path", "~/.globalban/baseline.json")
    if baseline_path is not None and not isinstance(baseline_path, str):
        raise ValueError("baseline_path must be a path string or null")
    windows_baseline_path = raw.get(
        "windows_baseline_path", "~/.globalban/windows-baseline.json"
    )
    if windows_baseline_path is not None and not isinstance(windows_baseline_path, str):
        raise ValueError("windows_baseline_path must be a path string or null")
    windows_event_channels = raw.get("windows_event_channels", ["Security"])
    if not isinstance(windows_event_channels, list) or not all(
        isinstance(channel, str) for channel in windows_event_channels
    ):
        raise ValueError("windows_event_channels must be a list of channel names")
    return AppConfig(
        failure_threshold=raw.get("failure_threshold", 5),
        correlation_window_seconds=raw.get("correlation_window_seconds", 300),
        max_actions_per_hour=raw.get("max_actions_per_hour", 3),
        allowlist=tuple(allowlist),
        baseline_path=baseline_path,
        windows_baseline_path=windows_baseline_path,
        baseline_warmup_events=raw.get("baseline_warmup_events", 20),
        dry_run=raw.get("dry_run", True),
        execution_enabled=raw.get("execution_enabled", False),
        windows_event_channels=tuple(windows_event_channels),
    )