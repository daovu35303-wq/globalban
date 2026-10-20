from __future__ import annotations

import base64
import hashlib
import logging
import math
import re
import subprocess
import time
from collections import deque
from collections.abc import Iterator, Sequence
from pathlib import Path

from globalban.ingestion.tailer import read_windows_event_export
from globalban.models.events import SecurityEvent
logger = logging.getLogger(__name__)
_CHANNEL_NAME = re.compile(r"^[A-Za-z0-9._/ -]{1,128}$")


def read_windows_export(path: str | Path) -> Iterator[SecurityEvent]:
    """Read a user-provided XML export without subscribing to live channels."""
    yield from read_windows_event_export(path)


def _powershell_script(
    log_names: Sequence[str], lookback_seconds: int, max_events_per_channel: int
) -> str:
    quoted_names = ",".join("'" + name + "'" for name in log_names)
    return f"""
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddSeconds(-{lookback_seconds})
$totalBytes = 0
$logs = @({quoted_names})
foreach ($log in $logs) {{
    try {{
        $events = @(Get-WinEvent -FilterHashtable @{{ LogName = $log; StartTime = $start }} `
            -MaxEvents {max_events_per_channel} -ErrorAction Stop | Sort-Object TimeCreated)
    }} catch {{
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*' `
            -and $_.Exception.Message -like 'No events were found that match*') {{
            continue
        }}
        [Console]::Error.WriteLine("Failed to read channel $log")
        exit 1
    }}
    foreach ($event in $events) {{
        $xml = $event.ToXml()
        $bytes = [Text.Encoding]::UTF8.GetBytes($xml)
        if ($bytes.Length -gt 1048576) {{ throw 'event record exceeds 1 MiB' }}
        $totalBytes += $bytes.Length
        if ($totalBytes -gt 16777216) {{ throw 'poll output exceeds 16 MiB' }}
        [Convert]::ToBase64String($bytes)
    }}
}}
"""


def _validate_query(
    log_names: Sequence[str], lookback_seconds: int, max_events_per_channel: int
) -> None:
    if not log_names or isinstance(log_names, (str, bytes)):
        raise ValueError("at least one Windows event channel is required")
    if len(log_names) > 10 or any(
        not isinstance(name, str)
        or not _CHANNEL_NAME.fullmatch(name)
        or name != name.strip()
        for name in log_names
    ):
        raise ValueError("Windows event channel names contain unsupported characters")
    if (
        not isinstance(lookback_seconds, int)
        or isinstance(lookback_seconds, bool)
        or lookback_seconds < 1
    ):
        raise ValueError("lookback_seconds must be greater than zero")
    if (
        not isinstance(max_events_per_channel, int)
        or isinstance(max_events_per_channel, bool)
        or not 1 <= max_events_per_channel <= 1000
    ):
        raise ValueError("max_events_per_channel must be between 1 and 1000")


def read_windows_events(
    log_names: Sequence[str],
    *,
    lookback_seconds: int = 60,
    max_events_per_channel: int = 200,
    timeout_seconds: float = 20.0,
) -> list[str]:
    """Read bounded Windows Event Log XML records using a fixed PowerShell query."""
    _validate_query(log_names, lookback_seconds, max_events_per_channel)
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a finite positive number")
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _powershell_script(
                    log_names, lookback_seconds, max_events_per_channel
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Windows Event Log query timed out") from exc
    except OSError as exc:
        raise RuntimeError(
            "powershell.exe is required for Windows Event Log ingestion"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip()
        logger.error("Windows Event Log query failed: %s", detail or "unknown PowerShell error")
        raise RuntimeError(
            f"Windows Event Log query failed with exit code {result.returncode}"
        )

    records: list[str] = []
    for line in result.stdout.splitlines():
        try:
            raw_xml = base64.b64decode(line.strip(), validate=True)
            records.append(raw_xml.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("PowerShell returned an invalid encoded event record") from exc
    return records


def follow_windows_events(
    log_names: Sequence[str],
    *,
    poll_interval_seconds: float = 5.0,
    lookback_seconds: int = 60,
    max_events_per_channel: int = 200,
) -> Iterator[str]:
    """Poll configured channels and yield each bounded event record once per process."""
    _validate_query(log_names, lookback_seconds, max_events_per_channel)
    if (
        not isinstance(poll_interval_seconds, (int, float))
        or isinstance(poll_interval_seconds, bool)
        or not math.isfinite(poll_interval_seconds)
        or poll_interval_seconds <= 0
    ):
        raise ValueError("poll_interval_seconds must be a finite positive number")
    seen: set[str] = set()
    seen_order: deque[str] = deque()
    while True:
        records = read_windows_events(
            log_names,
            lookback_seconds=lookback_seconds,
            max_events_per_channel=max_events_per_channel,
        )
        logger.debug("Windows Event Log poll completed: %d record(s)", len(records))
        for record in records:
            fingerprint = hashlib.sha256(record.encode("utf-8")).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            seen_order.append(fingerprint)
            if len(seen_order) > 10_000:
                seen.remove(seen_order.popleft())
            yield record
        time.sleep(poll_interval_seconds)
