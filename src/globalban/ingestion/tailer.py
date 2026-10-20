from __future__ import annotations

import math
import os
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from globalban.models.events import SecurityEvent
from globalban.ingestion.parser import parse_ssh_log, parse_windows_event_xml


def read_ssh_events(
    path: str | Path, timestamp: datetime | None = None
) -> Iterator[SecurityEvent]:
    """Read a static SSH auth log; callers can poll it without changing system policy."""
    with Path(path).open(encoding="utf-8", errors="replace") as log_file:
        while line := log_file.readline(65_537):
            if len(line) > 65_536:
                raise ValueError("SSH log line exceeds the 64 KiB limit")
            event = parse_ssh_log(line, timestamp)
            if event is not None:
                yield event


def read_windows_event_export(path: str | Path) -> Iterator[SecurityEvent]:
    """Read records from a Windows Event Viewer XML export."""
    try:
        with Path(path).open("rb") as export_file:
            content = export_file.read(32_000_001)
    except OSError as exc:
        raise OSError(f"Unable to read Windows event export {path}: {exc}") from exc
    if len(content) > 32_000_000:
        raise ValueError("Windows Event XML export exceeds the 32 MB limit")
    try:
        text = (
            content.decode("utf-16")
            if content.startswith((b"\xff\xfe", b"\xfe\xff"))
            else content.decode("utf-8-sig")
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"Windows Event XML export has an unsupported encoding: {path}") from exc
    if "<!DOCTYPE" in text.upper():
        raise ValueError("Windows Event XML document types are not accepted")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Windows Event XML export {path}: {exc}") from exc
    events = [root] if root.tag.rsplit("}", 1)[-1] == "Event" else (
        element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Event"
    )
    for element in events:
        event = parse_windows_event_xml(ET.tostring(element, encoding="unicode"))
        if event is not None:
            yield event


def follow_file(
    path: str | Path,
    *,
    poll_interval_seconds: float = 1.0,
    start_at_end: bool = True,
) -> Iterator[str]:
    """Yield appended lines, reopening after file replacement or truncation."""
    if (
        not isinstance(poll_interval_seconds, (int, float))
        or isinstance(poll_interval_seconds, bool)
        or not math.isfinite(poll_interval_seconds)
        or poll_interval_seconds <= 0
    ):
        raise ValueError("poll_interval_seconds must be a finite positive number")
    log_path = Path(path)
    stream = None
    identity: tuple[int, int] | None = None
    try:
        while True:
            try:
                stat = log_path.stat()
                current_identity = (stat.st_dev, stat.st_ino)
                if (
                    stream is None
                    or identity != current_identity
                    or stat.st_size < stream.tell()
                ):
                    if stream is not None:
                        stream.close()
                    stream = log_path.open("r", encoding="utf-8", errors="replace")
                    identity = current_identity
                    if start_at_end:
                        stream.seek(0, os.SEEK_END)
                line = stream.readline()
                if line:
                    yield line
                else:
                    time.sleep(poll_interval_seconds)
            except FileNotFoundError:
                if stream is not None:
                    stream.close()
                    stream = None
                    identity = None
                time.sleep(poll_interval_seconds)
    finally:
        if stream is not None:
            stream.close()