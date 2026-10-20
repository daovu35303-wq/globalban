from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    timestamp: datetime | None
    process_name: str | None
    parent_process_name: str | None
    event_id: int = 4688
    process_id: int | None = None
    parent_process_id: int | None = None
    host: str | None = None


def parse_process_creation_xml(xml_text: str) -> ProcessObservation | None:
    """Extract fields from Windows event 4688; names are data, not verdicts or commands."""
    if len(xml_text) > 1_048_576:
        raise ValueError("Windows process event XML exceeds the 1 MiB limit")
    if "<!DOCTYPE" in xml_text.upper():
        raise ValueError("Windows Event XML document types are not accepted")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Windows process event XML: {exc}") from exc
    event_id: int | None = None
    timestamp: datetime | None = None
    fields: dict[str, str] = {}
    host: str | None = None
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name == "EventID" and element.text:
            if element.text.strip().isdecimal():
                event_id = int(element.text.strip())
        elif local_name == "TimeCreated":
            value = element.attrib.get("SystemTime")
            if value:
                try:
                    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ValueError("Invalid Windows process event timestamp") from exc
        elif local_name == "Computer" and element.text:
            host = element.text.strip() or None
        elif local_name == "Data" and element.text:
            name = element.attrib.get("Name")
            if name in {
                "NewProcessName",
                "CreatorProcessName",
                "NewProcessId",
                "ProcessId",
            }:
                fields[name] = element.text.strip()
    if event_id != 4688:
        return None
    return ProcessObservation(
        timestamp=_aware_timestamp(timestamp),
        process_name=fields.get("NewProcessName"),
        parent_process_name=fields.get("CreatorProcessName"),
        process_id=_parse_pid(fields.get("NewProcessId")),
        parent_process_id=_parse_pid(fields.get("ProcessId")),
        host=host,
    )


def _parse_pid(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError as exc:
        raise ValueError("Windows process event contains an invalid process ID") from exc


def _aware_timestamp(timestamp: datetime | None) -> datetime | None:
    if timestamp is not None and (
        timestamp.tzinfo is None or timestamp.utcoffset() is None
    ):
        raise ValueError("Windows process event timestamp must be timezone-aware")
    return timestamp


class ProcessTree:
    """Build bounded process ancestry from observed event 4688 records only."""

    def __init__(
        self,
        *,
        max_age_seconds: int = 3600,
        max_observations: int = 10_000,
    ) -> None:
        if max_age_seconds < 1 or max_observations < 1:
            raise ValueError("process tree limits must be positive")
        self._max_age = timedelta(seconds=max_age_seconds)
        self._max_observations = max_observations
        self._by_host_pid: dict[
            tuple[str, int], deque[ProcessObservation]
        ] = defaultdict(deque)
        self._observation_count = 0

    def add(self, observation: ProcessObservation) -> None:
        if (
            observation.host is None
            or observation.process_id is None
            or observation.timestamp is None
        ):
            return
        _aware_timestamp(observation.timestamp)
        key = (observation.host, observation.process_id)
        self._by_host_pid[key].append(observation)
        self._observation_count += 1
        while self._observation_count > self._max_observations:
            oldest_key = next(iter(self._by_host_pid))
            oldest = self._by_host_pid[oldest_key]
            oldest.popleft()
            self._observation_count -= 1
            if not oldest:
                del self._by_host_pid[oldest_key]

    def ancestry(
        self, observation: ProcessObservation, *, max_depth: int = 8
    ) -> tuple[str, ...]:
        if max_depth < 1:
            raise ValueError("max_depth must be positive")
        names: list[str] = []
        current = observation
        seen: set[int] = set()
        for _ in range(max_depth):
            if current.process_name:
                names.append(current.process_name)
            parent_pid = current.parent_process_id
            if (
                current.host is None
                or current.timestamp is None
                or parent_pid is None
                or parent_pid in seen
            ):
                break
            seen.add(parent_pid)
            candidates: Iterable[ProcessObservation] = self._by_host_pid.get(
                (current.host, parent_pid), ()
            )
            current_time = current.timestamp
            eligible = [
                parent
                for parent in candidates
                if parent.timestamp is not None
                and parent.timestamp <= current_time
                and current_time - parent.timestamp <= self._max_age
            ]
            if not eligible:
                break
            current = max(eligible, key=lambda parent: parent.timestamp)
        return tuple(names)
