from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta

from globalban.models.events import EventSource, SecurityEvent


@dataclass(frozen=True, slots=True)
class EventContext:
    event_count: int
    failure_count: int
    success_count: int
    sources: tuple[str, ...]


def summarize_context(events: list[SecurityEvent]) -> EventContext:
    """Summarize a bounded evidence set without asserting identity or intent."""
    return EventContext(
        event_count=len(events),
        failure_count=sum(
            event.count for event in events if event.event_type.value == "login_failed"
        ),
        success_count=sum(
            event.count for event in events if event.event_type.value == "login_succeeded"
        ),
        sources=tuple(sorted({event.source.value for event in events})),
    )


class EventContextBuilder:
    """Keep a bounded, time-based context without grouping by username."""

    def __init__(self, *, window_seconds: int = 300, max_events: int = 1000) -> None:
        if window_seconds < 1 or max_events < 1:
            raise ValueError("context limits must be positive")
        self._window = timedelta(seconds=window_seconds)
        self._max_events = max_events
        self._events: dict[tuple[str, str], deque[SecurityEvent]] = defaultdict(deque)
        self._event_count = 0

    def add(self, event: SecurityEvent) -> EventContext:
        key = self._key(event)
        if key is None:
            return summarize_context([event])
        history = self._events[key]
        previous_count = len(history)
        history.append(event)
        ordered = sorted(history, key=lambda item: item.timestamp_utc)
        newest = ordered[-1].timestamp_utc
        cutoff = newest - self._window
        retained = [previous for previous in ordered if previous.timestamp_utc >= cutoff]
        history.clear()
        history.extend(retained)
        self._event_count += len(retained) - previous_count
        event_time = event.timestamp_utc
        related = [
            previous
            for previous in history
            if abs((previous.timestamp_utc - event_time).total_seconds())
            <= self._window.total_seconds()
        ]
        while self._event_count > self._max_events:
            oldest_key = next(iter(self._events))
            oldest = self._events[oldest_key]
            oldest.popleft()
            self._event_count -= 1
            if not oldest:
                del self._events[oldest_key]
        return summarize_context(related)

    @staticmethod
    def _key(event: SecurityEvent) -> tuple[str, str] | None:
        if event.source is EventSource.WINDOWS:
            return ("windows", event.host) if event.host else None
        return ("ssh", event.source_ip) if event.source_ip else None
