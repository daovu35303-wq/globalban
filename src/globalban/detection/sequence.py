from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta, timezone

from globalban.detection.baseline import BehaviorBaseline
from globalban.models.decisions import BehaviorSignal
from globalban.models.events import EventSource, EventType, SecurityEvent


@dataclass(frozen=True, slots=True)
class SequenceSignal:
    source_ip: str
    failure_event_ids: tuple[str, ...]
    success_event_id: str
    elapsed_seconds: float
    explanation: str
    confidence: float


def detect_failure_then_success(
    events: list[SecurityEvent],
    window_seconds: int = 300,
    minimum_failures: int = 2,
) -> list[SequenceSignal]:
    """Find a temporal auth sequence without treating it as proof of compromise."""
    if window_seconds < 1 or minimum_failures < 1:
        raise ValueError("window_seconds and minimum_failures must be positive")
    grouped: dict[str, list[SecurityEvent]] = {}
    for event in events:
        if event.source_ip is not None:
            grouped.setdefault(event.source_ip, []).append(event)
    signals: list[SequenceSignal] = []
    window = timedelta(seconds=window_seconds)
    for address, source_events in grouped.items():
        unique_events = {event.event_id: event for event in source_events}
        ordered = sorted(unique_events.values(), key=lambda event: event.timestamp_utc)
        failures: list[SecurityEvent] = []
        for event in ordered:
            timestamp = event.timestamp_utc
            failures = [
                failure
                for failure in failures
                if timestamp - failure.timestamp_utc <= window
            ]
            if event.event_type is EventType.LOGIN_FAILED:
                failures.append(event)
            elif (
                event.event_type is EventType.LOGIN_SUCCEEDED
                and len(failures) >= minimum_failures
            ):
                first_failure = failures[0].timestamp_utc
                signals.append(
                    SequenceSignal(
                        source_ip=address,
                        failure_event_ids=tuple(failure.event_id for failure in failures),
                        success_event_id=event.event_id,
                        elapsed_seconds=(timestamp - first_failure).total_seconds(),
                        explanation=(
                            "A successful authentication followed multiple failures from "
                            "the same source address; this correlation needs human review "
                            "and does not establish identity or intent."
                        ),
                        confidence=0.55,
                    )
                )
                failures = []
    return signals


class WindowsSequenceDetector:
    """Correlate a bounded set of Windows event IDs per host for review."""

    _SUSPICIOUS_IDS = {
        1102, 1116, 1117, 4104, 4688, 4698, 4702, 4719, 4720, 4728, 4732,
        4756, 7045,
    }

    def __init__(
        self,
        window_seconds: int = 300,
        max_events_per_host: int = 500,
        max_hosts: int = 1000,
        baseline: BehaviorBaseline | None = None,
    ) -> None:
        if window_seconds < 1 or max_events_per_host < 2 or max_hosts < 1:
            raise ValueError(
                "window_seconds must be positive, max_events_per_host at least 2, "
                "and max_hosts positive"
            )
        self._window = timedelta(seconds=window_seconds)
        self._max_events_per_host = max_events_per_host
        self._max_hosts = max_hosts
        self._baseline = baseline
        self._events: dict[str, deque[SecurityEvent]] = defaultdict(deque)
        self._emitted: set[tuple[str, str, tuple[str, ...]]] = set()
        self._emitted_order: deque[tuple[str, str, tuple[str, ...]]] = deque()

    def add(self, event: SecurityEvent) -> BehaviorSignal | None:
        if (
            event.source is not EventSource.WINDOWS
            or not event.host
            or event.windows_event_id is None
        ):
            return None
        observed_at = event.timestamp.astimezone(timezone.utc)
        if event.host not in self._events:
            if len(self._events) >= self._max_hosts:
                del self._events[next(iter(self._events))]
            self._events[event.host] = deque()
        events = self._events[event.host]
        newest_timestamp = max(
            (item.timestamp.astimezone(timezone.utc) for item in events),
            default=observed_at,
        )
        newest_timestamp = max(newest_timestamp, observed_at)
        cutoff = newest_timestamp - self._window
        retained = [
            item for item in events
            if item.timestamp.astimezone(timezone.utc) >= cutoff
        ]
        events.clear()
        events.extend(retained)
        if any(existing.event_id == event.event_id for existing in events):
            return None
        events.append(event)
        ordered = sorted(events, key=lambda item: item.timestamp.astimezone(timezone.utc))
        events.clear()
        events.extend(ordered)
        while len(events) > self._max_events_per_host:
            events.popleft()

        ids = {item.windows_event_id for item in events}
        baseline_score = 0
        baseline_context = None
        if self._baseline is not None:
            baseline_score, baseline_context = self._baseline.observe(event)
        suspicious = tuple(
            item for item in events if item.windows_event_id in self._SUSPICIOUS_IDS
        )
        if not suspicious or len(events) < 2:
            return None
        reasons: list[str] = []
        if 4624 in ids and 4688 in ids and (4698 in ids or 7045 in ids):
            rule = "logon-process-persistence"
            score = 75
            reasons.append("logon, process creation, and persistence events correlated")
            selected = tuple(
                item for item in events
                if item.windows_event_id in {4624, 4688, 4698, 7045}
            )
            explanation = (
                "A successful logon, process-creation record, and service or scheduled-task "
                "creation were observed on the same host within the review window."
            )
        else:
            selected = tuple(
                item for item in events
                if item.windows_event_id in self._SUSPICIOUS_IDS
                or item.windows_event_id in {4624, 4672}
            )
            if len({item.windows_event_id for item in selected}) < 2:
                return None
            rule = "multiple-sensitive-windows-events"
            score = min(90, 50 + 10 * (len(selected) - 1))
            reasons.append("multiple distinct sensitive event IDs correlated")
            explanation = (
                "Multiple security-sensitive Windows event types were observed on the same "
                "host within the review window; inspect the listed evidence before drawing "
                "a conclusion."
            )
        indicators = tuple(
            dict.fromkeys(
                indicator
                for item in selected
                for indicator in item.behavioral_indicators
            )
        )
        for indicator in indicators:
            if indicator == "encoded_or_obfuscated_script_marker":
                score += 15
                reasons.append("encoded or obfuscated script marker observed")
            elif indicator == "download_or_transfer_marker":
                score += 10
                reasons.append("download or transfer marker observed")
            elif indicator == "user_writable_or_staging_path_marker":
                score += 10
                reasons.append("user-writable or staging path marker observed")
            elif indicator == "credential_related_text_marker":
                score += 15
                reasons.append("credential-related text marker observed")
            elif indicator == "audit_or_log_management_marker":
                score += 20
                reasons.append("audit or log management marker observed")
            elif indicator == "task_or_service_marker":
                score += 10
                reasons.append("task or service marker observed")
        if baseline_score:
            score += baseline_score
            reasons.append("event combination is unusual for the local baseline")
        score = min(score, 100)
        evidence_ids = tuple(item.event_id for item in selected)
        signature = (event.host, rule, evidence_ids)
        if signature in self._emitted:
            return None
        self._emitted.add(signature)
        self._emitted_order.append(signature)
        if len(self._emitted_order) > 10_000:
            self._emitted.discard(self._emitted_order.popleft())
        return BehaviorSignal(
            timestamp=max(item.timestamp.astimezone(timezone.utc) for item in selected),
            host=event.host,
            score=score,
            event_ids=tuple(
                item.windows_event_id
                for item in selected
                if item.windows_event_id is not None
            ),
            evidence_event_ids=evidence_ids,
            explanation=explanation,
            confidence=0.55,
            reasons=tuple(dict.fromkeys(reasons)),
            behavioral_indicators=indicators,
            baseline_context=baseline_context,
        )
