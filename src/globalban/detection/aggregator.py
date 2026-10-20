from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from globalban.detection.baseline import LocalBaseline
from globalban.models.decisions import DetectionAlert
from globalban.models.events import EventType, SecurityEvent


class EventAggregator:
    """Correlate failed logins by source address without using usernames or process names."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,
        baseline: LocalBaseline | None = None,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.baseline = baseline or LocalBaseline()
        self._failures: dict[str, deque[tuple[datetime, str, int]]] = defaultdict(deque)
        self._active_alerts: set[str] = set()

    def ingest(self, event: SecurityEvent) -> DetectionAlert | None:
        if event.event_type is not EventType.LOGIN_FAILED or event.source_ip is None:
            return None
        address = str(ip_address(event.source_ip))
        timestamp = event.timestamp.astimezone(timezone.utc)
        baseline_context = self.baseline.observe_failure(event)
        events = self._failures[address]
        cutoff = timestamp - self.window
        while events and events[0][0] < cutoff:
            events.popleft()
        previous_count = sum(count for _, _, count in events)
        if previous_count < self.threshold:
            self._active_alerts.discard(address)
        events.append((timestamp, event.event_id, event.count))
        current_count = previous_count + event.count
        if (
            current_count >= self.threshold
            and len(events) >= 2
            and address not in self._active_alerts
        ):
            self._active_alerts.add(address)
            evidence = tuple(event_id for _, event_id, _ in events)
            return DetectionAlert(
                alert_id=f"ssh-windows-failure-burst:{address}:{timestamp.isoformat()}",
                timestamp=timestamp,
                source_ip=address,
                rule_id="AUTH-FAILURE-BURST",
                explanation=(
                    f"{current_count} failed authentication attempts from this address "
                    f"were correlated within {int(self.window.total_seconds())} seconds. "
                    "This is a review signal, not proof of identity or intent."
                ),
                evidence_event_ids=evidence,
                failure_count=current_count,
                confidence=0.65,
                baseline_context=baseline_context,
            )
        return None