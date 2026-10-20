import unittest
from datetime import datetime, timedelta, timezone

from globalban.detection.sequence import (
    WindowsSequenceDetector,
    detect_failure_then_success,
)
from globalban.models.events import EventSource, EventType, SecurityEvent


class SequenceTests(unittest.TestCase):
    def test_reports_failures_followed_by_success_as_review_signal(self):
        origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = [
            SecurityEvent("f1", origin, EventSource.SSH, EventType.LOGIN_FAILED, "8.8.8.8"),
            SecurityEvent(
                "f2", origin + timedelta(seconds=10), EventSource.WINDOWS,
                EventType.LOGIN_FAILED, "8.8.8.8",
            ),
            SecurityEvent(
                "s1", origin + timedelta(seconds=20), EventSource.SSH,
                EventType.LOGIN_SUCCEEDED, "8.8.8.8",
            ),
        ]
        signals = detect_failure_then_success(events)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].failure_event_ids, ("f1", "f2"))
        self.assertIn("does not establish", signals[0].explanation)
        self.assertEqual(signals[0].confidence, 0.55)

    def test_does_not_correlate_different_addresses_or_expired_failures(self):
        origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = [
            SecurityEvent("f1", origin, EventSource.SSH, EventType.LOGIN_FAILED, "8.8.8.8"),
            SecurityEvent(
                "f2", origin + timedelta(seconds=1), EventSource.SSH,
                EventType.LOGIN_FAILED, "8.8.8.8",
            ),
            SecurityEvent(
                "s1", origin + timedelta(seconds=400), EventSource.SSH,
                EventType.LOGIN_SUCCEEDED, "8.8.8.8",
            ),
        ]
        self.assertEqual(detect_failure_then_success(events, window_seconds=60), [])

    def test_windows_sequence_requires_multiple_events_on_same_host(self):
        origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
        detector = WindowsSequenceDetector()

        def windows_event(event_id, seconds, host="fixture-host"):
            return SecurityEvent(
                f"e{event_id}-{seconds}",
                origin + timedelta(seconds=seconds),
                EventSource.WINDOWS,
                EventType.WINDOWS_ACTIVITY,
                windows_event_id=event_id,
                host=host,
            )

        self.assertIsNone(detector.add(windows_event(4698, 0)))
        self.assertIsNone(detector.add(windows_event(4698, 1, "other-host")))
        signal = detector.add(windows_event(7045, 2))
        self.assertIsNotNone(signal)
        self.assertEqual(signal.event_ids, (4698, 7045))
        self.assertIn("inspect", signal.explanation)
        self.assertIsNone(detector.add(windows_event(7045, 2)))

    def test_windows_sequence_does_not_signal_on_single_sensitive_event(self):
        origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
        detector = WindowsSequenceDetector()
        event = SecurityEvent(
            "single",
            origin,
            EventSource.WINDOWS,
            EventType.WINDOWS_ACTIVITY,
            windows_event_id=1102,
            host="fixture-host",
        )
        self.assertIsNone(detector.add(event))

    def test_windows_sequence_requires_distinct_sensitive_event_types(self):
        origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
        detector = WindowsSequenceDetector()
        first = SecurityEvent(
            "clear-1",
            origin,
            EventSource.WINDOWS,
            EventType.WINDOWS_ACTIVITY,
            windows_event_id=1102,
            host="fixture-host",
        )
        second = SecurityEvent(
            "clear-2",
            origin + timedelta(seconds=1),
            EventSource.WINDOWS,
            EventType.WINDOWS_ACTIVITY,
            windows_event_id=1102,
            host="fixture-host",
        )
        self.assertIsNone(detector.add(first))
        self.assertIsNone(detector.add(second))


if __name__ == "__main__":
    unittest.main()
