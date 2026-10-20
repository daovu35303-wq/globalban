import unittest
from datetime import datetime, timedelta, timezone

from globalban.detection.aggregator import EventAggregator
from globalban.models.events import EventSource, EventType, SecurityEvent


class AggregatorTests(unittest.TestCase):
    def event(self, event_id, seconds, event_type=EventType.LOGIN_FAILED, count=1):
        return SecurityEvent(
            event_id=event_id,
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
            source=EventSource.SSH,
            event_type=event_type,
            source_ip="8.8.8.8",
            count=count,
        )

    def test_correlates_distinct_failures_and_explains_alert(self):
        aggregator = EventAggregator(threshold=3, window_seconds=60)
        self.assertIsNone(aggregator.ingest(self.event("one", 0)))
        self.assertIsNone(aggregator.ingest(self.event("two", 10)))
        alert = aggregator.ingest(self.event("three", 20))
        self.assertEqual(alert.rule_id, "AUTH-FAILURE-BURST")
        self.assertEqual(alert.failure_count, 3)
        self.assertEqual(len(alert.evidence_event_ids), 3)
        self.assertIn("not proof", alert.explanation)
        self.assertEqual(alert.confidence, 0.65)

    def test_single_aggregated_log_line_does_not_raise_alert(self):
        aggregator = EventAggregator(threshold=5, window_seconds=60)
        self.assertIsNone(aggregator.ingest(self.event("summary", 0, count=6)))
        alert = aggregator.ingest(self.event("follow-up", 1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.failure_count, 7)

    def test_success_does_not_contribute_to_failures(self):
        aggregator = EventAggregator(threshold=2, window_seconds=60)
        self.assertIsNone(
            aggregator.ingest(self.event("success", 0, EventType.LOGIN_SUCCEEDED))
        )
        self.assertIsNone(aggregator.ingest(self.event("failure", 1)))

    def test_expired_window_allows_a_new_alert(self):
        aggregator = EventAggregator(threshold=2, window_seconds=10)
        aggregator.ingest(self.event("first", 0))
        first_alert = aggregator.ingest(self.event("second", 1))
        self.assertIsNotNone(first_alert)
        aggregator.ingest(self.event("later-one", 20))
        later_alert = aggregator.ingest(self.event("later-two", 21))
        self.assertIsNotNone(later_alert)


if __name__ == "__main__":
    unittest.main()