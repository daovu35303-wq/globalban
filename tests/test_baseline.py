import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from globalban.detection.baseline import LocalBaseline
from globalban.models.events import EventSource, EventType, SecurityEvent


class BaselineTests(unittest.TestCase):
    def event(self, day, count=1):
        return SecurityEvent(
            event_id=f"event-{day}",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(days=day),
            source=EventSource.SSH,
            event_type=EventType.LOGIN_FAILED,
            source_ip="8.8.8.8",
            count=count,
        )

    def test_local_baseline_requires_history_and_reports_elevation(self):
        baseline = LocalBaseline(minimum_history_days=7)
        self.assertIn("not established", baseline.observe_failure(self.event(0)))
        for day in range(1, 7):
            baseline.observe_failure(self.event(day))
        context = baseline.observe_failure(self.event(7, count=5))
        self.assertIn("above", context)
        self.assertIn("7 prior active days", context)

    def test_persists_only_local_daily_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            LocalBaseline(path).observe_failure(self.event(0, count=3))
            restored = LocalBaseline(path)
            context = restored.describe("8.8.8.8", self.event(1).timestamp.date())
        self.assertIn("today's local count is 0", context)


if __name__ == "__main__":
    unittest.main()
