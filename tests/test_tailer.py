import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from globalban.ingestion.tailer import follow_file, read_windows_event_export


EVENT = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4625</EventID>
    <TimeCreated SystemTime="2025-01-02T03:04:00.000Z" /></System>
  <EventData><Data Name="IpAddress">8.8.8.8</Data></EventData></Event>"""


class TailerTests(unittest.TestCase):
    def test_reads_event_container_and_single_event_exports(self):
        for xml in (f"<Events>{EVENT}</Events>", EVENT):
            with self.subTest(root=xml[:8]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "events.xml"
                path.write_text(xml, encoding="utf-8")
                events = list(read_windows_event_export(path))
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].source_ip, "8.8.8.8")

    def test_rejects_document_types_and_malformed_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.xml"
            path.write_text("<!DOCTYPE Event><Events />", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "document types"):
                list(read_windows_event_export(path))
            path.write_text("<Events>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid Windows Event XML"):
                list(read_windows_event_export(path))

    def test_reads_utf16_event_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.xml"
            path.write_text(f"<Events>{EVENT}</Events>", encoding="utf-16")
            self.assertEqual(len(list(read_windows_event_export(path))), 1)

    def test_follow_file_reads_from_beginning_when_requested_and_closes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("first event\nsecond event\n", encoding="utf-8")
            with patch("globalban.ingestion.tailer.time.sleep"):
                follower = follow_file(
                    path,
                    poll_interval_seconds=0.01,
                    start_at_end=False,
                )
                self.assertEqual(next(follower), "first event\n")
                self.assertEqual(next(follower), "second event\n")
                follower.close()

    def test_follow_file_rejects_non_finite_poll_intervals(self):
        follower = follow_file("not-opened.log", poll_interval_seconds=float("inf"))
        with self.assertRaisesRegex(ValueError, "finite positive"):
            next(follower)


if __name__ == "__main__":
    unittest.main()
