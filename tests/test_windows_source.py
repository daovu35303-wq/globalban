import base64
import subprocess
import unittest
from unittest.mock import patch

from globalban.ingestion.windows_source import (
    _powershell_script,
    follow_windows_events,
    read_windows_events,
)


class WindowsSourceTests(unittest.TestCase):
    def test_query_is_bounded_and_uses_validated_channel_names(self):
        script = _powershell_script(["Security"], 60, 200)
        self.assertIn("-MaxEvents 200", script)
        self.assertIn("AddSeconds(-60)", script)
        self.assertIn("'Security'", script)
        spaced_script = _powershell_script(
            ["Microsoft-Windows-Windows Defender/Operational"], 60, 200
        )
        self.assertIn("'Microsoft-Windows-Windows Defender/Operational'", spaced_script)

    def test_rejects_unsafe_channel_before_starting_powershell(self):
        with patch("globalban.ingestion.windows_source.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "channel names"):
                read_windows_events(["Security'; Remove-Item C:\\*"], lookback_seconds=60)
        run.assert_not_called()

    def test_decodes_event_xml_and_reports_powershell_errors(self):
        xml_text = "<Event><System><EventID>4625</EventID></System></Event>"
        encoded = base64.b64encode(xml_text.encode()).decode()
        result = subprocess.CompletedProcess([], 0, stdout=encoded + "\n", stderr="")
        with patch(
            "globalban.ingestion.windows_source.subprocess.run", return_value=result
        ):
            self.assertEqual(read_windows_events(["Security"]), [xml_text])

        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="access denied")
        with patch(
            "globalban.ingestion.windows_source.subprocess.run", return_value=failed
        ):
            with self.assertLogs(
                "globalban.ingestion.windows_source", level="ERROR"
            ):
                with self.assertRaisesRegex(RuntimeError, "exit code 1"):
                    read_windows_events(["Security"])

    def test_follow_deduplicates_records(self):
        xml_text = "<Event><System><EventID>4625</EventID></System></Event>"
        with (
            patch(
                "globalban.ingestion.windows_source.read_windows_events",
                return_value=[xml_text],
            ),
            patch("globalban.ingestion.windows_source.time.sleep"),
        ):
            events = follow_windows_events(["Security"])
            self.assertEqual(next(events), xml_text)
            events.close()


if __name__ == "__main__":
    unittest.main()
