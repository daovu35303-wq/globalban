import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from globalban.main import main


def _event(event_id, seconds):
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="fixture-provider"/><Computer>fixture-host</Computer>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="2025-01-01T00:00:{seconds:02d}Z" /></System>
      <EventData><Data Name="ServiceName">fixture-service</Data></EventData></Event>"""


def _config(directory):
    path = Path(directory) / "config.yaml"
    path.write_text(
        json.dumps(
            {
                "baseline_path": None,
                "windows_baseline_path": None,
            }
        ),
        encoding="utf-8",
    )
    return path


class MainTests(unittest.TestCase):
    def test_windows_xml_batch_emits_review_signal_without_raw_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.xml"
            config_path = _config(directory)
            path.write_text(
                "<Events>" + _event(4698, 0) + _event(7045, 10) + "</Events>",
                encoding="utf-8",
            )
            output = StringIO()
            with redirect_stdout(output):
                result = main(
                    ["--config", str(config_path), "--windows-xml", str(path)]
                )

        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(result, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event_ids"], [4698, 7045])
        self.assertNotIn("fixture-service", output.getvalue())

    def test_live_polling_is_opt_in_and_uses_configured_channels(self):
        with patch(
            "globalban.main.follow_windows_events", return_value=iter(())
        ) as follow:
            with tempfile.TemporaryDirectory() as directory:
                config_path = _config(directory)
                result = main(
                    [
                        "--config",
                        str(config_path),
                        "--windows-live",
                        "--windows-channel",
                        "System",
                    ]
                )
        self.assertEqual(result, 0)
        follow.assert_called_once()
        self.assertEqual(follow.call_args.args[0], ["System"])

    def test_follow_ssh_live_is_explicit_and_reports_threshold_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "auth.log"
            log_path.write_text("", encoding="utf-8")
            config_path = _config(directory)
            with patch(
                "globalban.main.follow_file",
                return_value=iter(
                    [
                        "Failed password for alice from 8.8.8.8 port 1000 ssh2",
                        "Failed password for alice from 8.8.8.8 port 1001 ssh2",
                        "Failed password for alice from 8.8.8.8 port 1002 ssh2",
                        "Failed password for alice from 8.8.8.8 port 1003 ssh2",
                        "Failed password for alice from 8.8.8.8 port 1004 ssh2",
                    ]
                ),
            ) as follow:
                output = StringIO()
                with redirect_stdout(output):
                    result = main(
                        [
                            "--config",
                            str(config_path),
                            "--follow-ssh-log",
                            str(log_path),
                        ]
                    )
        self.assertEqual(result, 0)
        follow.assert_called_once()
        self.assertIn("8.8.8.8", output.getvalue())


if __name__ == "__main__":
    unittest.main()
