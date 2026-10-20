import unittest
from datetime import datetime, timezone

from globalban.ingestion.parser import (
    parse_ssh_log,
    parse_windows_event_fields,
    parse_windows_event_xml,
)
from globalban.models.events import EventSource, EventType


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime(2025, 1, 2, 3, 4, tzinfo=timezone.utc)

    def test_parses_failed_ssh_login(self):
        event = parse_ssh_log(
            "Failed password for invalid user admin from 192.0.2.10 port 41230 ssh2",
            self.timestamp,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.source, EventSource.SSH)
        self.assertEqual(event.event_type, EventType.LOGIN_FAILED)
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.timestamp, self.timestamp)

    def test_parses_pam_failure_count(self):
        event = parse_ssh_log(
            "PAM 6 more authentication failures; rhost=198.51.100.81 user=root",
            self.timestamp,
        )
        self.assertEqual(event.count, 6)
        self.assertEqual(event.source_ip, "198.51.100.81")

    def test_parses_success_and_ignores_unrelated_log(self):
        event = parse_ssh_log(
            "Accepted publickey for deploy from 203.0.113.7 port 33218 ssh2",
            self.timestamp,
        )
        self.assertEqual(event.event_type, EventType.LOGIN_SUCCEEDED)
        self.assertIsNone(parse_ssh_log("system started", self.timestamp))

    def test_normalizes_allowlisted_windows_event(self):
        event = parse_windows_event_fields(
            {"EventID": "4625", "IpAddress": "8.8.8.8", "TargetUserName": "ignored-locally"},
            self.timestamp,
        )
        self.assertEqual(event.source, EventSource.WINDOWS)
        self.assertEqual(event.event_type, EventType.LOGIN_FAILED)
        self.assertEqual(event.windows_event_id, 4625)
        self.assertEqual(event.source_ip, "8.8.8.8")
        self.assertIsNone(parse_windows_event_fields({"EventID": "1102"}, self.timestamp))

    def test_parses_windows_event_xml_and_discards_raw_content(self):
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/>
            <Computer>fixture-host</Computer><EventID>4625</EventID>
            <TimeCreated SystemTime="2025-01-02T03:04:00.000Z" /></System>
          <EventData><Data Name="IpAddress">8.8.4.4</Data>
            <Data Name="TargetUserName">user1</Data>
            <Data Name="CommandLine">must not be retained</Data></EventData></Event>"""
        event = parse_windows_event_xml(xml)
        self.assertEqual(event.source_ip, "8.8.4.4")
        self.assertEqual(event.timestamp, self.timestamp)
        self.assertEqual(event.host, "fixture-host")
        self.assertEqual(event.windows_provider, "Microsoft-Windows-Security-Auditing")
        self.assertNotIn("CommandLine", event.windows_fields)

    def test_parses_allowlisted_windows_activity_without_retaining_raw_xml(self):
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/>
            <Computer>fixture-host</Computer><EventID>4698</EventID>
            <TimeCreated SystemTime="2025-01-02T03:04:00.000Z" /></System>
          <EventData><Data Name="TargetUserName">fixture-user</Data>
            <Data Name="TaskContent">not retained</Data></EventData></Event>"""
        event = parse_windows_event_xml(xml)
        self.assertEqual(event.event_type, EventType.WINDOWS_ACTIVITY)
        self.assertEqual(event.windows_event_id, 4698)
        self.assertEqual(event.host, "fixture-host")
        self.assertEqual(dict(event.windows_fields), {"TargetUserName": "fixture-user"})

    def test_sensitive_command_text_is_reduced_to_indicator_tags(self):
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/>
            <Computer>fixture-host</Computer><EventID>4688</EventID>
            <TimeCreated SystemTime="2025-01-02T03:04:00.000Z" /></System>
          <EventData><Data Name="CommandLine">powershell.exe -EncodedCommand sample-token</Data>
            <Data Name="NewProcessName">C:\\Users\\fixture\\Temp\\worker.exe</Data></EventData></Event>"""
        event = parse_windows_event_xml(xml)
        self.assertIn("encoded_or_obfuscated_script_marker", event.behavioral_indicators)
        self.assertIn("user_writable_or_staging_path_marker", event.behavioral_indicators)
        self.assertNotIn("CommandLine", event.windows_fields)
        self.assertNotIn("sample-token", repr(event))

    def test_rejects_malformed_windows_xml_with_clear_error(self):
        with self.assertRaisesRegex(ValueError, "Invalid Windows Event XML"):
            parse_windows_event_xml("<Event>")


if __name__ == "__main__":
    unittest.main()