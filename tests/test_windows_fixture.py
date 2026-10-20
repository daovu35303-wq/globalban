import unittest
import json
import tempfile
from pathlib import Path

from globalban.detection.baseline import BehaviorBaseline
from globalban.detection.context import EventContextBuilder, summarize_context
from globalban.detection.process_monitor import ProcessTree, parse_process_creation_xml
from globalban.evaluation.metrics import classification_metrics, evaluate_binary
from globalban.evaluation.atomic_catalog import load_atomic_catalog
from globalban.ingestion.windows_source import read_windows_export
from globalban.models.events import EventType


class WindowsFixtureTests(unittest.TestCase):
    def test_manifest_and_synthetic_windows_export_are_consistent(self):
        root = Path(__file__).resolve().parents[1]
        manifest = load_atomic_catalog(root / "datasets" / "atomic_evtx_manifest.json")
        events = list(read_windows_export(root / "datasets" / "windows_events.xmll"))
        self.assertEqual(len(manifest), 2)
        self.assertEqual([event.windows_event_id for event in events], [4625, 4625, 4624])
        self.assertEqual(
            [event.event_type for event in events],
            [EventType.LOGIN_FAILED, EventType.LOGIN_FAILED, EventType.LOGIN_SUCCEEDED],
        )
        self.assertTrue(all(event.source_ip in {"192.0.2.10", "198.51.100.20"} for event in events))

    def test_manifest_discloses_no_binary_evtx_is_supplied(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "datasets" / "atomic_evtx_manifest.json").read_text())
        self.assertFalse(manifest["evtx_artifacts_present"])
        self.assertEqual(manifest["provenance"], "synthetic")

    def test_labeled_metrics_are_descriptive_and_empty_input_is_undefined(self):
        metrics = classification_metrics(
            ["failed_login", "successful_login"],
            ["failed_login", "failed_login"],
        )
        self.assertEqual(metrics.sample_count, 2)
        self.assertEqual(metrics.correct_count, 1)
        self.assertEqual(metrics.accuracy, 0.5)
        self.assertIsNone(classification_metrics([], []).accuracy)

    def test_binary_metrics_require_explicit_boolean_labels(self):
        metrics = evaluate_binary(
            [True, True, False, False],
            [True, False, True, False],
        )
        self.assertEqual(
            (
                metrics.true_positive,
                metrics.false_positive,
                metrics.false_negative,
                metrics.true_negative,
            ),
            (1, 1, 1, 1),
        )
        self.assertEqual(metrics.f1, 0.5)
        self.assertEqual(evaluate_binary([], []).precision, 0.0)
        with self.assertRaisesRegex(ValueError, "booleans"):
            evaluate_binary([1], [True])

    def test_context_summarizes_counts_without_username_inference(self):
        events = list(
            read_windows_export(
                Path(__file__).resolve().parents[1] / "datasets" / "windows_events.xmll"
            )
        )
        context = summarize_context(events)
        self.assertEqual(context.event_count, 3)
        self.assertEqual(context.failure_count, 2)
        self.assertEqual(context.success_count, 1)
        self.assertEqual(context.sources, ("windows",))

    def test_process_monitor_extracts_names_only_as_context(self):
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>4688</EventID>
            <TimeCreated SystemTime="2025-01-02T03:04:00Z" /></System>
          <EventData><Data Name="NewProcessName">C:\\Windows\\System32\\notepad.exe</Data>
            <Data Name="CreatorProcessName">C:\\Windows\\explorer.exe</Data></EventData></Event>"""
        observation = parse_process_creation_xml(xml)
        self.assertEqual(observation.process_name, "C:\\Windows\\System32\\notepad.exe")
        self.assertEqual(
            observation.parent_process_name, "C:\\Windows\\explorer.exe"
        )
        self.assertIsNone(parse_process_creation_xml(xml.replace("4688", "4625")))

    def test_process_tree_builds_bounded_parent_chain_on_same_host(self):
        def process_event(pid, parent_pid, name, parent_name, host="fixture-host"):
            return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><Computer>{host}</Computer><EventID>4688</EventID>
                <TimeCreated SystemTime="2025-01-02T03:04:00Z" /></System>
              <EventData><Data Name="NewProcessId">0x{pid:x}</Data>
                <Data Name="ProcessId">0x{parent_pid:x}</Data>
                <Data Name="NewProcessName">{name}</Data>
                <Data Name="CreatorProcessName">{parent_name}</Data></EventData></Event>"""

        parent = parse_process_creation_xml(
            process_event(100, 10, "child.exe", "explorer.exe")
        )
        grandparent = parse_process_creation_xml(
            process_event(10, 1, "explorer.exe", "winlogon.exe")
        )
        tree = ProcessTree()
        tree.add(grandparent)
        tree.add(parent)
        self.assertEqual(tree.ancestry(parent), ("child.exe", "explorer.exe"))
        self.assertEqual(parent.process_id, 100)
        self.assertEqual(parent.parent_process_id, 10)

    def test_context_builder_expires_old_events_and_does_not_group_by_username(self):
        events = list(
            read_windows_export(
                Path(__file__).resolve().parents[1] / "datasets" / "windows_events.xmll"
            )
        )
        builder = EventContextBuilder(window_seconds=30)
        first = builder.add(events[0])
        second = builder.add(events[1])
        self.assertEqual(first.event_count, 1)
        self.assertEqual(second.event_count, 2)

    def test_windows_baseline_is_local_aggregated_and_persisted_without_hostnames(self):
        events = list(
            read_windows_export(
                Path(__file__).resolve().parents[1] / "datasets" / "windows_events.xmll"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "windows-baseline.json"
            baseline = BehaviorBaseline(path, warmup_events=2)
            self.assertEqual(baseline.observe(events[0])[0], 0)
            score, reason = baseline.observe(events[2])
            self.assertEqual(score, 10)
            self.assertIn("first observed", reason)
            stored = path.read_text(encoding="utf-8")
            self.assertNotIn("fixture-host", stored)
            restored = BehaviorBaseline(path, warmup_events=2)
            self.assertEqual(restored.observe(events[0])[0], 0)

    def test_windows_baseline_rejects_boolean_warmup_and_schema_version(self):
        with self.assertRaisesRegex(ValueError, "warmup_events"):
            BehaviorBaseline(warmup_events=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "windows-baseline.json"
            path.write_text(
                json.dumps({"schema_version": True, "total": 0, "counts": {}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "format"):
                BehaviorBaseline(path)

    def test_metrics_reject_unpaired_labels(self):
        with self.assertRaisesRegex(ValueError, "same number"):
            classification_metrics(["failed"], [])


if __name__ == "__main__":
    unittest.main()
