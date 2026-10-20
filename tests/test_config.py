import json
import tempfile
import unittest
from pathlib import Path

from globalban.config import AppConfig, load_config


class ConfigTests(unittest.TestCase):
    def test_defaults_are_safe(self):
        config = AppConfig()
        self.assertTrue(config.dry_run)
        self.assertFalse(config.execution_enabled)

    def test_checked_in_example_is_loadable_and_safe(self):
        config = load_config(Path("config") / "config.example.yaml")
        self.assertTrue(config.dry_run)
        self.assertFalse(config.execution_enabled)
        self.assertEqual(config.failure_threshold, 5)

    def test_loads_supported_json_yaml_subset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                json.dumps(
                    {
                        "failure_threshold": 6,
                        "correlation_window_seconds": 120,
                        "max_actions_per_hour": 2,
                        "allowlist": ["10.0.0.0/8"],
                        "baseline_path": None,
                        "windows_event_channels": [
                            "Security",
                            "Microsoft-Windows-Windows Defender/Operational",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(config.failure_threshold, 6)
        self.assertIsNone(config.baseline_path)
        self.assertTrue(config.dry_run)
        self.assertEqual(
            config.windows_event_channels,
            ("Security", "Microsoft-Windows-Windows Defender/Operational"),
        )

    def test_rejects_unknown_keys_and_inconsistent_execution_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text('{"unexpected": true}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unknown configuration"):
                load_config(path)
        with self.assertRaisesRegex(ValueError, "execution_enabled"):
            AppConfig(dry_run=True, execution_enabled=True)
        with self.assertRaisesRegex(ValueError, "allowlist entry"):
            AppConfig(allowlist=("not-a-network",))
        with self.assertRaisesRegex(ValueError, "failure_threshold"):
            AppConfig(failure_threshold=5.0)
        with self.assertRaisesRegex(ValueError, "channel names"):
            AppConfig(windows_event_channels=("Security; exit",))


if __name__ == "__main__":
    unittest.main()
