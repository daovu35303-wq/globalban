import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from globalban.actions.block_ip import BlockIPAction
from globalban.audit.rollback import rollback_block
from globalban.config import AppConfig


class BlockIPTests(unittest.TestCase):
    def test_default_mode_is_dry_run_and_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            action = BlockIPAction(audit_path=audit_path)
            result = action.apply("8.8.8.8", evidence_count=5, approved=True)
            self.assertEqual(result.status, "dry_run")
            record = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(record["action"], "block_dry_run")

    def test_requires_approval_and_rejects_private_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            action = BlockIPAction(audit_path=Path(directory) / "audit.jsonl")
            self.assertEqual(action.apply("8.8.8.8", 5).status, "denied")
            self.assertEqual(action.apply("192.168.1.2", 5, approved=True).status, "denied")

    def test_real_execution_requires_explicit_opt_in_and_uses_fixed_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            config = AppConfig(dry_run=False, execution_enabled=True)
            action = BlockIPAction(config, Path(directory) / "audit.jsonl")
            completed = type("Completed", (), {"returncode": 0, "stderr": ""})()
            with patch("globalban.actions.block_ip.platform.system", return_value="Windows"):
                with (
                    patch(
                        "globalban.actions.block_ip.windows_executable_path",
                        return_value=r"C:\Windows\System32\netsh.exe",
                    ),
                    patch(
                        "globalban.actions.block_ip.subprocess.run",
                        return_value=completed,
                    ) as run,
                ):
                    result = action.apply("8.8.8.8", 5, approved=True, dry_run=False)
            self.assertEqual(result.status, "applied")
            args, kwargs = run.call_args
            self.assertEqual(
                args[0][0:5],
                [
                    r"C:\Windows\System32\netsh.exe",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                ],
            )
            self.assertFalse(kwargs["shell"])

    def test_rollback_requires_approval_and_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            action = BlockIPAction(audit_path=Path(directory) / "audit.jsonl")
            self.assertEqual(action.rollback("8.8.8.8").status, "denied")
            self.assertEqual(action.rollback("8.8.8.8", approved=True).status, "denied")
            self.assertEqual(rollback_block(action, "8.8.8.8").status, "denied")

    def test_rollback_only_removes_audited_globalban_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            config = AppConfig(dry_run=False, execution_enabled=True)
            action = BlockIPAction(config, Path(directory) / "audit.jsonl")
            completed = type("Completed", (), {"returncode": 0, "stderr": ""})()
            with patch("globalban.actions.block_ip.platform.system", return_value="Windows"):
                with (
                    patch(
                        "globalban.actions.block_ip.windows_executable_path",
                        return_value=r"C:\Windows\System32\netsh.exe",
                    ),
                    patch(
                        "globalban.actions.block_ip.subprocess.run",
                        return_value=completed,
                    ) as run,
                ):
                    applied = action.apply("8.8.8.8", 5, approved=True, dry_run=False)
                    rolled_back = action.rollback("8.8.8.8", approved=True)
            self.assertEqual(applied.status, "applied")
            self.assertEqual(rolled_back.status, "applied")
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args.args[0][3], "delete")
            self.assertEqual(action.rollback("8.8.8.8", approved=True).status, "denied")

    def test_rate_limit_survives_action_object_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            config = AppConfig(
                max_actions_per_hour=1,
                dry_run=False,
                execution_enabled=True,
            )
            completed = type("Completed", (), {"returncode": 0, "stderr": ""})()
            with patch("globalban.actions.block_ip.platform.system", return_value="Windows"):
                with (
                    patch(
                        "globalban.actions.block_ip.windows_executable_path",
                        return_value=r"C:\Windows\System32\netsh.exe",
                    ),
                    patch(
                        "globalban.actions.block_ip.subprocess.run",
                        return_value=completed,
                    ),
                ):
                    first = BlockIPAction(config, audit_path)
                    self.assertEqual(
                        first.apply("8.8.8.8", 5, approved=True, dry_run=False).status,
                        "applied",
                    )
                    restarted = BlockIPAction(config, audit_path)
                    second = restarted.apply(
                        "1.1.1.1", 5, approved=True, dry_run=False
                    )
            self.assertEqual(second.status, "denied")
            self.assertIn("rate limit", second.reason)


if __name__ == "__main__":
    unittest.main()