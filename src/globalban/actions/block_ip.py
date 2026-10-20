from __future__ import annotations

import hashlib
import platform
import subprocess
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from globalban.audit.logger import AuditLogger
from globalban.config import AppConfig
from globalban.models.decisions import ActionResult
from globalban.policy.guard import PolicyGuard


class BlockIPAction:
    """Request a narrowly scoped Windows Firewall rule, dry-run by default."""

    def __init__(
        self,
        config: AppConfig | None = None,
        audit_path: str | Path = "globalban-audit.jsonl",
        guard: PolicyGuard | None = None,
    ) -> None:
        self.config = config or AppConfig()
        self.audit = AuditLogger(audit_path)
        self.guard = guard or PolicyGuard(
            allowlist=self.config.allowlist,
            minimum_failures=self.config.failure_threshold,
            max_actions_per_hour=self.config.max_actions_per_hour,
        )
        if guard is None:
            now = datetime.now().astimezone()
            for timestamp in self.audit.recent_action_timestamps(
                now - timedelta(hours=1),
                {"block_dry_run", "block_intent", "rollback_intent"},
            ):
                self.guard.seed_action(timestamp)

    def apply(
        self,
        candidate_ip: str,
        evidence_count: int,
        approved: bool = False,
        dry_run: bool | None = None,
        now: datetime | None = None,
    ) -> ActionResult:
        effective_dry_run = self.config.dry_run if dry_run is None else dry_run
        if self.config.dry_run:
            effective_dry_run = True
        if not effective_dry_run and not self.config.execution_enabled:
            reason = "Real firewall execution is disabled by configuration."
            self.audit.record("block_denied", {"ip": candidate_ip, "reason": reason})
            return ActionResult("denied", reason)
        try:
            normalized_ip = str(ip_address(candidate_ip))
        except ValueError:
            normalized_ip = candidate_ip
        decision = self.guard.check_block(
            normalized_ip, evidence_count=evidence_count, approved=approved, now=now
        )
        if not decision.allowed:
            self.audit.record(
                "block_denied",
                {"ip": normalized_ip, "evidence_count": evidence_count, "reason": decision.reason},
            )
            return ActionResult("denied", decision.reason)
        if effective_dry_run:
            rule_name = self._rule_name(normalized_ip)
            self.audit.record(
                "block_dry_run",
                {"ip": normalized_ip, "evidence_count": evidence_count, "rule_name": rule_name},
            )
            return ActionResult("dry_run", "No firewall changes were made.", rule_name)
        if platform.system() != "Windows":
            reason = "Firewall execution is supported only on Windows."
            self.audit.record("block_denied", {"ip": normalized_ip, "reason": reason})
            return ActionResult("denied", reason)
        rule_name = self._rule_name(normalized_ip)
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={normalized_ip}",
            "enable=yes",
        ]
        self.audit.record(
            "block_intent",
            {"ip": normalized_ip, "evidence_count": evidence_count, "rule_name": rule_name},
        )
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=30, check=False, shell=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.audit.record(
                "block_failed", {"ip": normalized_ip, "rule_name": rule_name, "error": str(exc)}
            )
            return ActionResult("failed", f"Firewall command failed: {exc}", rule_name)
        if result.returncode != 0:
            reason = f"netsh failed with exit code {result.returncode}: {result.stderr.strip()}"
            self.audit.record(
                "block_failed", {"ip": normalized_ip, "rule_name": rule_name, "reason": reason}
            )
            return ActionResult("failed", reason, rule_name)
        self.audit.record(
            "block_applied",
            {"ip": normalized_ip, "evidence_count": evidence_count, "rule_name": rule_name},
        )
        return ActionResult("applied", "Firewall block rule was created.", rule_name)

    def rollback(
        self,
        candidate_ip: str,
        approved: bool = False,
        now: datetime | None = None,
    ) -> ActionResult:
        if self.config.dry_run or not self.config.execution_enabled:
            reason = "Real firewall execution is disabled by configuration."
            self.audit.record("rollback_denied", {"ip": candidate_ip, "reason": reason})
            return ActionResult("denied", reason)
        try:
            normalized_ip = str(ip_address(candidate_ip))
        except ValueError:
            reason = "The candidate is not a valid IP address."
            self.audit.record("rollback_denied", {"ip": candidate_ip, "reason": reason})
            return ActionResult("denied", reason)
        if not self.audit.has_unrolled_block(normalized_ip):
            reason = "No successful, unrolled GlobalBan block exists for this address."
            self.audit.record("rollback_denied", {"ip": normalized_ip, "reason": reason})
            return ActionResult("denied", reason)
        decision = self.guard.check_rollback(approved=approved, now=now)
        if not decision.allowed:
            self.audit.record("rollback_denied", {"ip": normalized_ip, "reason": decision.reason})
            return ActionResult("denied", decision.reason)
        if platform.system() != "Windows":
            reason = "Firewall rollback is supported only on Windows."
            self.audit.record("rollback_denied", {"ip": normalized_ip, "reason": reason})
            return ActionResult("denied", reason)
        rule_name = self._rule_name(normalized_ip)
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
        self.audit.record("rollback_intent", {"ip": normalized_ip, "rule_name": rule_name})
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=30, check=False, shell=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.audit.record(
                "rollback_failed",
                {"ip": normalized_ip, "rule_name": rule_name, "error": str(exc)},
            )
            return ActionResult("failed", f"Firewall rollback failed: {exc}", rule_name)
        if result.returncode != 0:
            reason = (
                f"netsh rollback failed with exit code {result.returncode}: "
                f"{result.stderr.strip()}"
            )
            self.audit.record(
                "rollback_failed", {"ip": normalized_ip, "rule_name": rule_name, "reason": reason}
            )
            return ActionResult("failed", reason, rule_name)
        self.audit.record("rollback_applied", {"ip": normalized_ip, "rule_name": rule_name})
        return ActionResult("applied", "Firewall block rule was removed.", rule_name)

    @staticmethod
    def _rule_name(candidate_ip: str) -> str:
        suffix = hashlib.sha256(candidate_ip.encode("ascii")).hexdigest()[:16]
        return f"GlobalBan-{suffix}"