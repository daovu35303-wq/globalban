from __future__ import annotations

from datetime import datetime
from pathlib import Path

from globalban.actions.enforcer import ActionEnforcer
from globalban.config import AppConfig
from globalban.models.decisions import ActionResult, DetectionAlert
from globalban.policy.guard import PolicyGuard


class PolicyGate:
    """Only entry point for alert-driven action requests; delegates all checks to enforcer."""

    def __init__(
        self,
        config: AppConfig | None = None,
        audit_path: str | Path = "globalban-audit.jsonl",
        guard: PolicyGuard | None = None,
    ) -> None:
        self.enforcer = ActionEnforcer(config, audit_path, guard)

    def request_block(
        self,
        alert: DetectionAlert,
        approved: bool = False,
        dry_run: bool | None = None,
        now: datetime | None = None,
    ) -> ActionResult:
        return self.enforcer.request_block(alert, approved, dry_run, now)
