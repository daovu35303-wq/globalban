from __future__ import annotations

from datetime import datetime
from pathlib import Path

from globalban.actions.block_ip import BlockIPAction
from globalban.config import AppConfig
from globalban.models.decisions import ActionResult, DetectionAlert
from globalban.policy.guard import PolicyGuard


class ActionEnforcer:
    """Route only a detection alert to the existing guarded block action."""

    def __init__(
        self,
        config: AppConfig | None = None,
        audit_path: str | Path = "globalban-audit.jsonl",
        guard: PolicyGuard | None = None,
    ) -> None:
        self.action = BlockIPAction(config=config, audit_path=audit_path, guard=guard)

    def request_block(
        self,
        alert: DetectionAlert,
        approved: bool = False,
        dry_run: bool | None = None,
        now: datetime | None = None,
    ) -> ActionResult:
        return self.action.apply(
            alert.source_ip,
            evidence_count=alert.failure_count,
            approved=approved,
            dry_run=dry_run,
            now=now,
        )
