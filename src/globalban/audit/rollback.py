from __future__ import annotations

from datetime import datetime

from globalban.actions.block_ip import BlockIPAction
from globalban.models.decisions import ActionResult


def rollback_block(
    action: BlockIPAction,
    address: str,
    approved: bool = False,
    now: datetime | None = None,
) -> ActionResult:
    """Delegate rollback to the audited action boundary and its policy checks."""
    return action.rollback(address, approved=approved, now=now)
