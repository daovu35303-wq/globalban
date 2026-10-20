from __future__ import annotations

from globalban.config import AppConfig
from globalban.dashboard.app import run_dashboard


def run(config: AppConfig | None = None) -> None:
    """Start the local desktop dashboard."""
    run_dashboard(config or AppConfig())
