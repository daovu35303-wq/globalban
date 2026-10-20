from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Iterable
from datetime import timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from globalban.agent.router import choose_tools
from globalban.config import AppConfig
from globalban.detection.aggregator import EventAggregator
from globalban.detection.baseline import BehaviorBaseline, LocalBaseline
from globalban.detection.sequence import WindowsSequenceDetector
from globalban.ingestion.tailer import read_ssh_events, read_windows_event_export
from globalban.models.events import SecurityEvent


class GlobalBanDashboard:
    def __init__(self, root: tk.Tk, config: AppConfig) -> None:
        self.root = root
        self.root.title("GlobalBan - Security Event Monitor")
        self.root.geometry("1000x650")
        self.aggregator = EventAggregator(
            threshold=config.failure_threshold,
            window_seconds=config.correlation_window_seconds,
            baseline=LocalBaseline(config.baseline_path),
        )
        self.sequence = WindowsSequenceDetector(
            window_seconds=config.correlation_window_seconds,
            baseline=BehaviorBaseline(
                config.windows_baseline_path,
                warmup_events=config.baseline_warmup_events,
            ),
        )
        self._build_ui()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root, padding=8)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Load SSH log", command=self.load_ssh).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Load Windows XML", command=self.load_windows).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Label(
            toolbar,
            text="Local monitoring only; firewall actions are not available in this dashboard.",
        ).pack(side=tk.RIGHT)

        events_frame = ttk.LabelFrame(self.root, text="Normalized events", padding=8)
        events_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        columns = ("time", "source", "event", "source_ip", "count")
        self.events = ttk.Treeview(events_frame, columns=columns, show="headings")
        headings = {
            "time": "UTC time",
            "source": "Source",
            "event": "Event",
            "source_ip": "Source IP (local)",
            "count": "Count",
        }
        for column, heading in headings.items():
            self.events.heading(column, text=heading)
        self.events.column("time", width=180)
        self.events.column("source", width=90)
        self.events.column("event", width=170)
        self.events.column("source_ip", width=160)
        self.events.column("count", width=70)
        self.events.pack(fill=tk.BOTH, expand=True)

        alerts_frame = ttk.LabelFrame(self.root, text="Explainable alerts", padding=8)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.alerts = tk.Listbox(alerts_frame, height=8)
        self.alerts.pack(fill=tk.BOTH, expand=True)

    def load_ssh(self) -> None:
        path = filedialog.askopenfilename(
            title="Select SSH authentication log",
            filetypes=(("Log files", "*.log *.txt"), ("All files", "*.*")),
        )
        if path:
            self._load(path, read_ssh_events)

    def load_windows(self) -> None:
        path = filedialog.askopenfilename(
            title="Select exported Windows Event XML",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*")),
        )
        if path:
            self._load(path, read_windows_event_export)

    def _load(
        self,
        path: str,
        reader: Callable[[str | Path], Iterable[SecurityEvent]],
    ) -> None:
        try:
            events = list(reader(path))
            self._add_events(events)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Unable to load events", str(exc), parent=self.root)

    def _add_events(self, events: list[SecurityEvent]) -> None:
        for event in events:
            self.events.insert(
                "",
                tk.END,
                values=(
                    event.timestamp.astimezone(timezone.utc).isoformat(timespec="seconds"),
                    event.source.value,
                    event.event_type.value,
                    event.source_ip or "not available",
                    event.count,
                ),
            )
            alert = self.aggregator.ingest(event)
            if alert is not None:
                self.alerts.insert(
                    tk.END,
                    (
                        f"{alert.rule_id} | {alert.source_ip} | "
                        f"{alert.failure_count} failures | confidence {alert.confidence:.0%} | "
                        f"{alert.explanation} {alert.baseline_context}"
                    ),
                )
            signal = self.sequence.add(event)
            if signal is not None:
                plan = choose_tools([event], risk_score=signal.score)
                self.alerts.insert(
                    tk.END,
                    (
                        f"WINDOWS-{','.join(map(str, signal.event_ids))} | "
                        f"score {signal.score} | confidence {signal.confidence:.0%} | "
                        f"{signal.explanation} Suggested tools: {', '.join(plan.tools)}. "
                        "No tool is executed automatically."
                    ),
                )


def run_dashboard(config: AppConfig) -> None:
    root = tk.Tk()
    GlobalBanDashboard(root, config)
    root.mainloop()
