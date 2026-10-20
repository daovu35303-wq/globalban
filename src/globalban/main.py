from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from globalban.agent.router import ToolPlan, choose_tools
from globalban.config import AppConfig, load_config
from globalban.detection.aggregator import EventAggregator
from globalban.detection.baseline import BehaviorBaseline, LocalBaseline
from globalban.detection.sequence import WindowsSequenceDetector
from globalban.ingestion.parser import parse_ssh_log, parse_windows_event_xml
from globalban.ingestion.tailer import (
    follow_file,
    read_ssh_events,
    read_windows_event_export,
)
from globalban.ingestion.windows_source import follow_windows_events
from globalban.models.events import SecurityEvent

logger = logging.getLogger(__name__)


def _load_events(args: argparse.Namespace) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    if args.ssh_log is not None:
        events.extend(read_ssh_events(args.ssh_log))
    if args.windows_xml is not None:
        events.extend(read_windows_event_export(args.windows_xml))
    return sorted(events, key=lambda event: event.timestamp_utc)


def _aggregator(config: AppConfig) -> EventAggregator:
    baseline = LocalBaseline(config.baseline_path)
    return EventAggregator(
        threshold=config.failure_threshold,
        window_seconds=config.correlation_window_seconds,
        baseline=baseline,
    )


def _windows_sequence(config: AppConfig) -> WindowsSequenceDetector:
    baseline = BehaviorBaseline(
        config.windows_baseline_path,
        warmup_events=config.baseline_warmup_events,
    )
    return WindowsSequenceDetector(
        window_seconds=config.correlation_window_seconds,
        baseline=baseline,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GlobalBan defensive security event monitor")
    parser.add_argument("--config", type=Path, help="Path to JSON-compatible YAML configuration")
    parser.add_argument("--ssh-log", type=Path, help="Read an SSH auth log file")
    parser.add_argument("--windows-xml", type=Path, help="Read a Windows Event Viewer XML export")
    parser.add_argument(
        "--follow-ssh-log",
        type=Path,
        help="Explicitly follow an SSH auth log from its current end",
    )
    parser.add_argument(
        "--windows-live",
        action="store_true",
        help="Explicitly poll Windows Event Log channels (does not change audit settings)",
    )
    parser.add_argument(
        "--windows-channel",
        action="append",
        dest="windows_channels",
        help="Windows channel to poll; repeat to select multiple (default: Security)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Polling interval in seconds for --windows-live",
    )
    parser.add_argument(
        "--lookback-seconds",
        type=int,
        default=60,
        help="Bounded event lookback window for --windows-live",
    )
    args = parser.parse_args(argv)
    config = load_config(args.config) if args.config else AppConfig()
    live_modes = sum((args.windows_live, args.follow_ssh_log is not None))
    if live_modes > 1:
        parser.error("only one live input mode can be selected")
    if live_modes and (args.ssh_log is not None or args.windows_xml is not None):
        parser.error("live monitoring cannot be combined with file input options")
    if args.follow_ssh_log is not None:
        _run_ssh_live(
            args.follow_ssh_log,
            _aggregator(config),
            args.poll_interval,
        )
        return 0
    if args.windows_live:
        _run_windows_live(
            _aggregator(config),
            _windows_sequence(config),
            args.windows_channels or list(config.windows_event_channels),
            args.poll_interval,
            args.lookback_seconds,
        )
        return 0
    if args.windows_channels is not None:
        parser.error("--windows-channel requires --windows-live")
    if args.ssh_log is None and args.windows_xml is None:
        from globalban.dashboard.app import run_dashboard

        run_dashboard(config)
        return 0
    aggregator = _aggregator(config)
    sequence = _windows_sequence(config)
    alerts = []
    signals = []
    for event in _load_events(args):
        alert = aggregator.ingest(event)
        if alert is not None:
            alerts.append(alert)
        signal = sequence.add(event)
        if signal is not None:
            signals.append((signal, event))
    for alert in alerts:
        print(
            json.dumps(
                {
                    "rule_id": alert.rule_id,
                    "source_ip": alert.source_ip,
                    "failure_count": alert.failure_count,
                    "evidence_event_ids": alert.evidence_event_ids,
                    "explanation": alert.explanation,
                    "confidence": alert.confidence,
                    "baseline_context": alert.baseline_context,
                },
                sort_keys=True,
            )
        )
    for signal, event in signals:
        print(
            json.dumps(
                {
                    "rule_id": "WINDOWS-" + "-".join(map(str, signal.event_ids)),
                    "host": signal.host,
                    "event_ids": signal.event_ids,
                    "evidence_event_ids": signal.evidence_event_ids,
                    "score": signal.score,
                    "explanation": signal.explanation,
                    "confidence": signal.confidence,
                    "timestamp": signal.timestamp.isoformat(),
                    "reasons": signal.reasons,
                    "behavioral_indicators": signal.behavioral_indicators,
                    "baseline_context": signal.baseline_context,
                    **_tool_plan_json(choose_tools([event], risk_score=signal.score)),
                },
                sort_keys=True,
            )
        )
    if not alerts and not signals:
        print("No correlation rules triggered; this is not proof that activity was benign.")
    return 0


def _run_windows_live(
    aggregator: EventAggregator,
    sequence: WindowsSequenceDetector,
    channels: list[str],
    poll_interval_seconds: float,
    lookback_seconds: int,
) -> None:
    logger.info(
        "Starting explicit Windows Event Log polling for configured channels: %s",
        ", ".join(channels),
    )
    try:
        for xml_text in follow_windows_events(
            channels,
            poll_interval_seconds=poll_interval_seconds,
            lookback_seconds=lookback_seconds,
        ):
            event = parse_windows_event_xml(xml_text)
            if event is None:
                continue
            alert = aggregator.ingest(event)
            if alert is not None:
                print(
                    json.dumps(
                        {
                            "rule_id": alert.rule_id,
                            "source_ip": alert.source_ip,
                            "failure_count": alert.failure_count,
                            "evidence_event_ids": alert.evidence_event_ids,
                            "explanation": alert.explanation,
                            "confidence": alert.confidence,
                            "baseline_context": alert.baseline_context,
                        },
                        sort_keys=True,
                    )
                )
            signal = sequence.add(event)
            if signal is not None:
                print(
                    json.dumps(
                        {
                            "rule_id": "WINDOWS-" + "-".join(map(str, signal.event_ids)),
                            "host": signal.host,
                            "event_ids": signal.event_ids,
                            "evidence_event_ids": signal.evidence_event_ids,
                            "score": signal.score,
                            "explanation": signal.explanation,
                            "confidence": signal.confidence,
                            "timestamp": signal.timestamp.isoformat(),
                            "reasons": signal.reasons,
                            "behavioral_indicators": signal.behavioral_indicators,
                            "baseline_context": signal.baseline_context,
                            **_tool_plan_json(
                                choose_tools([event], risk_score=signal.score)
                            ),
                        },
                        sort_keys=True,
                    )
                )
    except KeyboardInterrupt:
        logger.info("Windows Event Log polling stopped by operator")


def _tool_plan_json(plan: ToolPlan) -> dict[str, object]:
    return {
        "tools": plan.tools,
        "attack_hypotheses": plan.attack_hypotheses,
        "mitre_attack": plan.mitre_attack,
        "tool_plan_reasons": plan.reasons,
        "behavioral_indicators": plan.behavioral_indicators,
        "requires_approval": plan.requires_approval,
    }


def _run_ssh_live(
    path: Path,
    aggregator: EventAggregator,
    poll_interval_seconds: float,
) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"SSH authentication log does not exist: {path}")
    logger.info("Following SSH auth log from current end: %s", path)
    try:
        for line in follow_file(
            path,
            poll_interval_seconds=poll_interval_seconds,
            start_at_end=True,
        ):
            event = parse_ssh_log(line)
            if event is None:
                continue
            alert = aggregator.ingest(event)
            if alert is not None:
                print(
                    json.dumps(
                        {
                            "rule_id": alert.rule_id,
                            "source_ip": alert.source_ip,
                            "failure_count": alert.failure_count,
                            "evidence_event_ids": alert.evidence_event_ids,
                            "explanation": alert.explanation,
                            "confidence": alert.confidence,
                            "baseline_context": alert.baseline_context,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
    except KeyboardInterrupt:
        logger.info("SSH log following stopped by operator")


if __name__ == "__main__":
    raise SystemExit(main())