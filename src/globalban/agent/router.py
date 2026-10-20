from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from globalban.agent.tools import AllowlistedTools
from globalban.models.decisions import BehaviorSignal, DetectionAlert
from globalban.models.events import EventSource, EventType, SecurityEvent


@dataclass(frozen=True, slots=True)
class ToolPlan:
    """Static investigation suggestions; a plan is never an execution request."""

    attack_hypotheses: tuple[str, ...]
    tools: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    requires_approval: bool
    reasons: tuple[str, ...]
    behavioral_indicators: tuple[str, ...]


TOOL_NAMES = (
    "log_ingestion_parser",
    "process_monitor",
    "security_event_collector",
    "behavioral_context_builder",
    "anomaly_detection_engine",
    "threat_intelligence_lookup",
    "privacy_masking_proxy",
    "ai_decision_engine",
    "policy_gate",
    "action_enforcer",
    "audit_rollback_manager",
    "evaluation_reporting",
)


def choose_tools(
    events: tuple[SecurityEvent, ...] | list[SecurityEvent],
    *,
    risk_score: int = 0,
) -> ToolPlan:
    """Select a fixed tool plan from normalized evidence without executing tools."""
    if (
        not isinstance(risk_score, int)
        or isinstance(risk_score, bool)
        or not 0 <= risk_score <= 100
    ):
        raise ValueError("risk_score must be an integer from 0 to 100")
    if any(not isinstance(event, SecurityEvent) for event in events):
        raise TypeError("tool planning requires normalized SecurityEvent records")

    observed = tuple(events)
    selected = ["behavioral_context_builder", "anomaly_detection_engine"]
    hypotheses: list[str] = []
    techniques: list[str] = []
    reasons: list[str] = []
    indicators: list[str] = []

    for event in observed:
        if event.source is EventSource.WINDOWS:
            selected.append("log_ingestion_parser")
            if event.windows_event_id in {4688}:
                selected.append("process_monitor")
            if event.windows_event_id in {4624, 4625, 4648, 4672, 4740, 4771, 4776}:
                selected.append("security_event_collector")
                hypotheses.append("authentication or account activity")
                reasons.append("authentication-related Windows event observed")
            if event.windows_event_id in {4698, 4702, 7045}:
                selected.extend(("process_monitor", "security_event_collector"))
                hypotheses.append("possible task or service persistence activity")
                techniques.append(
                    "T1053.005" if event.windows_event_id in {4698, 4702} else "T1543.003"
                )
                indicators.append("task or service creation event observed")
                reasons.append("persistence-related Windows event ID observed")
            if event.windows_event_id in {1102, 4719}:
                selected.append("security_event_collector")
                hypotheses.append("possible audit configuration or log integrity change")
                techniques.append("T1070.001" if event.windows_event_id == 1102 else "T1562.002")
                indicators.append("audit integrity event observed")
                reasons.append("audit-related Windows event ID observed")
            if event.windows_event_id in {4104}:
                selected.append("process_monitor")
                hypotheses.append("script activity requiring contextual review")
                techniques.append("T1059.001")
                reasons.append("PowerShell operational event observed")

            safe_text = " ".join(
                event.windows_fields.get(name, "")
                for name in ("NewProcessName", "CreatorProcessName", "ServiceName")
                if event.windows_fields is not None
            ).lower()
            if any(token in safe_text for token in ("\\temp\\", "\\appdata\\", "\\public\\")):
                indicators.append("process or service path is in a user-writable location")
                selected.append("process_monitor")

        elif event.event_type in {
            EventType.LOGIN_FAILED,
            EventType.LOGIN_SUCCEEDED,
        }:
            selected.extend(("log_ingestion_parser", "security_event_collector"))
            hypotheses.append("authentication activity")
            reasons.append("authentication event observed")

        if event.source_ip is not None:
            selected.append("threat_intelligence_lookup")

    if risk_score >= 80:
        selected.extend(("privacy_masking_proxy", "ai_decision_engine"))
        reasons.append("risk score warrants optional privacy-filtered advisory")
    if risk_score >= 90:
        selected.extend(("policy_gate", "audit_rollback_manager"))
        reasons.append("high review score warrants policy and audit inspection")

    deduplicated = tuple(dict.fromkeys(selected))
    if not set(deduplicated).issubset(TOOL_NAMES):
        raise RuntimeError("tool planner produced a tool outside its fixed catalog")
    return ToolPlan(
        attack_hypotheses=tuple(dict.fromkeys(hypotheses)),
        tools=deduplicated,
        mitre_attack=tuple(dict.fromkeys(techniques)),
        requires_approval=bool({"policy_gate", "action_enforcer"} & set(deduplicated)),
        reasons=tuple(dict.fromkeys(reasons)),
        behavioral_indicators=tuple(dict.fromkeys(indicators)),
    )


class AgentRouter:
    """Dispatch fixed, read-only tools; never execute model-generated commands."""

    def __init__(self, tools: AllowlistedTools | None = None) -> None:
        self.tools = tools or AllowlistedTools()
        self._routes: dict[
            str, Callable[[DetectionAlert | BehaviorSignal], Any]
        ] = {
            "alert_summary": self.tools.alert_summary,
            "advisory_payload": self.tools.advisory_payload,
            "threat_intelligence_lookup": self.tools.threat_intelligence_lookup,
        }

    def route(
        self, tool_name: str, alert: DetectionAlert | BehaviorSignal
    ) -> Any:
        if not isinstance(tool_name, str) or tool_name not in self._routes:
            raise ValueError(f"Agent tool is not allowlisted: {tool_name!r}")
        if not isinstance(alert, (DetectionAlert, BehaviorSignal)):
            raise TypeError(
                "Allowlisted agent tools require a DetectionAlert or BehaviorSignal"
            )
        if tool_name == "threat_intelligence_lookup" and not isinstance(
            alert, DetectionAlert
        ):
            raise TypeError(
                "Local threat-intelligence lookup requires a DetectionAlert"
            )
        return self._routes[tool_name](alert)
