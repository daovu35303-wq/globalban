from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from globalban.models.decisions import BehaviorSignal, DetectionAlert
from globalban.privacy.payload_builder import build_advisory_payload
from globalban.threat_intel import LocalThreatIntel


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    requires_approval: bool


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool: str
    ok: bool
    output: Any
    error: str | None = None


class ToolRegistry:
    """Dispatch only handlers registered by trusted application code."""

    def __init__(self) -> None:
        self._handlers: dict[str, tuple[ToolSpec, Callable[..., Any]]] = {}

    def register(self, spec: ToolSpec, handler: Callable[..., Any]) -> None:
        if not spec.name:
            raise ValueError("tool name must not be empty")
        if spec.name in self._handlers:
            raise ValueError(f"tool already registered: {spec.name}")
        self._handlers[spec.name] = (spec, handler)

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(spec for spec, _ in self._handlers.values())

    def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        approved: bool = False,
    ) -> ToolResult:
        registered = self._handlers.get(name)
        if registered is None:
            return ToolResult(name, False, None, "tool is not allowlisted")
        spec, handler = registered
        if spec.requires_approval and not approved:
            return ToolResult(name, False, None, "explicit approval is required")
        try:
            return ToolResult(name, True, handler(**dict(arguments)))
        except (TypeError, ValueError, PermissionError, RuntimeError) as exc:
            return ToolResult(name, False, None, str(exc))


TOOL_SPECS = (
    ToolSpec("log_ingestion_parser", "Normalize configured security event records", False),
    ToolSpec("process_monitor", "Build process ancestry from observed event records", False),
    ToolSpec("security_event_collector", "Read explicitly configured security sources", False),
    ToolSpec("behavioral_context_builder", "Summarize bounded local event context", False),
    ToolSpec("anomaly_detection_engine", "Run explainable rules and local baselines", False),
    ToolSpec("threat_intelligence_lookup", "Look up an indicator in an explicitly selected feed", False),
    ToolSpec("privacy_masking_proxy", "Validate a minimized advisory payload", False),
    ToolSpec("ai_decision_engine", "Request an advisory with minimized evidence", False),
    ToolSpec("policy_gate", "Evaluate a defensive request against policy", True),
    ToolSpec("action_enforcer", "Request an already approved defensive action", True),
    ToolSpec("audit_rollback_manager", "Inspect audit history or request rollback", True),
    ToolSpec("evaluation_reporting", "Calculate metrics from caller-provided labels", False),
)


def empty_registry() -> ToolRegistry:
    """Catalog tools without connecting any action or external handler."""
    def not_wired(**_: Any) -> None:
        raise RuntimeError("tool handler is not wired")

    registry = ToolRegistry()
    for spec in TOOL_SPECS:
        registry.register(spec, not_wired)
    return registry


class AllowlistedTools:
    """Expose read-only alert formatting and privacy-safe advisory payload construction."""

    def __init__(self, local_threat_intel: LocalThreatIntel | None = None) -> None:
        self._local_threat_intel = local_threat_intel

    @staticmethod
    def alert_summary(
        alert: DetectionAlert | BehaviorSignal,
    ) -> dict[str, Any]:
        if isinstance(alert, BehaviorSignal):
            return {
                "rule_id": "WINDOWS-SEQUENCE-REVIEW",
                "score": alert.score,
                "confidence": alert.confidence,
                "event_ids": alert.event_ids,
                "evidence_count": len(alert.evidence_event_ids),
                "reasons": alert.reasons,
            }
        return {
            "rule_id": alert.rule_id,
            "failure_count": alert.failure_count,
            "confidence": alert.confidence,
            "explanation": alert.explanation,
            "evidence_count": len(alert.evidence_event_ids),
        }

    @staticmethod
    def advisory_payload(
        alert: DetectionAlert | BehaviorSignal,
    ) -> dict[str, object]:
        return build_advisory_payload(alert)

    def threat_intelligence_lookup(self, alert: DetectionAlert) -> dict[str, object]:
        if not isinstance(alert, DetectionAlert):
            raise TypeError("local threat-intelligence lookup requires an authentication alert")
        if self._local_threat_intel is None:
            raise RuntimeError("local threat-intelligence feed is not configured")
        record = self._local_threat_intel.lookup(alert.source_ip)
        if record is None:
            return {"found": False, "source": "local", "note": None}
        return {
            "found": True,
            "source": record.source,
            "note": record.note,
        }
