from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class DetectionAlert:
    alert_id: str
    timestamp: datetime
    source_ip: str
    rule_id: str
    explanation: str
    evidence_event_ids: tuple[str, ...]
    failure_count: int
    confidence: float
    baseline_context: str


@dataclass(frozen=True, slots=True)
class BehaviorSignal:
    timestamp: datetime
    host: str
    score: int
    event_ids: tuple[int, ...]
    evidence_event_ids: tuple[str, ...]
    explanation: str
    confidence: float
    reasons: tuple[str, ...] = ()
    behavioral_indicators: tuple[str, ...] = ()
    baseline_context: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ActionResult:
    status: str
    reason: str
    rule_name: str | None = None