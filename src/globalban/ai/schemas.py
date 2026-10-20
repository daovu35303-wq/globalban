from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AIAdvisory:
    summary: str
    hypotheses: tuple[str, ...]
    caveats: tuple[str, ...]
    severity: str = "low"
    confidence: float = 0.0
    evidence: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    missing_data: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()


def parse_advisory_response(value: Any) -> AIAdvisory:
    """Accept plain-language advisory fields only; tool/command-shaped output is rejected."""
    legacy_fields = {"summary", "hypotheses", "caveats"}
    rich_fields = {
        "severity",
        "summary",
        "confidence",
        "evidence",
        "hypotheses",
        "caveats",
        "mitre_attack",
        "missing_data",
        "recommended_actions",
    }
    if not isinstance(value, dict) or frozenset(value) not in {
        frozenset(legacy_fields),
        frozenset(rich_fields),
    }:
        raise ValueError("AI response contains unsupported advisory fields")
    summary = value["summary"]
    hypotheses = value["hypotheses"]
    caveats = value["caveats"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 2000:
        raise ValueError("AI summary must contain 1 to 2000 characters")
    if not _text_list(hypotheses) or not _text_list(caveats):
        raise ValueError("AI hypotheses and caveats must be lists of at most 10 short strings")
    if set(value) == legacy_fields:
        return AIAdvisory(summary.strip(), tuple(hypotheses), tuple(caveats))

    severity = value["severity"]
    confidence = value["confidence"]
    if not isinstance(severity, str) or severity not in {"low", "medium", "high"}:
        raise ValueError("AI severity must be low, medium, or high")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ValueError("AI confidence must be between 0 and 1")
    evidence = _string_list(value["evidence"], "evidence")
    mitre_attack = _string_list(value["mitre_attack"], "mitre_attack")
    missing_data = _string_list(value["missing_data"], "missing_data")
    recommended_actions = _string_list(
        value["recommended_actions"], "recommended_actions"
    )
    return AIAdvisory(
        summary=summary.strip(),
        hypotheses=tuple(hypotheses),
        caveats=tuple(caveats),
        severity=severity,
        confidence=float(confidence),
        evidence=evidence,
        mitre_attack=mitre_attack,
        missing_data=missing_data,
        recommended_actions=recommended_actions,
    )


def _text_list(values: Any) -> bool:
    return (
        isinstance(values, list)
        and len(values) <= 10
        and all(isinstance(item, str) and len(item) <= 1000 for item in values)
    )


def _string_list(values: Any, name: str) -> tuple[str, ...]:
    if not _text_list(values):
        raise ValueError(f"AI {name} must be a list of at most 10 short strings")
    return tuple(item.strip() for item in values if item.strip())