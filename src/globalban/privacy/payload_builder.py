from __future__ import annotations

from globalban.models.decisions import BehaviorSignal, DetectionAlert
from globalban.privacy.masking import mask_ip


def build_advisory_payload(
    alert: DetectionAlert | BehaviorSignal,
) -> dict[str, object]:
    """Build the strict low-data schema for SSH alerts or Windows sequences."""
    timestamp = alert.timestamp.replace(minute=0, second=0, microsecond=0).isoformat()
    if isinstance(alert, BehaviorSignal):
        return {
            "schema_version": 1,
            "alert": {
                "rule_id": "WINDOWS-SEQUENCE-REVIEW",
                "source_ip": None,
                "hour_utc": timestamp,
                "failure_count": 0,
                "evidence_count": len(alert.evidence_event_ids),
                "confidence": alert.confidence,
                "event_ids": alert.event_ids,
                "score": alert.score,
            },
        }
    return {
        "schema_version": 1,
        "alert": {
            "rule_id": alert.rule_id,
            "source_ip": mask_ip(alert.source_ip),
            "hour_utc": timestamp,
            "failure_count": alert.failure_count,
            "evidence_count": len(alert.evidence_event_ids),
            "confidence": alert.confidence,
        },
    }