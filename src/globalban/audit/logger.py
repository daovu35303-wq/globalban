from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL audit trail with a hash link between records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, action: str, fields: dict[str, Any]) -> str:
        if not action:
            raise ValueError("action must not be empty")
        with self._lock:
            previous_hash = self._last_hash()
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "fields": fields,
                "previous_hash": previous_hash,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            record["record_hash"] = digest
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as audit_file:
                audit_file.write(json.dumps(record, sort_keys=True) + "\n")
            return digest

    def has_unrolled_block(self, candidate_ip: str) -> bool:
        active = False
        for record in self._verified_records():
            fields = record.get("fields")
            if not isinstance(fields, dict) or fields.get("ip") != candidate_ip:
                continue
            if record.get("action") in ("block_intent", "block_applied", "rollback_intent"):
                active = True
            elif record.get("action") in ("block_failed", "rollback_applied"):
                active = False
        return active

    def recent_action_timestamps(
        self, since: datetime, actions: set[str]
    ) -> list[datetime]:
        if since.tzinfo is None or since.utcoffset() is None:
            raise ValueError("since must be timezone-aware")
        cutoff = since.astimezone(timezone.utc)
        timestamps: list[datetime] = []
        for record in self._verified_records():
            if record.get("action") not in actions:
                continue
            try:
                timestamp = datetime.fromisoformat(record["timestamp"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("Audit record has an invalid timestamp") from exc
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("Audit record has a timezone-naive timestamp")
            if timestamp.astimezone(timezone.utc) >= cutoff:
                timestamps.append(timestamp)
        return timestamps

    def _last_hash(self) -> str | None:
        records = self._verified_records()
        return records[-1]["record_hash"] if records else None

    def _verified_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        last_hash: str | None = None
        records: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as audit_file:
            for line_number, line in enumerate(audit_file, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    digest = record.pop("record_hash")
                    previous_hash = record.get("previous_hash")
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise ValueError(
                        f"Audit file has an invalid record at line {line_number}: {self.path}"
                    ) from exc
                if not isinstance(digest, str) or previous_hash != last_hash:
                    raise ValueError(
                        f"Audit chain is invalid at line {line_number}: {self.path}"
                    )
                canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if digest != expected:
                    raise ValueError(
                        f"Audit record hash mismatch at line {line_number}: {self.path}"
                    )
                last_hash = digest
                record["record_hash"] = digest
                records.append(record)
        return records