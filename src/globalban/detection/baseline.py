from __future__ import annotations

import json
from collections import defaultdict
from datetime import date
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path

from globalban.models.events import EventSource, SecurityEvent


class LocalBaseline:
    """Maintain local daily failed-login counts by source IP, never by username."""

    def __init__(self, path: str | Path | None = None, minimum_history_days: int = 7) -> None:
        if minimum_history_days < 2:
            raise ValueError("minimum_history_days must be at least 2")
        self.path = Path(path).expanduser() if path is not None else None
        self.minimum_history_days = minimum_history_days
        self._counts: dict[str, dict[str, int]] = defaultdict(dict)
        if self.path is not None and self.path.exists():
            self._load()

    def observe_failure(self, event: SecurityEvent) -> str:
        if event.source_ip is None:
            raise ValueError("A source IP is required for baseline observation")
        key = event.source_ip
        day = event.timestamp_utc.date().isoformat()
        daily = self._counts[key]
        daily[day] = daily.get(day, 0) + event.count
        context = self.describe(key, event.timestamp_utc.date())
        if self.path is not None:
            self._save()
        return context

    def describe(self, source_ip: str, on_date: date) -> str:
        daily = self._counts.get(source_ip, {})
        previous = [
            count
            for day, count in daily.items()
            if date.fromisoformat(day) < on_date
        ]
        current_count = daily.get(on_date.isoformat(), 0)
        if len(previous) < self.minimum_history_days:
            return (
                f"Local baseline not established ({len(previous)}/"
                f"{self.minimum_history_days} prior active days); today's local count is "
                f"{current_count}."
            )
        average = sum(previous) / len(previous)
        elevated = current_count >= max(5, average * 3)
        status = "above" if elevated else "within"
        return (
            f"Today's local count ({current_count}) is {status} the historical comparison "
            f"({average:.1f} failures/day across {len(previous)} prior active days)."
        )

    def _load(self) -> None:
        assert self.path is not None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to load local baseline {self.path}: {exc}") from exc
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError(f"Unsupported local baseline format: {self.path}")
        counts = value.get("daily_counts")
        if not isinstance(counts, dict):
            raise ValueError(f"Invalid local baseline counts: {self.path}")
        for address, days in counts.items():
            if not isinstance(address, str) or not isinstance(days, dict):
                raise ValueError(f"Invalid local baseline entry: {self.path}")
            try:
                ip_address(address)
            except ValueError as exc:
                raise ValueError(f"Invalid IP in local baseline: {self.path}") from exc
            for day, count in days.items():
                if (
                    not isinstance(day, str)
                    or not isinstance(count, int)
                    or isinstance(count, bool)
                    or count < 0
                ):
                    raise ValueError(f"Invalid local baseline count: {self.path}")
                try:
                    date.fromisoformat(day)
                except ValueError as exc:
                    raise ValueError(f"Invalid date in local baseline: {self.path}") from exc
            self._counts[address] = days

    def _save(self) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        data = {
            "schema_version": 1,
            "daily_counts": {
                address: dict(sorted(days.items()))
                for address, days in sorted(self._counts.items())
            },
        }
        temporary.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)


class BehaviorBaseline:
    """Persist local Windows event frequencies without usernames or raw event text."""

    def __init__(
        self,
        path: str | Path | None = None,
        warmup_events: int = 20,
    ) -> None:
        if (
            not isinstance(warmup_events, int)
            or isinstance(warmup_events, bool)
            or warmup_events < 1
        ):
            raise ValueError("warmup_events must be greater than zero")
        self.path = Path(path).expanduser() if path is not None else None
        self.warmup_events = warmup_events
        self._total = 0
        self._counts: dict[str, int] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def observe(self, event: SecurityEvent) -> tuple[int, str | None]:
        if event.source is not EventSource.WINDOWS or event.windows_event_id is None:
            raise ValueError("Windows event ID is required for behavior baseline")
        host_hash = sha256((event.host or "<unknown-host>").encode("utf-8")).hexdigest()
        provider_hash = sha256(
            (event.windows_provider or "<unknown-provider>").encode("utf-8")
        ).hexdigest()
        key = f"{host_hash}:{provider_hash}:{event.windows_event_id}"
        previous = self._counts.get(key, 0)
        self._counts[key] = previous + event.count
        self._total += event.count
        if self.path is not None:
            self._save()
        if self._total < self.warmup_events or previous:
            return 0, None
        return 10, "first observed host/provider/event-ID combination after baseline warmup"

    def _load(self) -> None:
        assert self.path is not None
        try:
            if self.path.stat().st_size > 8_000_000:
                raise ValueError("Windows behavior baseline exceeds the 8 MB limit")
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to load Windows behavior baseline {self.path}: {exc}") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "total", "counts"}
            or isinstance(value.get("schema_version"), bool)
            or value.get("schema_version") != 1
            or not isinstance(value.get("total"), int)
            or isinstance(value.get("total"), bool)
            or value["total"] < 0
            or not isinstance(value.get("counts"), dict)
        ):
            raise ValueError(f"Invalid Windows behavior baseline format: {self.path}")
        for key, count in value["counts"].items():
            parts = key.split(":") if isinstance(key, str) else []
            if (
                len(parts) != 3
                or len(parts[0]) != 64
                or len(parts[1]) != 64
                or any(char not in "0123456789abcdef" for part in parts[:2] for char in part)
                or not parts[2].isdecimal()
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count < 1
            ):
                raise ValueError(f"Invalid Windows behavior baseline entry: {self.path}")
        self._total = value["total"]
        self._counts = dict(value["counts"])

    def _save(self) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "total": self._total,
                    "counts": dict(sorted(self._counts.items())),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(self.path)
