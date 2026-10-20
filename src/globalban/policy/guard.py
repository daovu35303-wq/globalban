from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network

from globalban.models.decisions import PolicyDecision


class PolicyGuard:
    """Validate every requested block before an action can reach the OS boundary."""

    def __init__(
        self,
        allowlist: tuple[str, ...] = (),
        minimum_failures: int = 5,
        max_actions_per_hour: int = 3,
    ) -> None:
        if minimum_failures < 2:
            raise ValueError("minimum_failures must be at least 2")
        if max_actions_per_hour < 1:
            raise ValueError("max_actions_per_hour must be positive")
        try:
            self._allowlist = tuple(ip_network(entry, strict=False) for entry in allowlist)
        except ValueError as exc:
            raise ValueError(f"Invalid allowlist entry: {exc}") from exc
        self.minimum_failures = minimum_failures
        self.max_actions_per_hour = max_actions_per_hour
        self._actions: list[datetime] = []

    def check_block(
        self,
        candidate_ip: str,
        evidence_count: int,
        approved: bool,
        now: datetime | None = None,
    ) -> PolicyDecision:
        try:
            address = ip_address(candidate_ip)
        except ValueError:
            return PolicyDecision(False, "The candidate is not a valid IP address.")
        if (
            not isinstance(evidence_count, int)
            or isinstance(evidence_count, bool)
            or evidence_count < 0
        ):
            return PolicyDecision(False, "Evidence count must be a non-negative integer.")
        if any(
            address.version == network.version and address in network
            for network in self._allowlist
        ):
            return PolicyDecision(False, "The candidate is covered by the configured allowlist.")
        if not address.is_global:
            return PolicyDecision(False, "Only globally routable IP addresses may be considered.")
        if evidence_count < self.minimum_failures:
            return PolicyDecision(
                False,
                f"Evidence count {evidence_count} is below the minimum {self.minimum_failures}.",
            )
        if not approved:
            return PolicyDecision(False, "Explicit operator approval is required.")
        timestamp = self._validated_now(now)
        if not self._reserve_action(timestamp):
            return PolicyDecision(False, "The one-hour action rate limit has been reached.")
        return PolicyDecision(True, "Policy checks passed; operator approval was recorded.")

    def check_rollback(
        self, approved: bool, now: datetime | None = None
    ) -> PolicyDecision:
        if not approved:
            return PolicyDecision(False, "Explicit operator approval is required for rollback.")
        timestamp = self._validated_now(now)
        if not self._reserve_action(timestamp):
            return PolicyDecision(False, "The one-hour action rate limit has been reached.")
        return PolicyDecision(True, "Rollback approval and rate-limit checks passed.")

    def seed_action(self, timestamp: datetime) -> None:
        self._actions.append(self._validated_now(timestamp))

    @staticmethod
    def _validated_now(now: datetime | None) -> datetime:
        timestamp = now or datetime.now(timezone.utc)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        return timestamp.astimezone(timezone.utc)

    def _reserve_action(self, timestamp: datetime) -> bool:
        cutoff = timestamp - timedelta(hours=1)
        self._actions = [action for action in self._actions if action > cutoff]
        if len(self._actions) >= self.max_actions_per_hour:
            return False
        self._actions.append(timestamp)
        return True