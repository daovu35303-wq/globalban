import unittest
from datetime import datetime, timedelta, timezone

from globalban.policy.guard import PolicyGuard


class PolicyGuardTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2025, 1, 1, tzinfo=timezone.utc)

    def test_requires_approval_and_minimum_evidence(self):
        guard = PolicyGuard(minimum_failures=5)
        self.assertFalse(guard.check_block("8.8.8.8", 5, False, self.now).allowed)
        self.assertFalse(guard.check_block("8.8.8.8", 4, True, self.now).allowed)
        self.assertTrue(guard.check_block("8.8.8.8", 5, True, self.now).allowed)

    def test_rejects_private_and_allowlisted_addresses(self):
        guard = PolicyGuard(allowlist=("8.8.8.0/24",), minimum_failures=2)
        self.assertFalse(guard.check_block("10.0.0.1", 5, True, self.now).allowed)
        decision = guard.check_block("8.8.8.8", 5, True, self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("allowlist", decision.reason)

    def test_rate_limit_is_enforced_and_expires(self):
        guard = PolicyGuard(minimum_failures=2, max_actions_per_hour=1)
        self.assertTrue(guard.check_block("8.8.8.8", 2, True, self.now).allowed)
        self.assertFalse(
            guard.check_block(
                "1.1.1.1", 2, True, self.now + timedelta(minutes=20)
            ).allowed
        )
        self.assertTrue(
            guard.check_block(
                "1.1.1.1", 2, True, self.now + timedelta(hours=2)
            ).allowed
        )

    def test_invalid_address_and_naive_clock_are_rejected(self):
        guard = PolicyGuard(minimum_failures=2)
        self.assertFalse(guard.check_block("not-an-ip", 2, True, self.now).allowed)
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            guard.check_block("8.8.8.8", 2, True, datetime(2025, 1, 1))

    def test_rollback_also_consumes_the_action_rate_limit(self):
        guard = PolicyGuard(minimum_failures=2, max_actions_per_hour=1)
        self.assertTrue(guard.check_rollback(True, self.now).allowed)
        self.assertFalse(
            guard.check_block(
                "8.8.8.8", 2, True, self.now + timedelta(minutes=1)
            ).allowed
        )


if __name__ == "__main__":
    unittest.main()