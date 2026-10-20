import unittest

from globalban.ai.schemas import parse_advisory_response


class AISchemaTests(unittest.TestCase):
    def test_accepts_advisory_without_actions(self):
        advisory = parse_advisory_response(
            {"summary": "Review activity.", "hypotheses": [], "caveats": ["Not proof."]}
        )
        self.assertEqual(advisory.summary, "Review activity.")

    def test_rejects_action_fields(self):
        with self.assertRaises(ValueError):
            parse_advisory_response(
                {
                    "summary": "Block this address.",
                    "hypotheses": [],
                    "caveats": [],
                    "action": "block_ip",
                }
            )


if __name__ == "__main__":
    unittest.main()
