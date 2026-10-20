import unittest

from globalban.ai.schemas import parse_advisory_response


class AdvisorySchemaTests(unittest.TestCase):
    def test_accepts_advisory_only_fields(self):
        advisory = parse_advisory_response(
            {
                "summary": "Several failures were observed.",
                "hypotheses": ["Automated retries are possible."],
                "caveats": ["This does not establish identity or intent."],
            }
        )
        self.assertEqual(advisory.hypotheses[0], "Automated retries are possible.")
        self.assertEqual(advisory.severity, "low")

    def test_accepts_structured_evidence_based_advisory(self):
        advisory = parse_advisory_response(
            {
                "severity": "medium",
                "summary": "Several failures were correlated.",
                "confidence": 0.55,
                "evidence": ["Five authentication failures."],
                "hypotheses": ["Automated retries are possible."],
                "caveats": ["This does not identify a person."],
                "mitre_attack": [],
                "missing_data": ["Operator confirmation."],
                "recommended_actions": ["Review the local authentication records."],
            }
        )
        self.assertEqual(advisory.severity, "medium")
        self.assertEqual(advisory.confidence, 0.55)
        self.assertEqual(advisory.evidence, ("Five authentication failures.",))

    def test_rejects_commands_or_unknown_ai_fields(self):
        with self.assertRaisesRegex(ValueError, "unsupported advisory fields"):
            parse_advisory_response(
                {
                    "summary": "Block the IP",
                    "hypotheses": [],
                    "caveats": [],
                    "command": "netsh",
                }
            )


if __name__ == "__main__":
    unittest.main()
