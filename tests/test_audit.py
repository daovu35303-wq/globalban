import json
import tempfile
import unittest
from pathlib import Path

from globalban.audit.logger import AuditLogger


class AuditTests(unittest.TestCase):
    def test_records_form_a_verified_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            logger = AuditLogger(path)
            first_hash = logger.record("dry_run", {"ip": "8.8.8.8"})
            logger.record("rollback_denied", {"reason": "not approved"})
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["record_hash"], first_hash)
            self.assertEqual(records[1]["previous_hash"], first_hash)
            logger.record("another", {})

    def test_detects_tampered_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            AuditLogger(path).record("dry_run", {"ip": "8.8.8.8"})
            record = json.loads(path.read_text())
            record["fields"]["ip"] = "1.1.1.1"
            path.write_text(json.dumps(record) + "\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                AuditLogger(path).record("next", {})


if __name__ == "__main__":
    unittest.main()
