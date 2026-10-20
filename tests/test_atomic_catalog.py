import tempfile
import unittest
from pathlib import Path

from globalban.evaluation.atomic_catalog import (
    load_atomic_techniques,
    summarize_atomic_techniques,
)


class AtomicCatalogTests(unittest.TestCase):
    def test_loads_local_metadata_and_summarizes_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.csv"
            path.write_text(
                "Category,TTP ID,Description\n"
                "Discovery,T1016,  Local   system discovery \n"
                "Discovery,T1082,System information discovery\n",
                encoding="utf-8",
            )
            techniques = load_atomic_techniques(path)
        self.assertEqual(len(techniques), 2)
        self.assertEqual(techniques[0].description, "Local system discovery")
        self.assertEqual(summarize_atomic_techniques(techniques), {"Discovery": 2})

    def test_rejects_missing_headers_and_incomplete_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.csv"
            path.write_text("name,id\nvalue,1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must contain"):
                load_atomic_techniques(path)
            path.write_text(
                "Category,TTP ID,Description\nDiscovery,T1016,\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "incomplete row"):
                load_atomic_techniques(path)


if __name__ == "__main__":
    unittest.main()
