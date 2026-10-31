"""Keep the published coverage audit aligned with executable source contracts."""
from pathlib import Path
import unittest

from app.modules import hunting_profiles as profiles
from app.modules.hunting_builder import EVENT_METADATA_SPECS, LINUX_QUERIES, PERSISTENCE_QUERIES, QUERIES, SUPPORTED
from app.modules.hunting_windows_queries import WINDOWS_QUERIES


ROOT = Path(__file__).resolve().parents[1]
AUDIT = (ROOT / "docs" / "THREAT_HUNTING_COVERAGE.md").read_text()


class CoverageMatrixTests(unittest.TestCase):
    def test_every_catalog_source_has_audited_status(self):
        for item in profiles.CATALOG:
            with self.subTest(source=item["id"]):
                self.assertIn(item["source"], AUDIT)
        self.assertEqual(SUPPORTED, frozenset(QUERIES) | frozenset(PERSISTENCE_QUERIES) | frozenset(LINUX_QUERIES))
        self.assertTrue(set(SUPPORTED) <= {item["id"] for item in profiles.CATALOG})

    def test_windows_candidates_are_documented_as_not_packaged(self):
        for key, (label, _query) in WINDOWS_QUERIES.items():
            with self.subTest(source=key):
                self.assertIn(label, AUDIT)
                self.assertIn(key, AUDIT)
        for key in EVENT_METADATA_SPECS:
            with self.subTest(source=key):
                self.assertIn(key, AUDIT)
        self.assertIn("not packaged", AUDIT.lower())
        self.assertIn("synthetic", AUDIT.lower())
        self.assertIn("not implemented", AUDIT.lower())

    def test_absent_evidence_and_provenance_gaps_are_explicit(self):
        for phrase in ("volatile-first", "clock offset", "tamper-evident", "per-row hash",
                       "Deleted-but-running", "BPF", "journald", "Prefetch", "USN Journal",
                       "Memory acquisition", "does not establish that activity did not occur"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase.lower(), AUDIT.lower())

    def test_in_app_docs_link_matches_canonical_matrix(self):
        docs = (ROOT / "frontend" / "src" / "pages" / "docs.tsx").read_text()
        self.assertIn("hunting-source-audit", docs)
        self.assertIn("docs/THREAT_HUNTING_COVERAGE.md", docs)
        reference = (ROOT / "docs" / "THREAT_HUNTING.md").read_text()
        self.assertIn("THREAT_HUNTING_COVERAGE.md", reference)


if __name__ == "__main__":
    unittest.main()
