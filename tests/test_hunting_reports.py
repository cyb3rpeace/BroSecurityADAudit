import io
import unittest
from app.modules.hunting_reports import build_ai_markdown, build_ai_pdf, validate_ai_answer, build_group_pdf, build_group_xlsx


class AIReportBuilderTests(unittest.TestCase):
    def setUp(self):
        self.result = {"id": "a"*32, "sha256": "b"*64, "summary": {"hostnames": ["host"], "sources": [{"source": "processes.jsonl", "rows": 2}]}}
        self.analysis = {"ruleset": "test-rules", "rows_reviewed": {"processes.jsonl": 2}, "findings": [{"rule_id": "R1", "source": "processes.jsonl", "row_number": 2}], "triage_summary": {"timeline": [{"timestamp": "2026-01-01T00:00:00Z", "source": "processes.jsonl", "row_number": 2}], "timeline_truncated": True}}
        self.answer = "\u041f\u0440\u0438\u0432\u0435\u0442 <script>alert(1)</script> [x](javascript:evil)\n```\nEND"

    def test_markdown_literal_full_answer_and_metadata(self):
        text = build_ai_markdown(9, self.result, self.analysis, self.answer).decode()
        for line in self.answer.split("\n"):
            self.assertIn("    " + line, text)
        for word in ["UNREVIEWED", "Company ID: 9", "b"*64, "test-rules", "processes.jsonl", "2026-01-01T00:00:00Z", '"timeline_truncated": true', "not verified"]:
            self.assertIn(word, text)

    def test_pdf_unicode_and_no_active_links(self):
        data = build_ai_pdf(9, self.result, self.analysis, self.answer)
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertIn(b"/ToUnicode", data)
        self.assertNotIn(b"/URI", data)
        self.assertNotIn(b"/JavaScript", data)
        # Inspect the embedded ToUnicode CMap without adding a test dependency.
        import re, zlib
        streams = []
        for raw in re.findall(rb"stream\r?\n(.*?)endstream", data, re.S):
            try:
                streams.append(zlib.decompress(raw.strip()))
            except zlib.error:
                pass
        cmaps = b"\n".join(stream for stream in streams if b"begincmap" in stream)
        for character in "\u041f\u0440\u0438\u0432\u0435\u0442":
            self.assertIn(("<%04X>" % ord(character)).encode(), cmaps)
        self.assertIn(b"/FontFile2", data)

    def test_validation_and_boundary_no_truncation(self):
        for answer in ["", "   ", "x"*100001, "x\x00", "\ud800"]:
            with self.assertRaises(ValueError):
                validate_ai_answer(answer)
        answer = "x"*99997 + "END"
        self.assertIn(answer.encode(), build_ai_markdown(1, self.result, self.analysis, answer))
        self.assertTrue(build_ai_pdf(1, self.result, self.analysis, answer).startswith(b"%PDF"))


class CitationAuditTests(unittest.TestCase):
    def setUp(self):
        self.analysis = {"findings": [{"source": "results/p.jsonl", "row_number": 0},
                                      {"source": "results/p.jsonl", "row_number": 3}]}

    def test_valid_references_do_not_verify_claims(self):
        from app.modules.hunting_ai import audit_answer_citations
        result = audit_answer_citations("Fact [evidence:results/p.jsonl#0] [evidence:results/p.jsonl#0]", self.analysis)
        self.assertEqual(result["status"], "references_present")
        self.assertEqual(len(result["valid_references"]), 1)
        self.assertFalse(result["claims_verified"])

    def test_unknown_foreign_and_malformed_references(self):
        from app.modules.hunting_ai import audit_answer_citations
        for token in ["results/p.jsonl#1", "foreign.jsonl#0", "results/p.jsonl#-1", "results/p.jsonl#True", "broken"]:
            with self.subTest(token=token):
                result = audit_answer_citations("[evidence:" + token + "]", self.analysis)
                self.assertEqual(result["status"], "invalid_references")
                self.assertFalse(result["valid_references"])

    def test_absent_citations_are_explicitly_unverified(self):
        from app.modules.hunting_ai import audit_answer_citations
        self.assertEqual(audit_answer_citations("No citations", self.analysis)["status"], "no_verifiable_references")

    def test_catalog_excludes_context_omitted_findings(self):
        from app.modules.hunting_ai import audit_answer_citations
        analysis = {"findings": [{"source": "p", "row_number": n} for n in range(100)]}
        self.assertEqual(audit_answer_citations("[evidence:p#80]", analysis)["status"], "invalid_references")
        self.assertEqual(audit_answer_citations("[evidence:p#79]", analysis)["status"], "references_present")

    def test_report_includes_citation_audit_without_changing_answer(self):
        answer = "Claim [evidence:foreign.jsonl#0]"
        data = build_ai_markdown(1, {"id": "a"*32}, self.analysis, answer).decode()
        self.assertIn("invalid_references", data)
        self.assertIn('"claims_verified": false', data)
        self.assertIn(answer, data)


class GroupReportTests(unittest.TestCase):
    def setUp(self):
        self.correlation = {"version":"hunting-correlation-1", "result_ids":["a"*32,"b"*32], "limitations":["test limit"], "graph":{"nodes":[{"id":"host:a","evidence_refs":[{"result_id":"a"*32,"source":"host.jsonl","row_number":1}]}],"edges":[]}, "limits":{}, "truncated":False}
        self.results = [{"id":"a"*32,"sha256":"c"*64,"created_at":"now","size":12},{"id":"b"*32,"sha256":"d"*64,"created_at":"now","size":13}]

    def test_group_markdown_is_unreviewed_and_audits_scope(self):
        from app.modules.hunting_reports import build_group_ai_markdown
        answer = "Shared artifact [evidence:" + "a"*32 + ":host.jsonl#1]"
        text = build_group_ai_markdown(1, self.results, self.correlation, answer).decode()
        self.assertIn("UNREVIEWED", text)
        self.assertIn("references_present", text)
        self.assertIn("claims_verified", text)
        self.assertIn(answer, text)

    def test_group_pdf_has_no_active_links(self):
        from app.modules.hunting_reports import build_group_ai_pdf
        data = build_group_ai_pdf(1, self.results, self.correlation, "[evidence:foreign.jsonl#1]")
        self.assertTrue(data.startswith(b"%PDF-")); self.assertNotIn(b"/URI", data); self.assertNotIn(b"/JavaScript", data)


class CustomExportBuilderTests(unittest.TestCase):
    def test_custom_pdf_and_xlsx_include_scope_and_sections(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            result = {"id": "a" * 32, "sha256": "b" * 64, "size": 10, "summary": {"total_rows": 3, "sources": []}}
            analysis = {"import_id": result["id"], "findings": [{"rule_id": "process.encoded_powershell", "title": "PowerShell", "source": "Processes", "row_number": 1, "reason": "synthetic"}], "triage_summary": {"timeline": []}, "graph": {"edges": []}}
            correlation = {"limits": {"results": 20}, "graph": {"nodes": [], "edges": []}}
            pdf = Path(d) / "report.pdf"; xlsx = Path(d) / "report.xlsx"
            build_group_pdf(pdf, [result], [analysis], correlation, {"summary", "findings", "timeline", "mitre", "graph", "remediation"})
            build_group_xlsx(xlsx, [result], [analysis], correlation, {"summary", "findings", "timeline", "mitre", "graph", "remediation"})
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF")); self.assertGreater(xlsx.stat().st_size, 100)
