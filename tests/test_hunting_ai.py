import unittest
import pytest
from app.modules.hunting_ai import prepare_context, public_research, audit_answer_citations
class AiSafetyTests(unittest.TestCase):
 def test_context_contains_graph_ioc_and_contract(self):
  r=prepare_context({"ruleset":"x","findings":[],"graph":{"nodes":[]},"iocs":[]})
  self.assertIn("citation_contract",r);self.assertIn("graph",r);self.assertIn("iocs",r)
 def test_research_rejects_non_ioc(self):
  self.assertEqual(public_research("not-a-valid-ioc")["status"],"not_supported")
if __name__ == "__main__": unittest.main()


def test_prepare_context_includes_complete_inventory_when_details_are_bounded():
  from app.modules.hunting_ai import prepare_context
  findings=[{"rule_id":f"rule.{i}","title":f"Finding {i}","classification":"review","confidence":"medium","risk_score":30,"source":"events.json","row_number":i+1,"reason":"x"*2000} for i in range(140)]
  context=prepare_context({"findings":findings,"graph":{},"iocs":[]})
  assert context["finding_inventory_complete"] is True
  assert len(context["finding_inventory"]) == len(findings)
  assert context["finding_inventory"][-1]["rule_id"] == "rule.139"
  assert context["findings_supplied"] < context["findings_available"]
  assert context["context_truncated"] is True

def test_prepare_context_inventory_handles_non_dict_findings():
  from app.modules.hunting_ai import prepare_context
  context=prepare_context({"findings":[None, {"rule_id":"x"}]})
  assert context["finding_inventory_complete"] is True
  assert len(context["finding_inventory"]) == 2


def test_prepare_context_uses_complete_analysis_inventory():
  from app.modules.hunting_ai import prepare_context
  inventory=[{"rule_id":str(i),"title":"t","source":"s","row_number":i+1} for i in range(250)]
  context=prepare_context({"findings":inventory[:200],"finding_inventory":inventory,"matched_rules":250,"truncated":True})
  assert len(context["finding_inventory"]) == 250
  assert context["finding_inventory_complete"] is False
  assert context["findings_omitted_by_analysis_cap"] == 50


def test_citation_audit_requires_exact_source_path():
  analysis={"findings":[{"source":"results/Windows.System.Services.json","row_number":298}]}
  exact=audit_answer_citations("Observed [evidence:results/Windows.System.Services.json#298]",analysis)
  shortened=audit_answer_citations("Observed [evidence:Windows.System.Services.json#298]",analysis)
  assert exact["status"] == "references_present"
  assert shortened["status"] == "invalid_references"
  assert shortened["invalid_references"] == ["Windows.System.Services.json#298"]

def test_citation_audit_flags_missing_and_unknown_references():
  analysis={"findings":[{"source":"results/Host.json","row_number":1}]}
  assert audit_answer_citations("No refs",analysis)["status"] == "no_verifiable_references"
  result=audit_answer_citations("[evidence:results/Host.json#2]",analysis)
  assert result["status"] == "invalid_references"


def test_ask_hunting_rejects_invalid_citation_after_single_retry(monkeypatch):
  import pytest
  from app.modules import hunting_ai
  calls=[]
  responses=iter([
    "Повторите [evidence:missing.json#1]",
    "Повтор снова неверный [evidence:missing.json#1]",
  ])
  class Response:
    def __init__(self, text): self.text=text
    def raise_for_status(self): pass
    def json(self): return {"choices":[{"message":{"content":self.text}}]}
  def post(*args, **kwargs):
    calls.append(kwargs["json"]["messages"])
    return Response(next(responses))
  monkeypatch.setattr(hunting_ai.requests, "post", post)
  with pytest.raises(RuntimeError, match="после повторной проверки"):
    hunting_ai.ask_hunting({"api_url":"https://ai.example/v1", "api_key":"test"}, "Проверь", {"findings":[{"source":"results/Host.json", "row_number":1}]})
  assert len(calls) == 2
