import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import Hypothesis
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc
from test_finish_contract import finish
from test_turns import ev, hyp, tool_replies


def setup(tmp_path):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    return runner, db, rp


def first_scan(runner, rp):
    runner._llm = ScriptedLLM([[tc(1, "grep", {"pattern": "cursor.execute"})], [finish([hyp()], [ev(0)])]])
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    h = res.hypotheses[0]
    assert h.status == "initial"
    return h


def test_known_findings_are_listed_for_the_model(tmp_path):
    runner, db, rp = setup(tmp_path)
    for i in range(65):
        db.save_hypothesis(rp, Hypothesis(actor="a", capability="c", entry_point=f"/r{i}",
                                          security_boundary="b", violated_invariant=f"rule {i}",
                                          observable_impact=f"impact {i}", cwe="CWE-89"))
    text = runner._build_initial_context(rp)
    assert "Findings already recorded" in text and "existing_id" in text
    assert text.count("CWE-89 /r") == 60 and "and 5 more" in text


def test_new_evidence_for_a_recorded_finding_is_merged(tmp_path):
    runner, db, rp = setup(tmp_path)
    h = first_scan(runner, rp)
    merge = dict(hyp(), existing_id=h.id, violated_invariant="worded differently this time")
    llm = ScriptedLLM([[tc(1, "read_file", {"file_path": "app/views.py"})], [finish([merge], [ev(0)])]])
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert res.hypotheses == [] and res.merged == [h.id]
    rows = db.list_hypotheses(rp)
    assert len(rows) == 1 and rows[0].id == h.id and rows[0].status == "evidence_supported"
    assert rows[0].violated_invariant == h.violated_invariant
    assert len(db.get_all_evidence_for_hypothesis(h.id)) == 2
    assert any("added by hunt-injection-sqli-cmdi" in u for u in rows[0].uncertainty)


def test_an_unknown_existing_id_is_sent_back_then_kept_as_new(tmp_path):
    runner, db, rp = setup(tmp_path)
    entry = dict(hyp(), existing_id="nosuchid")
    llm = ScriptedLLM([[finish([entry], [ev(0)])]] * 3)
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert "not a recorded finding" in tool_replies(llm)["call_101"]
    assert len(res.hypotheses) == 1 and res.merged == []
    assert any("kept as a new hypothesis" in q for q in res.open_questions)


def test_a_merge_entry_without_evidence_is_sent_back(tmp_path):
    runner, db, rp = setup(tmp_path)
    h = first_scan(runner, rp)
    llm = ScriptedLLM([[finish([dict(hyp(), existing_id=h.id)])], [finish([])]])
    runner._llm = llm
    asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert "no evidence item has hypothesis_index 0" in tool_replies(llm)["call_101"]


def test_a_human_decision_survives_a_merge(tmp_path):
    runner, db, rp = setup(tmp_path)
    h = first_scan(runner, rp)
    h.status = "human_confirmed"
    db.save_hypothesis(rp, h)
    runner._llm = ScriptedLLM([[finish([dict(hyp(), existing_id=h.id)], [ev(0)])]])
    asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert db.get_hypothesis(rp, h.id).status == "human_confirmed"


def merge_scan(runner, rp, h, entry=None, evidence=None, tools=None):
    entry = dict(hyp(), existing_id=h.id, **(entry or {}))
    turns = [[tc(1, "read_file", {"file_path": "app/views.py"})]] if tools is None else tools
    runner._llm = ScriptedLLM(turns + [[finish([entry], evidence or [ev(0)])]])
    return asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))


def test_new_evidence_reopens_a_model_rejection_or_block(tmp_path):
    for status in ("rejected", "blocked"):
        runner, db, rp = setup(tmp_path / status)
        h = first_scan(runner, rp)
        h.status = status
        h.rejected_by = "model" if status == "rejected" else None
        h.rejection_reason = "model said no"
        h.rejected_at_commit = runner._get_commit(rp)
        db.save_hypothesis(rp, h)
        res = merge_scan(runner, rp, h)
        assert res.merged == [h.id]
        assert db.get_hypothesis(rp, h.id).status == "evidence_supported"
        runner.reconcile(rp)
        after = db.get_hypothesis(rp, h.id)
        assert after.status == "evidence_supported" and after.priority > 0
        assert any("reopened by new evidence" in u for u in after.uncertainty)


def test_a_human_rejection_survives_a_merge(tmp_path):
    runner, db, rp = setup(tmp_path)
    h = first_scan(runner, rp)
    h.status, h.rejected_by = "rejected", "human"
    db.save_hypothesis(rp, h)
    merge_scan(runner, rp, h)
    assert db.get_hypothesis(rp, h.id).status == "rejected"


def test_a_merge_carries_resolved_claims_and_obligations(tmp_path):
    runner, db, rp = setup(tmp_path)
    runner._llm = ScriptedLLM([[tc(1, "read_file", {"file_path": "app/views.py"})],
                               [finish([hyp(reachability="probable")], [ev(0)])]])
    h = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp)).hypotheses[0]
    assert h.status == "initial"
    assert any(o.claim_type == "reachability" and o.status == "unresolved" for o in h.proof_obligations)
    merge_scan(runner, rp, h, entry={"reachability": "proven", "proof_obligations": [
        {"question": "Is search reachable from GET /search?", "status": "verified", "claim_type": "reachability"}]})
    runner.reconcile(rp)
    after = db.get_hypothesis(rp, h.id)
    assert after.reachability == "proven" and after.status == "evidence_supported"
    assert not any(o.status == "unresolved" for o in after.proof_obligations if o.required_for_finding)


def test_claims_without_kept_evidence_change_nothing(tmp_path):
    runner, db, rp = setup(tmp_path)
    h = first_scan(runner, rp)
    before = len(db.get_all_evidence_for_hypothesis(h.id))
    runner._llm = ScriptedLLM([[finish([dict(hyp(), existing_id=h.id, reachability="proven")])]])
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp, max_iterations=1))
    assert res.merged == []
    assert len(db.get_all_evidence_for_hypothesis(h.id)) == before
    bad = merge_scan(runner, rp, h, evidence=[ev(5)], tools=[])
    assert bad.merged == []


def test_weaker_merged_evidence_does_not_lower_the_confidence_cap(tmp_path):
    runner, db, rp = setup(tmp_path)
    runner._llm = ScriptedLLM([[tc(1, "trace_path", {"function_name": "app/views.py:search"})],
                               [finish([hyp(confidence=8)], [ev(0, analysis_quality={"method": "semantic"})])]])
    h = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp)).hypotheses[0]
    runner.reconcile(rp)
    assert db.get_hypothesis(rp, h.id).confidence == 8
    merge_scan(runner, rp, h, evidence=[ev(0, analysis_quality={"method": "textual"})],
               tools=[[tc(1, "grep", {"pattern": "cursor.execute"})]])
    runner.reconcile(rp)
    after = db.get_hypothesis(rp, h.id)
    assert after.confidence == 8 and after.status == "evidence_supported"
    kinds = sorted((e.analysis_quality.method, e.merged_by) for e in db.get_all_evidence_for_hypothesis(h.id))
    assert kinds == [("semantic", None), ("textual", "hunt-injection-sqli-cmdi")]


def test_list_hypotheses_gives_one_line_per_finding_and_pages(tmp_path):
    runner, db, rp = setup(tmp_path)
    for i in range(70):
        db.save_hypothesis(rp, Hypothesis(actor="a", capability="c", entry_point=f"GET /r{i} -> h{i}",
                                          security_boundary="b", violated_invariant="rule " + "x" * 300,
                                          observable_impact="impact " + "y" * 300,
                                          cwe="CWE-639" if i % 2 else "CWE-89"))
    out = asyncio.run(runner._execute_tool("list_hypotheses", {"limit": 200}, rp))
    lines = out.splitlines()
    assert len(lines) == 61 and "showing 1-60 of 70" in lines[-1]
    assert all(line.startswith("[") and len(line) < 330 for line in lines[:-1])
    page = asyncio.run(runner._execute_tool("list_hypotheses", {"offset": 60}, rp))
    assert len(page.splitlines()) == 11 and "showing 61-70 of 70" in page
    hit = asyncio.run(runner._execute_tool("list_hypotheses", {"query": "/r7 h7"}, rp))
    assert len(hit.splitlines()) == 1 and "GET /r7 -> h7" in hit and "CWE-639" in hit
    both = asyncio.run(runner._execute_tool("list_hypotheses", {"query": "cwe-89 /r1"}, rp))
    assert all("CWE-89" in line for line in both.splitlines())
    none = asyncio.run(runner._execute_tool("list_hypotheses", {"query": "nothing-like-this"}, rp))
    assert none == "No hypotheses match."
    past = asyncio.run(runner._execute_tool("list_hypotheses", {"offset": 90}, rp))
    assert past == "No hypotheses past offset 90; 70 match."
