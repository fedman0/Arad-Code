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
