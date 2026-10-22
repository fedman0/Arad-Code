import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import FINDINGS_SCHEMA
from core.prompts import HUNT_OUTPUT_CONTRACT, OUTPUT_CONTRACT
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc
from test_turns import FINDING, ev, hyp, tool_replies


def finish(hypotheses, evidence=None, **extra):
    return tc(len(hypotheses) + 100, "finish", {"findings": {
        "hypotheses": hypotheses, "evidence": evidence or [], "coverage": [], "open_questions": [],
        **extra}})


def run(tmp_path, turns, **kw):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM(turns)
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp, **kw))
    return res, llm


def test_the_model_never_sees_or_sets_evidence_refs(tmp_path):
    props = FINDINGS_SCHEMA["properties"]["hypotheses"]["items"]["properties"]
    assert "evidence_refs" not in props
    assert "evidence_refs" not in OUTPUT_CONTRACT and "evidence_refs" not in HUNT_OUTPUT_CONTRACT
    res, llm = run(tmp_path, [[finish([hyp(evidence_refs=["ev-login-1"])], [ev(0)])]])
    assert len(llm.calls) == 1 and len(res.hypotheses) == 1
    assert res.hypotheses[0].evidence_refs == []


def test_a_confident_finding_without_evidence_is_sent_back_once(tmp_path):
    res, llm = run(tmp_path, [[tc(1, "search_graph", {"name_pattern": "search"})],
                              [finish([hyp(confidence=9)])], [tc(2, "finish", FINDING)]])
    reply = tool_replies(llm)["call_101"]
    assert reply.startswith("Findings NOT recorded")
    assert "hypotheses[0]" in reply and "has no evidence item" in reply
    assert "confidence 3 or less" in reply
    assert len(llm.calls) == 3 and len(res.hypotheses) == 1 and res.evidence
    assert res.hypotheses[0].status == "evidence_supported"


def test_low_confidence_leads_pass_without_evidence(tmp_path):
    res, llm = run(tmp_path, [[finish([hyp(confidence=3)])]])
    assert len(llm.calls) == 1 and len(res.hypotheses) == 1
    assert res.hypotheses[0].status == "initial"


def test_an_invalid_hypothesis_is_sent_back_with_the_reason(tmp_path):
    broken = hyp()
    del broken["actor"]
    res, llm = run(tmp_path, [[finish([broken], [ev(0)])], [tc(2, "finish", FINDING)]])
    reply = tool_replies(llm)["call_101"]
    assert "hypotheses[0] is invalid: actor: Field required" in reply
    assert len(llm.calls) == 2 and len(res.hypotheses) == 1


def test_evidence_that_names_no_hypothesis_is_reported(tmp_path):
    item = ev(0)
    del item["hypothesis_index"]
    res, llm = run(tmp_path, [[finish([hyp(), hyp(entry_point="app/views.py:other")], [item])],
                              [tc(2, "finish", FINDING)]])
    reply = tool_replies(llm)["call_102"]
    assert "evidence[0] needs hypothesis_index" in reply and "0 to 1" in reply
    assert "hypotheses[0]" in reply and "hypotheses[1]" in reply
    assert len(res.hypotheses) == 1


def test_the_third_finish_is_recorded_as_it_is(tmp_path):
    res, llm = run(tmp_path, [[finish([hyp(confidence=9)])], [finish([hyp(confidence=9)])],
                              [finish([hyp(confidence=9)])]])
    replies = tool_replies(llm)
    assert replies["call_101"].startswith("Findings NOT recorded")
    assert len(llm.calls) == 3 and len(res.hypotheses) == 1
    assert res.hypotheses[0].status == "initial"


def test_forced_finish_rejection_says_only_finish_is_left(tmp_path):
    res, llm = run(tmp_path, [[finish([hyp(confidence=9)])], [tc(2, "finish", FINDING)]],
                   max_iterations=3)
    reply = tool_replies(llm)["call_101"]
    assert "only finish() is available now" in reply
    assert llm.calls[1]["tools"] == ["finish"] and len(res.hypotheses) == 1


def test_empty_findings_are_never_bounced(tmp_path):
    res, llm = run(tmp_path, [[finish([])]])
    assert len(llm.calls) == 1 and not res.hypotheses and not res.open_questions


def test_evidence_without_a_snippet_is_kept_and_filled_from_the_file(tmp_path):
    item = ev(0)
    del item["snippet"]
    res, llm = run(tmp_path, [[tc(1, "search_graph", {"name_pattern": "search"})],
                              [finish([hyp()], [item])]])
    assert len(llm.calls) == 2 and len(res.evidence) == 1
    assert res.evidence[0].snippet.strip().startswith("cursor.execute")
    assert res.hypotheses[0].status == "evidence_supported"
    assert not any("evidence[0] invalid" in q for q in res.open_questions)


def test_evidence_with_a_bad_field_is_sent_back_naming_it(tmp_path):
    res, llm = run(tmp_path, [[finish([hyp()], [ev(0, kind="screenshot")])],
                              [tc(2, "finish", FINDING)]])
    reply = tool_replies(llm)["call_101"]
    assert "evidence[0] is invalid: kind:" in reply
    assert len(llm.calls) == 2 and len(res.evidence) == 1


def test_obligation_status_is_judged_against_the_finding():
    ob = FINDINGS_SCHEMA["properties"]["hypotheses"]["items"]["properties"]["proof_obligations"]
    assert "against the finding" in ob["items"]["properties"]["status"]["description"]
    assert "against the finding" in OUTPUT_CONTRACT


def test_a_refuted_required_obligation_is_sent_back_once(tmp_path):
    ob = {"question": "Is any rate limiter applied to the login route?", "status": "refuted",
          "claim_type": "guard", "required_for_finding": True, "reason": "none at server.ts:616"}
    fixed = dict(ob, status="verified", evidence_ref="app/views.py:4")
    res, llm = run(tmp_path, [[tc(1, "search_graph", {"name_pattern": "search"})],
                              [finish([hyp(proof_obligations=[ob])], [ev(0)])],
                              [finish([hyp(proof_obligations=[fixed])], [ev(0)])]])
    reply = tool_replies(llm)["call_101"]
    assert reply.startswith("Findings NOT recorded")
    assert "Is any rate limiter applied to the login route?" in reply
    assert "judged against the finding" in reply
    assert len(llm.calls) == 3 and len(res.hypotheses) == 1
    assert res.hypotheses[0].status == "evidence_supported"


def test_optional_refuted_points_and_demotions_are_not_sent_back(tmp_path):
    optional = {"question": "Is the token also written to the log?", "status": "refuted",
                "required_for_finding": False}
    required = {"question": "Is the input concatenated into SQL?", "status": "refuted"}
    res, llm = run(tmp_path, [[finish([hyp(proof_obligations=[optional]),
                                       hyp(entry_point="app/views.py:other", status="rejected",
                                           proof_obligations=[required])],
                                      [ev(0), ev(1)])]])
    assert len(llm.calls) == 1 and len(res.hypotheses) == 2
