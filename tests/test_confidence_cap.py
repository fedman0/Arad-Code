import asyncio
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.evidence_gate import _apply_quality_caps
from core.models import AnalysisQuality, Evidence, Hypothesis
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc
from test_finish_contract import finish
from test_turns import FINDING, ev, hyp


def mk(confidence=10):
    return Hypothesis(actor="a", capability="c", entry_point="/x", security_boundary="b",
                      violated_invariant="i", observable_impact="o", confidence=confidence)


def evidence(h, method="textual", stale=False):
    return Evidence(hypothesis_id=h.id, kind="code", description="d", file_path="f.py",
                    line_start=1, line_end=1, snippet="x", stale=stale,
                    analysis_quality=AnalysisQuality(method=method))


def test_no_evidence_caps_confidence_like_a_guess():
    h = mk()
    _apply_quality_caps(h, [])
    assert h.confidence == 3
    h = mk()
    _apply_quality_caps(h, [evidence(h, stale=True)])
    assert h.confidence == 3
    h = mk(confidence=2)
    _apply_quality_caps(h, [])
    assert h.confidence == 2


def test_evidence_quality_caps_are_unchanged():
    h = mk()
    _apply_quality_caps(h, [evidence(h, "textual")])
    assert h.confidence == 4
    h = mk()
    _apply_quality_caps(h, [evidence(h, "semantic"), evidence(h, "structural")])
    assert h.confidence == 7


def test_reconcile_can_leave_a_missing_cap_out():
    h = mk()
    _apply_quality_caps(h, [], missing_cap=None)
    assert h.confidence == 10


def test_a_recorded_finding_without_evidence_is_at_most_a_lead(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM([[finish([hyp(confidence=10)])]] * 3)
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert len(res.hypotheses) == 1
    assert res.hypotheses[0].confidence == 3 and res.hypotheses[0].status == "initial"


def test_evidence_that_fails_verification_counts_as_none(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    bad = ev(0, anchor_text="this text appears nowhere in the file at all")
    runner._llm = ScriptedLLM([[finish([hyp(confidence=9)], [bad])]])
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert res.evidence and res.evidence[0].stale
    assert res.hypotheses[0].confidence == 3 and res.hypotheses[0].status == "initial"


def test_reconcile_keeps_confidence_when_code_moves_on(tmp_path):
    runner, db = make_runner(tmp_path)
    repo = make_repo(tmp_path / "repo")
    rp = str(repo)
    runner._llm = ScriptedLLM([[tc(1, "search_graph", {"name_pattern": "search"})],
                               [tc(2, "finish", FINDING)]])
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    h = res.hypotheses[0]
    assert h.status == "evidence_supported" and h.confidence == 7

    (repo / "app" / "views.py").write_text("def search(request):\n    return 'rewritten'\n")
    git = ["git", "-c", "user.email=a@b", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    subprocess.run(git + ["commit", "-qam", "rewrite"], cwd=repo, check=True)
    runner.reconcile(rp)
    again = db.get_hypothesis(rp, h.id)
    assert again.status == "initial" and again.confidence == 7
