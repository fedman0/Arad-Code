import asyncio
import traceback

import pytest

from core.models import NegativeEvidence
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc


class Checks:
    def __init__(self):
        self.failed = []

    def __call__(self, name, cond, extra=""):
        if not cond:
            self.failed.append((name, extra))

    def verify(self):
        if self.failed:
            pytest.fail("\n".join(f"FAIL {name}  <- {extra}" for name, extra in self.failed), pytrace=False)


def hyp(**kw):
    d = dict(actor="unauthenticated attacker", capability="sqli", entry_point="app/views.py:search",
             security_boundary="HTTP", violated_invariant="user input concatenated into SQL — search() name",
             observable_impact="read all users", severity=9, confidence=7, reachability="proven",
             input_control="full", guard_coverage="no_paths", exposure="internet", cwe="CWE-89",
             proof_obligations=[])
    d.update(kw)
    return d


def ev(idx, **kw):
    d = dict(kind="code", description="concat", file_path="app/views.py", line_start=4, line_end=4,
             snippet="x", hypothesis_index=idx, anchor_text="cursor.execute(\"SELECT * FROM users",
             analysis_quality={"method": "structural", "confidence": "high"})
    d.update(kw)
    return d


async def scan_rescan_reconcile(check, repo, tmp):
    runner, db = make_runner(tmp)
    rp = str(repo)

    llm = ScriptedLLM([
        [tc(1, "search_graph", {"name_pattern": "search"}),
         tc(2, "grep", {"pattern": "--pre=sh", "file_glob": "*.py"}),
         tc(3, "grep", {"pattern": "pull_request_target"}),
         tc(4, "grep", {"pattern": "a(?!b)"}),
         tc(5, "trace_path", {"function_name": "search", "mode": "called_by"}),
         tc(6, "search_code", {"pattern": "a|b", "regex": True}),
         tc(7, "read_file", {"file_path": "app/views.py", "end_line": 2}),
         tc(8, "read_file", {"file_path": "app/views.py", "start_line": 99})],
        "Let me think about this some more.",
        [tc(9, "finish", {"findings": {
            "hypotheses": [hyp(exposure="network", violated_invariant="first bad exposure"),
                           hyp(status="human_confirmed", id="deadbeef", violated_invariant="second"),
                           hyp(severity=12, violated_invariant="third")],
            "evidence": [ev(0), ev(1), ev(2, anchor_text="cursor.execute(\"SELECT", line_start=2, line_end=2)],
            "coverage": None,
            "open_questions": None,
            "entry_points_found": None,
        }})],
    ])
    runner._llm = llm
    res = await runner.run_skill("hunt-injection-sqli-cmdi", rp)
    tool_msgs = [m for m in llm.calls[-1]["messages"] if m.get("role") == "tool"]
    by_id = {m["tool_call_id"]: m["content"] for m in tool_msgs}
    check("grep '--pre=sh' treated as pattern", "No matches" in by_id["call_2"] or "grep error" not in by_id["call_2"], by_id["call_2"][:200])
    check("hidden .github searched", ".github" in by_id["call_3"], by_id["call_3"][:200])
    check("regex error surfaced", by_id["call_4"].startswith("grep error"), by_id["call_4"][:200])
    check("called_by mapped to inbound", '"direction": "inbound"' in by_id["call_5"] and '"mode": "calls"' in by_id["call_5"], by_id["call_5"])
    check("search_code regex forwarded", '"regex": true' in by_id["call_6"], by_id["call_6"])
    check("read_file end_line only", by_id["call_7"].startswith("   1:") and "2:" in by_id["call_7"], by_id["call_7"])
    check("read_file past end", "past the end" in by_id["call_8"], by_id["call_8"])
    check("text-only reply nudged instead of ending", any("Continue the skill" in str(m.get("content")) for m in llm.calls[-1]["messages"]))
    check("three hypotheses kept", len(res.hypotheses) == 3, [h.violated_invariant for h in res.hypotheses])
    h0, h1, h2 = res.hypotheses
    check("invalid exposure coerced", h0.exposure == "unspecified" and any("exposure" in u for u in h0.uncertainty), h0.exposure)
    check("model cannot self-confirm", h1.status != "human_confirmed", h1.status)
    check("model cannot pick id", h1.id != "deadbeef")
    check("severity clamped", h2.severity == 10, h2.severity)
    ev_by_h = {}
    for e in res.evidence:
        ev_by_h.setdefault(e.hypothesis_id, []).append(e)
    check("each hypothesis got its own evidence", all(len(ev_by_h.get(h.id, [])) == 1 for h in res.hypotheses), {k: len(v) for k, v in ev_by_h.items()})
    e2 = ev_by_h[h2.id][0]
    check("ambiguous anchor flagged stale (two matches)", e2.stale, e2.analysis_quality.limitations)
    check("open_questions null handled", "None" not in res.open_questions, res.open_questions)

    llm2 = ScriptedLLM([[tc(1, "search_graph", {"name_pattern": "search"}),
                         tc(2, "finish", {"findings": {"hypotheses": [hyp(violated_invariant="first bad exposure", exposure="network")],
                                                        "evidence": [ev(0, file_path=str(repo / "app" / "views.py"))],
                                                        "coverage": [], "open_questions": []}})]])
    runner._llm = llm2
    res2 = await runner.run_skill("hunt-injection-sqli-cmdi", rp)
    merged = res2.hypotheses[0]
    check("rescan merges onto existing id", merged.id == h0.id, (merged.id, h0.id))
    evs = db.get_all_evidence_for_hypothesis(h0.id)
    check("rescan evidence attached to merged id", len(evs) >= 2, len(evs))
    check("absolute evidence path normalised", all(not e.file_path.startswith("/") for e in evs), [e.file_path for e in evs])
    orphans = [e for e in db.list_all_evidence_for_repo(rp) if db.get_hypothesis(rp, e.hypothesis_id) is None]
    check("no orphaned evidence", not orphans, len(orphans))

    ne = NegativeEvidence(entry_point="app/views.py:search", safe_from="CWE-89", because="x",
                          anchor_file="app/views.py", anchor_line=4,
                          anchor_text="cursor.execute(\"SELECT * FROM users")
    db.save_negative_evidence(rp, ne)
    try:
        s = runner.reconcile(rp)
        check("reconcile contradiction path does not crash", True)
        check("contradiction found", s["contradictions_found"] >= 1, s)
        check("NE marked disputed", any(n.disputed for n in db.list_negative_evidence(rp)))
    except Exception as ex:
        check("reconcile contradiction path does not crash", False, repr(ex))


def test_skill_run_rescan_and_reconcile(tmp_path):
    check = Checks()
    repo = make_repo(tmp_path / "repo")
    work = tmp_path / "work"
    work.mkdir()
    try:
        asyncio.run(scan_rescan_reconcile(check, repo, work))
    except Exception:
        check("scan, rescan and reconcile ran to completion", False, traceback.format_exc())
    check.verify()


def test_skill_scheduling_order(tmp_path):
    check = Checks()
    runner, db = make_runner(tmp_path)
    order = runner._all_skills()
    p1 = [n for n in order if n in ("inventory-repository", "resolve-build-context", "map-entry-points", "resolve-dependency-injection")]
    check("p1 runs in declared order", p1 == ["inventory-repository", "resolve-build-context", "map-entry-points", "resolve-dependency-injection"], p1)
    check("p0 scheduled before each phase", order.count("resolve-open-questions") == 5, order.count("resolve-open-questions"))
    check("phase digits accepted", runner._phase_skills("4") == runner._phase_skills("p4"))
    check.verify()
