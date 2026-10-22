import asyncio
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cache import completed_skills, fanout_progress, record_fanout
from core.fanout import (
    Target, assignment, coverage_key, inventory, make_batches, normalize_method,
    normalize_route_path, parse_graph_routes, uncovered,
)
from core.llm import Reply
from core.models import CoverageItem, EntryPoint
from core.usage import BudgetExceeded
from core.skills import SkillCatalog, SkillFormatError
from fakes_engine import make_repo, make_runner, tc


def ep(path, method=None, handler="h", file_path="routes/x.ts", line=1, kind="route"):
    return EntryPoint(kind=kind, path=path, method=method, handler_qn=handler, file_path=file_path, line=line)


def test_methods_and_paths_are_normalised():
    assert normalize_method("POST POST", "/api/Feedbacks") == "POST"
    assert normalize_method(None, "GET /x") == "GET"
    assert normalize_method("ALL", "/x") == normalize_method("", "/x") == "ANY"
    assert normalize_route_path("POST /api/Feedbacks (finale)") == "/api/Feedbacks"
    assert normalize_route_path("rest/x") == "/rest/x"
    assert normalize_route_path("  ") == ""


def test_inventory_merges_duplicates_and_keeps_the_richest():
    items = inventory([
        ep("/api/Feedbacks", "POST", handler="finale", file_path="server.ts", line=0),
        ep("POST /api/Feedbacks", "POST POST", handler="finale.resource(Feedback).create", file_path="server.ts", line=521),
        ep("/rest/basket/:id", "GET", handler="retrieveBasket", file_path="routes/basket.ts", line=15),
        ep("/rest/basket/{bid}", "get", handler="b", file_path="", line=0),
        ep("/ftp", "ANY", handler="serveIndex"),
        ep("orders.created", None, kind="consumer", handler="onOrder"),
    ], [("GET", "/rest/basket/:id", "server.ts"), ("ANY", "/api/Feedbacks", "server.ts"),
        ("DELETE", "/api/Feedbacks/:id", "server.ts")])
    names = [t.name for t in items]
    assert names.count("POST /api/Feedbacks") == 1 and "ANY /api/Feedbacks" not in names
    fb = next(t for t in items if t.name == "POST /api/Feedbacks")
    assert fb.line == 521 and fb.source == "p1"
    basket = [t for t in items if "/rest/basket" in t.path]
    assert len(basket) == 1 and basket[0].handler == "retrieveBasket"
    assert any(t.name == "DELETE /api/Feedbacks/:id" and t.source == "graph" for t in items)
    assert "ANY /ftp" in names and "consumer orders.created" in names


def test_batches_cover_everything_once_and_group_by_area():
    targets = [Target("route", "GET", f"/rest/basket/{i}") for i in range(5)] + \
              [Target("route", "POST", f"/api/Users/{i}") for i in range(3)] + \
              [Target("route", "GET", "/ftp"), Target("job", "", "nightly")]
    plan = make_batches(targets, 4)
    flat = [t for b in plan for t in b]
    assert sorted(t.name for t in flat) == sorted(t.name for t in targets)
    assert all(len(b) <= 4 for b in plan)
    assert make_batches(targets, 4) == plan
    assert all(t.path.startswith("/rest/basket") for t in plan[[i for i, b in enumerate(plan) if b[0].path.startswith("/rest/basket")][0]])


def test_coverage_names_are_matched_loosely():
    chunk = [Target("route", "GET", "/rest/basket/:id"), Target("route", "POST", "/api/Users"),
             Target("route", "ANY", "/ftp"), Target("job", "", "nightly cleanup")]
    names = ["get /rest/basket/{id} | handler retrieveBasket", "/ftp", "job nightly cleanup"]
    assert [t.name for t in uncovered(chunk, names)] == ["POST /api/Users"]
    assert coverage_key("GET /a/:x") == coverage_key("GET /a/<y>")


def test_graph_rows_are_parsed():
    rows = {"columns": ["qn", "src"], "rows": [["__route__GET__/rest/x", "server.ts"],
                                                 ["__route__ANY__/ftp", "server.ts"], ["not a route", "x"], []]}
    assert parse_graph_routes(rows) == [("GET", "/rest/x", "server.ts"), ("ANY", "/ftp", "server.ts")]
    assert parse_graph_routes("text") == [] and parse_graph_routes(None) == []


def test_assignment_lists_every_target_with_its_name_first():
    text = assignment([Target("route", "GET", "/a", "h", "routes/a.ts", 3),
                       Target("route", "PUT", "/b", "", "server.ts"), Target("route", "GET", "/c")], 2, 5)
    assert "batch 2 of 5" in text
    assert "- GET /a | handler h (routes/a.ts:3)" in text
    assert "- PUT /b | registered in server.ts; resolve the handler first" in text
    assert "- GET /c | handler not resolved" in text


@pytest.mark.parametrize("header,msg", [("fanout: modules", "fanout"), ("batch: 0", "batch"), ("batch: x", "batch")])
def test_bad_fanout_headers_are_errors(tmp_path, header, msg):
    d = tmp_path / "s" / "p4"
    d.mkdir(parents=True)
    (d / "x.md").write_text(f"---\n{header}\n---\n# x\n")
    with pytest.raises(SkillFormatError, match=msg):
        SkillCatalog(tmp_path / "s").find("x")


SKILL = "---\nfanout: entry_points\nbatch: 2\nmax_turns: 10\n---\n\n# SKILL: review-test\nReview the assigned entry points.\n"


class Reviewer:
    def __init__(self, skip=(), status="no_issue_found", stop_at=None, found=None):
        self.skip = set(skip)
        self.status = status
        self.stop_at = stop_at
        self.found = found
        self.prompts = []

    async def complete_turn(self, messages, tools, system=None, tool_choice=None, **extra):
        first = messages[0]["content"]
        self.prompts.append(first)
        if self.stop_at == len(self.prompts):
            raise BudgetExceeded("budget reached")
        names = re.findall(r"^- (.+?) \| ", first, re.M)
        coverage = [{"kind": "entry_point", "name": n, "status": self.status}
                    for n in names if n not in self.skip]
        args = {"findings": {"hypotheses": [], "coverage": coverage, "open_questions": []}}
        if self.found and len(self.prompts) == 1:
            args["findings"]["entry_points_found"] = [self.found]
        return Reply(None, [tc(len(self.prompts), "finish", args)], "tool_calls")


class GraphMCP:
    def __init__(self, rows, page=0):
        self.rows = rows
        self.page = page
        self.calls = []

    async def find_project_for_repo(self, repo):
        return "proj"

    async def query_graph(self, query, project=None, max_rows=None, fmt=None, **kw):
        assert "Route" in query and project == "proj" and fmt == "json" and max_rows is None
        self.calls.append(kw)
        if not self.page:
            return {"columns": ["qn", "src"], "rows": self.rows}
        start = int(kw.get("cursor", "c0")[1:])
        end = start + self.page
        more = end < len(self.rows)
        return {"columns": ["qn", "src"], "rows": self.rows[start:end], "has_more": more,
                **({"next_cursor": f"c{end}", "next_offset": end} if more else {})}

    async def close(self):
        pass


def fanout_runner(tmp_path, graph_rows=(), skip=()):
    runner, db = make_runner(tmp_path)
    skills = tmp_path / "skills"
    shutil.copytree(Path(__file__).resolve().parent.parent / "skills" / "p0", skills / "p0")
    (skills / "p4").mkdir(parents=True)
    (skills / "p4" / "review-test.md").write_text(SKILL)
    runner._skills = SkillCatalog(skills)
    runner._mcp = GraphMCP([list(r) for r in graph_rows])
    rp = str(make_repo(tmp_path / "repo"))
    for path, method, f in [("/rest/basket/:id", "GET", "routes/basket.ts"),
                            ("/rest/basket/:id/checkout", "POST", "routes/order.ts"),
                            ("/api/Users", "POST", "routes/users.ts")]:
        db.save_entry_point(rp, ep(path, method, handler=f"h{len(path)}", file_path=f, line=3), "c")
    llm = Reviewer(skip)
    runner._llm = llm
    return runner, db, rp, llm


def test_a_fanout_skill_runs_one_batch_per_group_with_its_assignment(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path, graph_rows=[("__route__GET__/ftp", "server.ts")])
    events = []
    results = asyncio.run(runner._run_skill_list(["review-test"], rp, False, False,
                                                 on_progress=lambda n, s, r: events.append((n, s))))
    assert len(results) == 2 and len(llm.prompts) == 2
    assigned = sorted(n for p in llm.prompts for n in re.findall(r"^- (.+?) \| ", p, re.M))
    assert assigned == ["GET /ftp", "GET /rest/basket/:id", "POST /api/Users", "POST /rest/basket/:id/checkout"]
    assert ("review-test#01", "started") in events and ("review-test#02", "done") in events
    commit = runner._get_commit(rp)
    assert completed_skills(rp, commit) == {"review-test"}
    progress = fanout_progress(rp, commit, "review-test")
    assert sorted(progress["reviewed"]) == assigned and progress["undecided"] == []
    scopes = {json.loads(f.read_text().splitlines()[0])["scope"] for f in (tmp_path / "transcripts").rglob("*.jsonl")}
    assert scopes == {"review-test#01", "review-test#02"}


def test_entry_points_left_without_a_decision_are_retried_then_flagged(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path, skip={"POST /api/Users"})
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    retry = [p for p in llm.prompts if "POST /api/Users" in p]
    assert len(retry) == 2 and "batch 1 of 1" in retry[1]
    cov = {c["name"]: c for c in db.coverage_detail(rp) if c["kind"] == "entry_point"}
    assert cov["POST /api/Users"]["status"] == "needs_follow_up"
    assert "two attempts" in (cov["POST /api/Users"]["blocker"] or "")


def test_resume_skips_finished_batches_and_a_fresh_run_redoes_them(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path)
    targets = inventory(db.list_entry_points(rp))
    first = make_batches(targets, 2)[0]
    commit = runner._get_commit(rp)
    record_fanout(rp, commit, "review-test", False, [t.name for t in first], [])
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, True))
    assert len(llm.prompts) == 1
    llm.prompts.clear()
    record_fanout(rp, commit, "review-test", False, [t.name for t in first], [])
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    assert len(llm.prompts) == 2


def test_without_any_inventory_the_skill_runs_once_and_finds_entry_points_itself(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path)
    db.conn.execute("DELETE FROM entry_points")
    db.conn.commit()
    results = asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    assert len(results) == 1 and "No entry points have been recorded" in llm.prompts[0]


def test_running_a_fanout_skill_directly_returns_one_combined_result(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path)
    res = asyncio.run(runner.run_skill("review-test", rp))
    assert res.skill_name == "review-test" and len(llm.prompts) == 2
    assert len([c for c in res.coverage if c.kind == "entry_point"]) == 3
    assert res.usage["calls"] == 0 or isinstance(res.usage, dict)


def test_batch_prompts_put_the_assigned_area_first_in_known_findings(tmp_path):
    from core.models import Hypothesis
    runner, db, rp, llm = fanout_runner(tmp_path)
    for i in range(70):
        db.save_hypothesis(rp, Hypothesis(actor="a", capability="c", entry_point=f"GET /other/{i}",
                                          security_boundary="b", violated_invariant=f"rule {i}",
                                          observable_impact=f"impact {i}", severity=9, confidence=7))
    db.save_hypothesis(rp, Hypothesis(actor="a", capability="c", entry_point="POST /api/Users -> routes/users.ts",
                                      security_boundary="b", violated_invariant="role from the body",
                                      observable_impact="admin", severity=1, confidence=1))
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    users = next(p for p in llm.prompts if "- POST /api/Users |" in p)
    assert "role from the body" in users
    other = next(p for p in llm.prompts if "- POST /api/Users |" not in p)
    assert "role from the body" not in other


def coverage(db, rp):
    return {c["name"]: (c["status"], c["blocker"]) for c in db.coverage_detail(rp) if c["kind"] == "entry_point"}


def batch_of(llm, name):
    return next(i for i, p in enumerate(llm.prompts) if f"- {name} |" in p)


def test_resume_retries_what_a_finished_batch_left_undecided(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path, skip={"GET /rest/basket/:id"})
    llm.stop_at = 2
    with pytest.raises(BudgetExceeded):
        asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    first = llm.prompts[0]
    llm.prompts.clear()
    llm.stop_at = None
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, True))
    assigned = [re.findall(r"^- (.+?) \| ", p, re.M) for p in llm.prompts]
    assert "- GET /rest/basket/:id |" in first
    assert ["GET /rest/basket/:id"] in assigned and len(assigned) == 2
    assert not any("POST /rest/basket/:id/checkout" in a for a in assigned)
    cov = coverage(db, rp)
    assert cov["GET /rest/basket/:id"][0] == "needs_follow_up"
    assert "review-test" in completed_skills(rp, runner._get_commit(rp))


def test_resume_after_a_stop_in_the_retry_pass_retries_and_flags(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path, skip={"POST /api/Users"})
    llm.stop_at = 3
    with pytest.raises(BudgetExceeded):
        asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    llm.prompts.clear()
    llm.stop_at = None
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, True))
    assert len(llm.prompts) == 1 and "- POST /api/Users |" in llm.prompts[0]
    assert coverage(db, rp)["POST /api/Users"][0] == "needs_follow_up"


def test_resume_does_not_review_finished_entries_again_when_the_inventory_grows(tmp_path):
    found = {"kind": "route", "path": "/rest/basket/:id/apply", "method": "PUT",
             "handler_qn": "applyCoupon", "file_path": "routes/coupon.ts", "line": 9}
    runner, db, rp, llm = fanout_runner(tmp_path)
    llm.found = found
    llm.stop_at = 2
    with pytest.raises(BudgetExceeded):
        asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    done = re.findall(r"^- (.+?) \| ", llm.prompts[0], re.M)
    llm.prompts.clear()
    llm.stop_at = None
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, True))
    again = [n for p in llm.prompts for n in re.findall(r"^- (.+?) \| ", p, re.M)]
    assert "PUT /rest/basket/:id/apply" in again
    assert not set(done) & set(again)


def test_a_direct_fanout_run_passes_the_user_context_to_every_batch(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path)
    asyncio.run(runner.run_skill("review-test", rp, "USER-CONTEXT-42"))
    assert len(llm.prompts) == 2 and all("USER-CONTEXT-42" in p for p in llm.prompts)
    db.conn.execute("DELETE FROM entry_points")
    db.conn.commit()
    llm.prompts.clear()
    asyncio.run(runner.run_skill("review-test", rp, "USER-CONTEXT-42"))
    assert len(llm.prompts) == 1 and "USER-CONTEXT-42" in llm.prompts[0]


def test_a_budget_stop_in_a_direct_run_reports_the_saved_batches(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path)
    llm.stop_at = 2
    with pytest.raises(BudgetExceeded) as info:
        asyncio.run(runner.run_skill("review-test", rp))
    exc = info.value
    assert exc.saved_batches == 1 and len(exc.partial.coverage) == 2
    assert fanout_progress(rp, runner._get_commit(rp), "review-test") == {}
    assert completed_skills(rp, runner._get_commit(rp)) == set()


def test_the_cli_says_which_batches_were_saved(tmp_path, monkeypatch):
    from click.testing import CliRunner
    import pentest
    runner, db, rp, llm = fanout_runner(tmp_path)
    llm.stop_at = 2
    monkeypatch.setattr(pentest, "_make_deps", lambda *a, **k: (runner._cfg, db, runner._mcp, runner))
    out = CliRunner().invoke(pentest.cli, ["skill", "review-test", rp])
    assert "1 finished batch(es) of this skill were saved" in out.output
    assert "nothing from this skill was saved" not in out.output


def test_the_flag_never_overwrites_a_decision_and_a_later_decision_clears_it(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path, skip={"POST /api/Users", "GET /rest/basket/:id"})
    db.upsert_coverage(rp, CoverageItem(kind="entry_point", name="POST /api/Users", status="reported"))
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    cov = coverage(db, rp)
    assert cov["POST /api/Users"] == ("reported", None)
    assert cov["GET /rest/basket/:id"][0] == "needs_follow_up"
    runner._llm = Reviewer()
    runner._llm.skip = set()
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    assert coverage(db, rp)["GET /rest/basket/:id"] == ("no_issue_found", None)
    db.upsert_coverage(rp, CoverageItem(kind="entry_point", name="GET /rest/basket/:id", status="needs_follow_up",
                                        blocker="review-test reached no decision on it in two attempts"), force=True)
    llm2 = Reviewer()
    runner._llm = llm2

    async def named(messages, tools, system=None, tool_choice=None, **extra):
        first = messages[0]["content"]
        llm2.prompts.append(first)
        names = re.findall(r"^- (.+?) \| (.+?) \| ", first, re.M)
        cov = [{"kind": "entry_point", "name": f"{n} | {w}", "status": "no_issue_found"} for n, w in names]
        return Reply(None, [tc(len(llm2.prompts), "finish", {"findings": {
            "hypotheses": [], "coverage": cov, "open_questions": []}})], "tool_calls")
    llm2.complete_turn = named
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    assert "GET /rest/basket/:id" not in coverage(db, rp)


def test_unseen_is_not_a_decision(tmp_path):
    runner, db, rp, llm = fanout_runner(tmp_path, graph_rows=[("__route__GET__/ftp", "server.ts")])
    llm.status = "unseen"
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, False))
    assert len(llm.prompts) == 4
    assert {s for s, _ in coverage(db, rp).values()} == {"needs_follow_up"}


def test_combined_merges_are_listed_once(tmp_path):
    from core.models import SkillResult
    runner, db, rp, llm = fanout_runner(tmp_path)
    parts = [SkillResult(skill_name="review-test", repo_path=rp, commit="c", merged=["p1"]),
             SkillResult(skill_name="review-test", repo_path=rp, commit="c", merged=["p1", "p2"])]
    assert runner._combine("review-test", rp, parts).merged == ["p1", "p2"]


def test_graph_routes_are_read_page_by_page(tmp_path):
    rows = [(f"__route__GET__/api/r{i}", "server.ts") for i in range(7)]
    runner, db, rp, llm = fanout_runner(tmp_path, graph_rows=rows)
    runner._mcp.page = 3
    routes = asyncio.run(runner._graph_routes(rp))
    assert [p for _, p, _ in routes] == [f"/api/r{i}" for i in range(7)]
    assert runner._mcp.calls == [{}, {"cursor": "c3"}, {"cursor": "c6"}]


def test_routes_called_from_tests_are_not_entry_points():
    rows = {"rows": [["__route__GET__/rest/x", "test/api/http.test.ts", "true"],
                     ["__route__GET__/whatever", "frontend/src/app/a.component.spec.ts", "false"],
                     ["__route__GET__/api/Cards", "data/static/codefixes/fix_1.ts", "false"],
                     ["__route__GET__/api/Cards", "server.ts", "false"],
                     ["__route__POST__/api/Cards", "server.ts", "false"],
                     ["__route__GET__/real", "routes/a.ts", None]]}
    routes = parse_graph_routes(rows)
    assert [p for _, p, _ in routes] == ["/api/Cards", "/api/Cards", "/api/Cards", "/real"]
    cards = [t for t in inventory([], routes) if t.name == "GET /api/Cards"]
    assert cards[0].file_path == "server.ts"


def test_a_richer_any_route_is_kept_next_to_a_specific_method():
    items = inventory([ep("/api/Quantitys/:id", None, handler="finale.resource(Quantity)", file_path="server.ts",
                          line=454)], [("DELETE", "/api/Quantitys/{}", "server.ts")])
    names = {t.name: t for t in items}
    assert names["ANY /api/Quantitys/:id"].line == 454 and "DELETE /api/Quantitys/{}" in names
    graph_only = inventory([], [("ANY", "/api/Feedbacks/{}", "server.ts"), ("PUT", "/api/Feedbacks/{}", "server.ts")])
    assert [t.name for t in graph_only] == ["ANY /api/Feedbacks/{}", "PUT /api/Feedbacks/{}"]


def test_a_p1_entry_with_several_methods_or_paths_becomes_several_targets():
    names = lambda *eps: sorted(t.name for t in inventory(list(eps)))
    assert names(ep("/promotion, /video", "GET")) == ["GET /promotion", "GET /video"]
    assert names(ep("GET|POST /ftp, /ftp/:file", "GET")) == ["GET /ftp", "GET /ftp/:file", "POST /ftp", "POST /ftp/:file"]
    assert len(names(ep("/api/BasketItems[/:id]", "GET|POST|PUT|DELETE"))) == 8
    assert names(ep("/snippets/verdict", "GET/DELETE")) == ["DELETE /snippets/verdict", "GET /snippets/verdict"]
    assert names(ep("HTTP :3000 (Express app)"), ep("memory handlers (path registration not read)", "GET")) == []
    assert normalize_route_path("/support/logs,") == "/support/logs"


def test_non_route_coverage_is_matched_without_the_location():
    chunk = [Target("consumer", "", "orders.created", "onOrder", "workers/orders.ts", 12),
             Target("job", "", "metrics updateLoop (5000 ms interval)")]
    assert uncovered(chunk, ["consumer orders.created | handler onOrder (workers/orders.ts:12)",
                             "job metrics updateLoop"]) == []
    assert uncovered(chunk, ["consumer orders.created (onOrder)", "job metrics updateLoop every 5s"]) == []
    assert [t.name for t in uncovered(chunk, ["consumer orders.deleted"])] == [
        "consumer orders.created", "job metrics updateLoop (5000 ms interval)"]


def test_pentest_run_counts_skills_not_batches_and_offers_to_resume(tmp_path, monkeypatch):
    from click.testing import CliRunner
    import pentest
    runner, db, rp, llm = fanout_runner(tmp_path)
    llm.stop_at = 2
    monkeypatch.setattr(pentest, "_make_deps", lambda *a, **k: (runner._cfg, db, runner._mcp, runner))
    out = CliRunner().invoke(pentest.cli, ["run", rp, "--phase", "p4"])
    assert "0 skill(s) saved, plus finished batches of 1 fan-out skill(s)" in " ".join(out.output.split())
    llm.prompts.clear()
    llm.stop_at = None
    out = CliRunner().invoke(pentest.cli, ["run", rp, "--phase", "p4"], input="y\n")
    assert "with 0 of 1 skill(s) already done, 1 partly done" in " ".join(out.output.split())
    assert len(llm.prompts) == 1


@pytest.mark.parametrize("header", ["max_turns: .inf", "max_turns: -.inf", "batch: .inf", "order: .inf"])
def test_infinite_header_numbers_name_the_file(tmp_path, header):
    d = tmp_path / "s" / "p4"
    d.mkdir(parents=True)
    (d / "x.md").write_text(f"---\n{header}\n---\n# x\n")
    with pytest.raises(SkillFormatError, match=r"x\.md"):
        SkillCatalog(tmp_path / "s").find("x")
