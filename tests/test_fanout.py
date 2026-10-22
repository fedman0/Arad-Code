import asyncio
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cache import completed_skills, mark_skill_done
from core.fanout import (
    Target, assignment, batch_key, coverage_key, inventory, make_batches, normalize_method,
    normalize_route_path, parse_graph_routes, uncovered,
)
from core.llm import Reply
from core.models import EntryPoint
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
    def __init__(self, skip=()):
        self.skip = set(skip)
        self.prompts = []

    async def complete_turn(self, messages, tools, system=None, tool_choice=None, **extra):
        first = messages[0]["content"]
        self.prompts.append(first)
        names = re.findall(r"^- (.+?) \| ", first, re.M)
        coverage = [{"kind": "entry_point", "name": n, "status": "no_issue_found"}
                    for n in names if n not in self.skip]
        args = {"findings": {"hypotheses": [], "coverage": coverage, "open_questions": []}}
        return Reply(None, [tc(len(self.prompts), "finish", args)], "tool_calls")


class GraphMCP:
    def __init__(self, rows):
        self.rows = rows

    async def find_project_for_repo(self, repo):
        return "proj"

    async def query_graph(self, query, project=None, max_rows=None, fmt=None):
        assert "Route" in query and project == "proj" and fmt == "json"
        return {"columns": ["qn", "src"], "rows": self.rows}

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
    done = completed_skills(rp, commit)
    assert "review-test" in done and sum(1 for d in done if d.startswith("review-test#")) == 2
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
    mark_skill_done(rp, commit, batch_key("review-test", "01", first))
    asyncio.run(runner._run_skill_list(["review-test"], rp, False, True))
    assert len(llm.prompts) == 1
    llm.prompts.clear()
    mark_skill_done(rp, commit, batch_key("review-test", "01", first))
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
