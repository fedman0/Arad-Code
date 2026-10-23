import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Config
from core.memory_mcp import CodebaseMemoryClient
from core.tool_specs import TOOLS, _PROMPT_TOOL_NAMES
from fakes_engine import make_repo, make_runner


class Recorder:
    def __init__(self):
        self.calls = []

    async def find_project_for_repo(self, repo):
        return "proj"

    async def search_graph(self, **kw):
        self.calls.append(("search_graph", kw)); return "rows"

    async def trace_path(self, **kw):
        self.calls.append(("trace_path", kw)); return "chain"

    async def get_code_snippet(self, qn, project=None, **kw):
        self.calls.append(("get_code_snippet", {"qn": qn, "project": project, **kw})); return "src"

    async def query_graph_text(self, query, project=None, max_rows=None, **kw):
        self.calls.append(("query_graph", {"query": query, "project": project, "max_rows": max_rows, **kw}))
        return "rows: 1"

    async def close(self):
        pass


def run(tmp_path, name, args):
    runner, _ = make_runner(tmp_path)
    rec = Recorder()
    runner._mcp = rec
    rp = str(make_repo(tmp_path / "repo"))
    out = asyncio.run(runner._execute_tool(name, args, rp))
    return out, rec.calls


def test_search_graph_passes_meaning_and_keyword_search(tmp_path):
    out, calls = run(tmp_path, "search_graph", {"query": "sql login", "file_pattern": "routes/", "limit": 999,
                                                "project": "evil", "format": "json", "semantic_query": ["x"]})
    assert out == "rows"
    kw = calls[0][1]
    assert kw["query"] == "sql login" and kw["file_pattern"] == "routes/" and kw["limit"] == 200
    assert kw["project"] == "proj" and "format" not in kw and "semantic_query" not in kw


def test_semantic_query_accepts_a_string_and_caps_the_list(tmp_path):
    _, calls = run(tmp_path, "search_graph", {"semantic_query": "runs a shell command"})
    assert calls[0][1]["semantic_query"] == ["runs a shell command"]
    _, calls = run(tmp_path / "b", "search_graph", {"semantic_query": [str(i) for i in range(9)] + [" "]})
    assert calls[0][1]["semantic_query"] == ["0", "1", "2", "3", "4"]


def test_trace_path_supports_data_flow_and_clamps(tmp_path):
    _, calls = run(tmp_path, "trace_path", {"function_name": "f", "mode": "data_flow", "parameter_name": "req",
                                            "risk_labels": True, "depth": 50, "edge_types": ["X"]})
    kw = calls[0][1]
    assert kw["mode"] == "data_flow" and kw["parameter_name"] == "req" and kw["risk_labels"] is True
    assert kw["depth"] == 10 and "edge_types" not in kw and kw["project"] == "proj"
    _, calls = run(tmp_path / "b", "trace_path", {"function_name": "f", "mode": "topology"})
    assert calls[0][1]["mode"] == "calls"
    _, calls = run(tmp_path / "c", "trace_path", {"function_name": "f", "mode": "called_by"})
    assert calls[0][1]["mode"] == "calls" and calls[0][1]["direction"] == "inbound"


def test_trace_path_points_at_find_all_usages_when_the_graph_has_no_node(tmp_path):
    runner, _ = make_runner(tmp_path)
    rec = Recorder()

    async def missing(**kw):
        return json.dumps({"error": "function not found", "function_name": kw["function_name"]})
    rec.trace_path = missing
    runner._mcp = rec
    rp = str(make_repo(tmp_path / "repo"))
    out = asyncio.run(runner._execute_tool("trace_path", {"function_name": "lib.challengeUtils.solveIf"}, rp))
    assert out.startswith("{") and 'find_all_usages(symbol_name="solveIf")' in out
    out, _ = run(tmp_path / "b", "trace_path", {"function_name": "f"})
    assert out == "chain"


def test_code_snippet_extras(tmp_path):
    _, calls = run(tmp_path, "get_code_snippet", {"qualified_name": "a.b", "include_neighbors": True,
                                                  "max_lines": 9999, "start_line": 40, "source_mode": "bogus"})
    kw = calls[0][1]
    assert kw["qn"] == "a.b" and kw["include_neighbors"] is True and kw["max_lines"] == 500
    assert kw["start_line"] == 40 and "source_mode" not in kw


def test_query_graph_is_read_only_and_scoped(tmp_path):
    out, calls = run(tmp_path, "query_graph", {"query": "MATCH (f:Function) RETURN f.name", "max_rows": 10000})
    assert out == "rows: 1" and calls[0][1] == {"query": "MATCH (f:Function) RETURN f.name", "project": "proj", "max_rows": 500}
    for q in ("CREATE (n:X) RETURN n", "MATCH (n) DETACH DELETE n", "MATCH (n) SET n.x = 1", "CALL db.labels()", ""):
        out, calls = run(tmp_path / str(abs(hash(q))), "query_graph", {"query": q})
        assert not calls and ("read-only" in out or "required" in out)


def test_query_graph_is_offered_to_skills_and_prompts():
    names = [t["function"]["name"] for t in TOOLS]
    assert "query_graph" in names and names[-1] == "finish" and "query_graph" in _PROMPT_TOOL_NAMES


class Wire(CodebaseMemoryClient):
    def __init__(self):
        super().__init__(Config(api_key="k"))
        self.sent = []

    async def _call(self, tool, args, timeout=0):
        self.sent.append((tool, dict(args)))
        return {"rows": []} if tool == "query_graph" else "ok"


def test_client_forwards_only_present_extras():
    c = Wire()
    asyncio.run(c.search_graph(query="q", semantic_query=None, limit=5, project="p"))
    asyncio.run(c.trace_path("f", mode="data_flow", depth=2, project="p", parameter_name="req", risk_labels=None))
    asyncio.run(c.get_code_snippet("a.b", project="p", include_neighbors=True, max_lines=None))
    text = asyncio.run(c.query_graph_text("MATCH (n) RETURN n", project="p", max_rows=3))
    assert c.sent[0] == ("search_graph", {"limit": 5, "project": "p", "query": "q"})
    assert c.sent[1] == ("trace_path", {"function_name": "f", "mode": "data_flow", "depth": 2, "project": "p",
                                        "parameter_name": "req"})
    assert c.sent[2] == ("get_code_snippet", {"qualified_name": "a.b", "project": "p", "include_neighbors": True})
    assert c.sent[3] == ("query_graph", {"query": "MATCH (n) RETURN n", "project": "p", "max_rows": 3})
    assert json.loads(text) == {"rows": []}


def test_read_only_queries_that_name_write_words_reach_the_graph(tmp_path):
    for i, q in enumerate(["MATCH (r:Route) WHERE r.method = 'DELETE' RETURN r.qualified_name, r.path",
                           "MATCH (f)-[:CALLS]->(g) WHERE g.name = 'merge' RETURN f.qualified_name",
                           "MATCH (f)-[:CALLS]->(g) WHERE g.name IN ['set', 'create', 'remove', 'call'] RETURN f.name",
                           "MATCH (f:Function) WHERE f.qualified_name ENDS WITH '.set' RETURN f.qualified_name",
                           "MATCH (n) RETURN n.set, n.`create`"]):
        out, calls = run(tmp_path / str(i), "query_graph", {"query": q})
        assert out == "rows: 1" and calls[0][1]["query"] == q
    for i, q in enumerate(["MATCH (n) WHERE n.name = 'x' SET n.y = 1", "MATCH (n) // note\nDETACH DELETE n",
                           "MERGE (n:X {name: 'set'})", "match (n) foreach (x in [1] | create (:Y))"]):
        out, calls = run(tmp_path / f"w{i}", "query_graph", {"query": q})
        assert not calls and "read-only" in out


def test_paging_tokens_are_forwarded(tmp_path):
    _, calls = run(tmp_path, "query_graph", {"query": "MATCH (n) RETURN n", "cursor": "q1.abc", "offset": 5})
    assert calls[0][1]["cursor"] == "q1.abc" and "offset" not in calls[0][1]
    _, calls = run(tmp_path / "b", "query_graph", {"query": "MATCH (n) RETURN n", "offset": "100"})
    assert calls[0][1]["offset"] == 100
    _, calls = run(tmp_path / "c", "trace_path", {"function_name": "sink", "cursor": "c1"})
    assert calls[0][1]["cursor"] == "c1"
    _, calls = run(tmp_path / "d", "get_code_snippet", {"qualified_name": "a.B", "source_mode": "outline",
                                                        "member_offset": 50})
    assert calls[0][1]["member_offset"] == 50
    specs = {t["function"]["name"]: t["function"]["parameters"]["properties"] for t in TOOLS}
    assert "cursor" in specs["query_graph"] and "offset" in specs["query_graph"]
    assert "cursor" in specs["trace_path"] and "member_offset" in specs["get_code_snippet"]


def test_list_valued_search_arguments_are_turned_into_text(tmp_path):
    _, calls = run(tmp_path, "search_graph", {"query": ["login", "sql"], "label": ["Function", "Method"],
                                              "name_pattern": ["merge", "set"], "qn_pattern": 5})
    kw = calls[0][1]
    assert kw["query"] == "login sql" and kw["label"] == "Function" and kw["name_pattern"] == "merge|set"
    assert "qn_pattern" not in kw
    _, calls = run(tmp_path / "b", "search_graph", {"semantic_query": [None, "runs sql", 3]})
    assert calls[0][1]["semantic_query"] == ["runs sql"]


def test_trace_depth_matches_the_advertised_default(tmp_path):
    spec = next(t for t in TOOLS if t["function"]["name"] == "trace_path")
    default = spec["function"]["parameters"]["properties"]["depth"]["default"]
    _, calls = run(tmp_path, "trace_path", {"function_name": "query"})
    assert calls[0][1]["depth"] == default == 3
    c = Wire()
    asyncio.run(c.trace_path("query"))
    assert c.sent[0][1]["depth"] == 3


class GraphRows(Recorder):
    def __init__(self, reply):
        super().__init__()
        self.reply = reply

    async def query_graph_text(self, query, project=None, max_rows=None, **kw):
        self.calls.append(("query_graph", {"query": query}))
        return self.reply


def gated(tmp_path, query, reply, evidence=True):
    from fakes_engine import ScriptedLLM, tc
    from test_finish_contract import finish
    from test_turns import ev, hyp
    runner, _ = make_runner(tmp_path)
    runner._mcp = GraphRows(reply)
    rp = str(make_repo(tmp_path / "repo"))
    items = [ev(0, analysis_quality={"method": "semantic"})] if evidence else []
    runner._llm = ScriptedLLM([[tc(1, "query_graph", {"query": query})],
                               [finish([hyp(confidence=9)], items)]] + [[finish([hyp(confidence=9)], items)]] * 2)
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    return res.hypotheses[0], [e.analysis_quality.method for e in res.evidence]


def test_query_graph_counts_as_semantic_only_when_its_rows_name_the_file(tmp_path):
    unrelated = "MATCH (f:Function) WHERE f.name STARTS WITH 'auth' WITH f AS views RETURN views.name"
    h, methods = gated(tmp_path / "a", unrelated, "rows: authA, authB")
    assert methods == ["structural"] and h.confidence <= 7
    refused = "MATCH (f) WHERE f.file_path CONTAINS 'views' DETACH DELETE f"
    h, methods = gated(tmp_path / "b", refused, "unused")
    assert methods != ["semantic"] and h.confidence <= 7
    h, methods = gated(tmp_path / "c", "MATCH (f) WHERE f.file_path CONTAINS 'views' RETURN f", "No rows")
    assert methods != ["semantic"] and h.confidence <= 7
    h, methods = gated(tmp_path / "d", "MATCH (f) WHERE f.file_path CONTAINS 'views' RETURN f.file_path",
                       "app/views.py search -> cursor.execute")
    assert methods == ["semantic"] and h.confidence == 9


def test_a_refused_query_does_not_become_synthetic_semantic_evidence(tmp_path):
    refused = "MATCH (f) WHERE f.file_path CONTAINS 'views' DETACH DELETE f"
    h, methods = gated(tmp_path, refused, "unused", evidence=False)
    assert "semantic" not in methods and h.status == "initial"
