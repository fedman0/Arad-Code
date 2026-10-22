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

    async def query_graph_text(self, query, project=None, max_rows=None):
        self.calls.append(("query_graph", {"query": query, "project": project, "max_rows": max_rows})); return "rows: 1"

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
