import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Config
from core.memory_mcp import CodebaseMemoryClient, _parse_project_table
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc

TABLE = (
    "projects: 2  (cols: name root_path branch)\n"
    "  alpha /srv/alpha main\n"
    "  beta /srv/my repo/beta -\n"
    "total: 2\n"
    "returned: 2\n"
    "has_more: false\n"
)


class Client(CodebaseMemoryClient):
    def __init__(self, pages):
        super().__init__(Config(api_key="k"))
        self.pages = list(pages)
        self.calls = []

    async def _call(self, tool, args, timeout=0):
        self.calls.append((tool, dict(args)))
        return self.pages.pop(0) if self.pages else None


class NoGraph:
    async def find_project_for_repo(self, repo):
        return None

    async def search_graph(self, **kw):
        raise AssertionError("the server must not be called without a project")

    async def close(self):
        pass


def test_text_table_from_newer_servers_is_parsed():
    rows = _parse_project_table(TABLE)
    assert rows == [
        {"name": "alpha", "root_path": "/srv/alpha", "branch": "main"},
        {"name": "beta", "root_path": "/srv/my repo/beta", "branch": "-"},
    ]
    assert _parse_project_table("nothing indexed\n") == []


def test_list_projects_asks_for_json_and_accepts_every_shape():
    client = Client([TABLE])
    assert [p["name"] for p in asyncio.run(client.list_projects())] == ["alpha", "beta"]
    assert client.calls[0] == ("list_projects", {"format": "json", "limit": 200, "offset": 0})

    client = Client([[{"name": "a", "root_path": "/a"}]])
    assert asyncio.run(client.list_projects()) == [{"name": "a", "root_path": "/a"}]

    client = Client([{"projects": [{"name": "a", "root_path": "/a"}], "has_more": False}])
    assert asyncio.run(client.list_projects()) == [{"name": "a", "root_path": "/a"}]


def test_list_projects_pages_and_retries_without_arguments():
    client = Client([
        {"projects": [{"name": "a", "root_path": "/a"}, {"name": "b", "root_path": "/b"}],
         "has_more": True},
        {"projects": [{"name": "c", "root_path": "/c"}], "has_more": False},
    ])
    assert [p["name"] for p in asyncio.run(client.list_projects())] == ["a", "b", "c"]
    assert [a["offset"] for _, a in client.calls] == [0, 2]

    client = Client([None, [{"name": "old", "root_path": "/old"}]])
    assert [p["name"] for p in asyncio.run(client.list_projects())] == ["old"]
    assert client.calls[1] == ("list_projects", {})


def test_find_project_prefers_exact_root_then_nearest_parent(tmp_path):
    mono = tmp_path / "mono"
    sub = mono / "services" / "api"
    sub.mkdir(parents=True)
    (mono / "other").mkdir()
    projects = [{"name": "mono", "root_path": str(mono)},
                {"name": "api", "root_path": str(sub)},
                {"name": "broken", "root_path": ""}]

    def find(path):
        return asyncio.run(Client([list(projects)]).find_project_for_repo(str(path)))

    assert find(sub) == "api"
    assert find(sub / "handlers") == "api"
    assert find(mono / "other") == "mono"
    assert find(tmp_path / "elsewhere") is None


def test_graph_tools_always_carry_the_engine_project(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    out = asyncio.run(runner._execute_tool("trace_path", {"function_name": "f", "project": "evil"}, rp))
    assert json.loads(out)["project"] == "fake-project"
    out = asyncio.run(runner._execute_tool("search_code", {"pattern": "x", "project": "evil"}, rp))
    assert '"pattern": "x"' in out


def test_graph_tools_explain_a_missing_index_without_calling_the_server(tmp_path):
    runner, _ = make_runner(tmp_path)
    runner._mcp = NoGraph()
    rp = str(make_repo(tmp_path / "repo"))
    out = asyncio.run(runner._execute_tool("search_graph", {"name_pattern": "f"}, rp))
    assert out.startswith("search_graph is unavailable") and "read_file" in out
    out = asyncio.run(runner._execute_tool("list_dir", {"path": ""}, rp))
    assert "app/" in out


def test_skill_prompt_names_the_project_or_says_there_is_none(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM([])
    runner._llm = llm
    asyncio.run(runner.run_skill("map-entry-points", rp))
    first = llm.calls[0]["messages"][0]["content"]
    assert "Project name: `fake-project`" in first
    assert 'get_architecture(project="fake-project")' in first

    runner, _ = make_runner(tmp_path / "second")
    runner._mcp = NoGraph()
    llm = ScriptedLLM([])
    runner._llm = llm
    asyncio.run(runner.run_skill("map-entry-points", rp))
    first = llm.calls[0]["messages"][0]["content"]
    assert "no graph index" in first and "get_architecture(project=" not in first
    assert "Start with list_dir" in first
