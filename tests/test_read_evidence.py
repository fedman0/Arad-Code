import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.evidence_gate import _cap_method_per_evidence, _read_window
from core.prompts import HUNT_OUTPUT_CONTRACT, HUNT_SYSTEM_PROMPT, OUTPUT_CONTRACT
from core.tool_specs import TOOLS
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc
from test_finish_contract import finish
from test_turns import ev, hyp


def scan(tmp_path, first_turn, item):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    runner._llm = ScriptedLLM([first_turn, [finish([hyp()], [item])]])
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    return res.hypotheses[0], res.evidence[0]


def test_read_window_matches_what_read_file_shows(tmp_path):
    runner, _ = make_runner(tmp_path)
    repo = tmp_path / "big"
    repo.mkdir()
    (repo / "f.txt").write_text("".join(f"line {i}\n" for i in range(1, 2001)))
    for start, end in [(None, None), (5, None), (None, 40), (10, 30), (100, 5000), (1, 1)]:
        out = runner._read_file(str(repo), "f.txt", start, end)
        shown = [int(n) for n in re.findall(r"^\s*(\d+): ", out, re.M)]
        s, e = _read_window(start, end)
        assert (shown[0], shown[-1]) == (s + 1, e), (start, end)


def test_read_verified_evidence_may_be_structural_without_a_graph_tool():
    none = frozenset()
    assert _cap_method_per_evidence("structural", "a.py", "", [], none, read_verified=True) == "structural"
    assert _cap_method_per_evidence("structural", "a.py", "", [], none) == "textual"
    assert _cap_method_per_evidence("semantic", "a.py", "", [], none, read_verified=True) == "structural"
    assert _cap_method_per_evidence("textual", "a.py", "", [], none, read_verified=True) == "textual"


def test_reading_the_cited_lines_earns_structural(tmp_path):
    h, e = scan(tmp_path, [tc(1, "read_file", {"file_path": "app/views.py", "start_line": 1, "end_line": 10})], ev(0))
    assert e.analysis_quality.method == "structural"
    assert any("read_file showed the cited lines" in l for l in e.analysis_quality.limitations)
    assert h.status == "evidence_supported" and h.confidence == 7


def test_a_default_read_and_an_absolute_path_both_count(tmp_path):
    h, e = scan(tmp_path, [tc(1, "read_file", {"file_path": "app/views.py"})], ev(0))
    assert e.analysis_quality.method == "structural" and h.status == "evidence_supported"
    repo = tmp_path / "second" / "repo"
    h, e = scan(tmp_path / "second", [tc(1, "read_file", {"file_path": str(repo / "app" / "views.py")})], ev(0))
    assert e.analysis_quality.method == "structural"


def test_a_read_that_misses_the_cited_lines_stays_textual(tmp_path):
    h, e = scan(tmp_path, [tc(1, "read_file", {"file_path": "app/views.py", "start_line": 1, "end_line": 2})], ev(0))
    assert e.analysis_quality.method == "textual" and h.status == "initial"


def test_a_grep_hit_that_was_never_opened_stays_textual(tmp_path):
    h, e = scan(tmp_path, [tc(1, "grep", {"pattern": "cursor.execute"})], ev(0))
    assert e.analysis_quality.method == "textual" and h.status == "initial" and h.confidence == 4


def test_reading_without_a_usable_anchor_stays_textual(tmp_path):
    item = ev(0)
    del item["anchor_text"]
    h, e = scan(tmp_path, [tc(1, "read_file", {"file_path": "app/views.py"})], item)
    assert e.analysis_quality.method == "textual" and h.status == "initial"


def test_reading_a_different_file_does_not_count(tmp_path):
    h, e = scan(tmp_path, [tc(1, "read_file", {"file_path": ".github/ci.yml"})], ev(0))
    assert e.analysis_quality.method == "textual"


def test_prompts_describe_the_rule_and_point_at_trace_path():
    assert "a grep hit you did not open" in OUTPUT_CONTRACT
    assert "read_file over a range" in OUTPUT_CONTRACT and "read_file over a range" in HUNT_OUTPUT_CONTRACT
    assert 'direction="inbound"' in OUTPUT_CONTRACT and 'direction="inbound"' in HUNT_SYSTEM_PROMPT
    spec = next(t for t in TOOLS if t["function"]["name"] == "trace_path")
    assert "semantic" in spec["function"]["description"]
