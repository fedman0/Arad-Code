import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.llm import Reply
from core.skills import SkillCatalog, SkillFormatError
from fakes_engine import EMPTY, make_repo, make_runner, tc


def catalog(tmp_path, header):
    d = tmp_path / "skills" / "p4"
    d.mkdir(parents=True, exist_ok=True)
    (d / "s.md").write_text(f"---\n{header}\n---\n\n# s\n")
    return SkillCatalog(tmp_path / "skills")


def test_max_turns_is_read_from_the_header(tmp_path):
    assert catalog(tmp_path, "max_turns: 45").find("s").max_turns == 45
    assert catalog(tmp_path / "b", "order: 5").find("s").max_turns is None


@pytest.mark.parametrize("value", ["3", "500", "lots", "true"])
def test_bad_max_turns_is_an_error_naming_the_file(tmp_path, value):
    with pytest.raises(SkillFormatError, match="max_turns"):
        catalog(tmp_path, f"max_turns: {value}").find("s")


class Explorer:
    def __init__(self):
        self.calls = []

    async def complete_turn(self, messages, tools, system=None, tool_choice=None, **extra):
        closing = "Call finish() RIGHT NOW" in str(messages[-1].get("content") or "")
        self.calls.append(closing)
        if closing:
            return Reply(None, [tc(len(self.calls), "finish", EMPTY)], "tool_calls")
        return Reply(None, [tc(len(self.calls), "list_dir", {"path": ""})], "tool_calls")


def turns_used(tmp_path, skill, **kw):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = Explorer()
    runner._llm = llm
    asyncio.run(runner.run_skill(skill, rp, **kw))
    return sum(1 for c in llm.calls if not c), len(llm.calls)


def test_deep_skills_get_forty_turns_and_hunts_keep_thirty(tmp_path):
    assert turns_used(tmp_path / "a", "trace-effect-to-callers") == (34, 35)
    assert turns_used(tmp_path / "b", "hunt-injection-sqli-cmdi") == (24, 25)
    assert turns_used(tmp_path / "c", "trace-effect-to-callers", max_iterations=12) == (6, 7)


def test_every_shipped_deep_skill_declares_its_budget():
    from core.config import Config
    cat = SkillCatalog(Config().resolved_skills())
    for phase in ("p1", "p2", "p3", "p5"):
        assert all(s.max_turns == (45 if s.fanout else 40) for s in cat.phase_skills(phase)), phase
    p4 = cat.phase_skills("p4")
    assert all(s.max_turns == 40 for s in p4 if s.name.startswith("understand-"))
    assert all(s.max_turns is None for s in p4 if s.name.startswith("hunt-"))


def test_trace_input_to_effect_fans_out_over_entry_points():
    from core.config import Config
    cat = SkillCatalog(Config().resolved_skills())
    info = cat.find("trace-input-to-effect")
    assert info.fanout == "entry_points" and info.batch == 6 and info.max_turns == 45
    assert "Assigned entry points" in cat.body("trace-input-to-effect")
    assert [s.name for s in cat.phase_skills("p3") if s.fanout] == ["trace-input-to-effect"]
