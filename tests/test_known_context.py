import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Config, _config_from_data
from core.context import ContextWindow
from core.models import FINDINGS_SCHEMA
from core.runner import _force_finish
from fakes_engine import ScriptedLLM, make_repo, make_runner, tc

BASE = "## Overview\nA shop.\n\n## Trust Boundaries\nInternet to API.\n\n## Severity Calibration\nAuth first.\n" + "b" * 400
MAP = "## Middleware Map\n" + "".join(f"row {i:03d} " + "m" * 60 + "\n" for i in range(60)) + "LAST LINE\n"


def setup(tmp_path):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    db.save_threat_model(rp, BASE, "inventory-repository")
    return runner, db, rp


def test_known_context_shows_amendments_by_their_summary(tmp_path):
    runner, db, rp = setup(tmp_path)
    db.amend_threat_model(rp, MAP, "map-middleware-and-filters",
                          summary="Only the /api prefix guard protects the generic CRUD routes.")
    db.amend_threat_model(rp, "## Configuration\nsafetyMode is auto.\n", "resolve-configuration")
    text = runner._build_initial_context(rp)
    assert "Only the /api prefix guard protects the generic CRUD routes." in text
    assert "LAST LINE" not in text and 'get_threat_model(section="1") returns all' in text
    assert "safetyMode is auto." in text and 'section="2"' not in text
    assert "## Severity Calibration" in text
    assert "LAST LINE" in db.get_threat_model(rp)


def test_a_long_amendment_without_summary_shows_its_first_lines(tmp_path):
    runner, db, rp = setup(tmp_path)
    db.amend_threat_model(rp, MAP, "map-middleware-and-filters")
    brief = db.get_threat_model(rp, brief=True)
    assert "row 000" in brief and "LAST LINE" not in brief
    assert f"returns all {len(MAP)} characters" in brief
    assert len(brief) < len(BASE) + 1700


def test_get_threat_model_finds_a_section_by_number_title_or_skill(tmp_path):
    runner, db, rp = setup(tmp_path)
    db.amend_threat_model(rp, MAP, "map-middleware-and-filters", summary="short")
    db.amend_threat_model(rp, "## Deployment Context\nport 3000 is public\n", "map-deployment-context")
    run = lambda args: asyncio.run(runner._execute_tool("get_threat_model", args, rp))
    assert "LAST LINE" in run({"section": "1"}) and "Amendment 1 (by map-middleware-and-filters)" in run({"section": "1"})
    assert "port 3000 is public" in run({"section": "deployment context"})
    assert "LAST LINE" in run({"section": "map-middleware-and-filters"})
    listing = run({})
    assert listing.startswith("## Overview") and "1. Middleware Map (by map-middleware-and-filters" in listing
    assert "2. Deployment Context" in listing and "LAST LINE" not in listing
    assert "## Overview" in run({"section": "severity calibration"})
    assert run({"section": "kubernetes"}).startswith("No threat model section matches 'kubernetes'")


def test_amend_threat_model_keeps_the_summary_the_model_gives(tmp_path):
    runner, db, rp = setup(tmp_path)
    out = asyncio.run(runner._execute_tool("amend_threat_model",
                                           {"addendum": MAP, "summary": "  guard only on /api  "}, rp))
    assert out == "Amendment recorded."
    assert "guard only on /api\n[shortened here" in db.get_threat_model(rp, brief=True)


def test_a_map_is_kept_when_no_base_exists_yet(tmp_path):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    assert db.amend_threat_model(rp, MAP, "map-middleware-and-filters", summary="guard only on /api")
    brief = db.get_threat_model(rp, brief=True)
    assert brief.startswith("### Amendment 1 (by map-middleware-and-filters)")
    assert "guard only on /api" in runner._build_initial_context(rp)
    listing = asyncio.run(runner._execute_tool("get_threat_model", {}, rp))
    assert listing.startswith("No base threat model has been saved yet.")
    assert "1. Middleware Map (by map-middleware-and-filters" in listing
    db.save_threat_model(rp, BASE, "inventory-repository")
    full = db.get_threat_model(rp)
    assert full.startswith("## Overview") and "LAST LINE" in full
    db.save_threat_model(rp, BASE + "x", "inventory-repository")
    assert "LAST LINE" not in db.get_threat_model(rp)


def test_the_tools_say_a_map_needs_no_base(tmp_path):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    run = lambda name, args: asyncio.run(runner._execute_tool(name, args, rp))
    assert run("get_threat_model", {}).startswith("No threat model exists yet. amend_threat_model")
    assert run("amend_threat_model", {"addendum": MAP, "summary": "s"}) == "Amendment recorded."
    assert "LAST LINE" in run("get_threat_model", {"section": "1"})


def finish_with(update, i=200):
    return tc(i, "finish", {"findings": {"hypotheses": [], "coverage": [], "open_questions": [],
                                         "threat_model_update": update}})


def scripted(tmp_path, turns, base=True):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    if base:
        db.save_threat_model(rp, BASE, "inventory-repository")
    runner._llm = ScriptedLLM(turns)
    asyncio.run(runner.run_skill("map-middleware-and-filters", rp))
    return db, rp


def test_finish_carries_the_map_a_skill_had_no_turns_left_for(tmp_path):
    assert "threat_model_update" in _force_finish(True)
    assert "threat_model_update" not in _force_finish(False)
    assert "threat_model_update" in FINDINGS_SCHEMA["properties"]
    db, rp = scripted(tmp_path, [[finish_with({"content": MAP, "summary": "guard only on /api"})]])
    full = db.get_threat_model(rp)
    assert full.startswith("## Overview") and "LAST LINE" in full
    assert "Amendment 1 (by map-middleware-and-filters)" in full
    assert "guard only on /api" in db.get_threat_model(rp, brief=True)


def test_finish_writes_the_base_only_when_there_is_none(tmp_path):
    db, rp = scripted(tmp_path / "a", [[finish_with({"content": BASE, "base": True})]], base=False)
    assert db.threat_model_parts(rp) == (BASE, [])
    db, rp = scripted(tmp_path / "b", [[finish_with({"content": MAP, "base": True, "summary": "s"})]])
    base, amendments = db.threat_model_parts(rp)
    assert base == BASE and [a["content"] for a in amendments] == [MAP.strip()]


def test_a_map_already_saved_is_not_recorded_twice(tmp_path):
    db, rp = scripted(tmp_path, [[tc(1, "amend_threat_model", {"addendum": MAP, "summary": "s"})],
                                 [finish_with({"content": MAP, "summary": "s"})]])
    assert len(db.threat_model_parts(rp)[1]) == 1


def test_history_budget_trims_without_counting_the_first_message():
    msgs = [{"role": "user", "content": "k" * 50000}]
    for i in range(8):
        msgs.append({"role": "assistant", "tool_calls": [{"id": str(i), "function": {"arguments": "{}"}}]})
        msgs.append({"role": "tool", "tool_call_id": str(i), "content": "y" * 5000})
    assert ContextWindow(200000, keep_recent=3, history_chars=60000).view(msgs) is msgs
    w = ContextWindow(200000, keep_recent=3, history_chars=30000)
    out = w.view(msgs)
    assert out[0]["content"] == "k" * 50000
    assert sum(1 for m in out if "trimmed" in str(m.get("content"))) == 5
    assert ContextWindow(0, history_chars=0).view(msgs) is msgs
    assert sum(1 for m in ContextWindow(0, keep_recent=3, history_chars=30000).view(msgs)
               if "trimmed" in str(m.get("content"))) == 5


def test_history_budget_has_a_default_and_can_be_configured():
    assert Config().history_char_limit == 110000
    assert _config_from_data({}).history_char_limit == 110000
    assert _config_from_data({"history_char_limit": 0}).history_char_limit == 0
    runner, _ = make_runner(Path(__import__("tempfile").mkdtemp()))
    assert runner._window().history == runner._cfg.history_char_limit == 110000


def test_the_known_context_lists_late_amendments_in_one_line(tmp_path):
    runner, db, rp = setup(tmp_path)
    for i in range(30):
        db.amend_threat_model(rp, f"## Batch {i:02d} map\n" + "x" * 300, "trace-input-to-effect",
                              summary=f"summary of batch {i:02d}")
    brief = db.get_threat_model(rp, brief=True)
    assert "summary of batch 24" in brief and "summary of batch 25" not in brief
    assert brief.count("### Amendment ") == 25
    assert "### Amendments 26 to 30, one line each" in brief
    assert "  30. Batch 29 map (by trace-input-to-effect)" in brief
    assert "x" * 300 not in brief
    full = db.get_threat_model(rp)
    assert full.count("### Amendment ") == 30 and "x" * 300 in full
    assert "summary of batch 29" not in runner._build_initial_context(rp)


def test_only_a_map_skill_is_told_to_put_its_map_in_finish(tmp_path):
    notes = {}
    for skill in ("map-middleware-and-filters", "hunt-injection-sqli-cmdi"):
        (tmp_path / skill).mkdir()
        runner, _ = make_runner(tmp_path / skill)
        rp = str(make_repo(tmp_path / skill / "repo"))
        llm = ScriptedLLM([[tc(1, "search_graph", {"name_pattern": "search"})],
                           [finish_with({"content": MAP, "summary": "s"})]])
        runner._llm = llm
        asyncio.run(runner.run_skill(skill, rp, max_iterations=7))
        notes[skill] = llm.calls[1]["messages"][-1]["content"]
    assert notes["map-middleware-and-filters"].endswith(_force_finish(True))
    assert notes["hunt-injection-sqli-cmdi"].endswith(_force_finish(False))
    assert "threat_model_update" not in notes["hunt-injection-sqli-cmdi"]
