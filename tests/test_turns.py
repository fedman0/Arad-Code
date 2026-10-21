import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.llm import Reply
from fakes_engine import EMPTY, ScriptedLLM, make_repo, make_runner, tc
from test_usage import FakeAPI, bad_request, completion, make_client


def raw(i, name, arguments):
    return SimpleNamespace(id=f"call_{i}", function=SimpleNamespace(name=name, arguments=arguments))


def hyp(**kw):
    d = dict(actor="unauthenticated attacker", capability="sqli", entry_point="app/views.py:search",
             security_boundary="HTTP", violated_invariant="user input concatenated into SQL",
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


FINDING = {"findings": {"hypotheses": [hyp()], "evidence": [ev(0)], "coverage": [], "open_questions": []}}


def tool_replies(llm):
    return {m["tool_call_id"]: m["content"] for call in llm.calls for m in call["messages"]
            if m.get("role") == "tool"}


def transcript_events(tmp):
    files = list(Path(tmp).rglob("*.jsonl"))
    assert len(files) == 1
    return [json.loads(line) for line in files[0].read_text().splitlines()]


def test_client_reports_the_finish_reason_and_honours_overrides():
    seen = []

    def reply(body):
        seen.append(body)
        return completion({"role": "assistant", "content": "ok"})

    client = make_client(FakeAPI(reply=reply, strict=False), reasoning_effort="high")
    r = asyncio.run(client.complete_turn([{"role": "user", "content": "hi"}], []))
    assert r.finish_reason == "stop" and r.content == "ok" and not r.truncated
    assert seen[-1]["max_tokens"] == 16384 and seen[-1]["reasoning_effort"] == "high"
    asyncio.run(client.complete_turn([{"role": "user", "content": "hi"}], [],
                                     max_tokens=65536, reasoning_effort="low"))
    assert seen[-1]["max_tokens"] == 65536 and seen[-1]["reasoning_effort"] == "low"

    plain = make_client(FakeAPI(reply=reply, strict=False))
    asyncio.run(plain.complete_turn([{"role": "user", "content": "hi"}], [], reasoning_effort="low"))
    assert "reasoning_effort" not in seen[-1]


def test_client_falls_back_when_the_model_refuses_the_bigger_limit():
    seen = []

    def reply(body):
        seen.append(body)
        if body["max_tokens"] > 32768:
            return bad_request(f"max_tokens is too large: {body['max_tokens']}. This model "
                               "supports at most 32768 completion tokens.", "max_tokens",
                               "invalid_value")
        return completion({"role": "assistant", "content": "ok"})

    client = make_client(FakeAPI(reply=reply, strict=False))
    r = asyncio.run(client.complete_turn([{"role": "user", "content": "hi"}], [], max_tokens=65536))
    assert r.content == "ok" and [b["max_tokens"] for b in seen] == [65536, 16384]
    asyncio.run(client.complete_turn([{"role": "user", "content": "hi"}], [], max_tokens=65536))
    assert [b["max_tokens"] for b in seen] == [65536, 16384, 16384]


def test_cut_off_finish_is_retried_with_more_room(tmp_path):
    runner, db = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM([
        Reply(None, [raw(1, "finish", '{"findings": {"hypotheses": [{"actor": "att')], "length"),
        [tc(2, "finish", FINDING)],
    ])
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert len(res.hypotheses) == 1 and res.evidence
    assert tool_replies(llm)["call_1"].startswith("finish() was cut off")
    assert llm.calls[1]["max_tokens"] == 65536 and llm.calls[1]["reasoning_effort"] == "low"
    assert "max_tokens" not in llm.calls[0]
    events = transcript_events(tmp_path)
    turns = [e for e in events if e["type"] == "turn"]
    assert [t["finish_reason"] for t in turns] == ["length", "tool_calls"]
    assert turns[1]["brief"] is True and events[-1]["type"] == "end"


def test_cut_off_tool_call_is_explained_and_the_next_turn_gets_room(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM([
        Reply(None, [tc(1, "list_dir", {"path": ""}), raw(2, "read_file", '{"file_path": "app/vi')],
              "length"),
        [tc(3, "finish", FINDING)],
    ])
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    replies = tool_replies(llm)
    assert "app/" in replies["call_1"]
    assert "cut off at the token limit" in replies["call_2"]
    assert llm.calls[1]["reasoning_effort"] == "low" and llm.calls[1]["max_tokens"] == 65536
    assert len(res.hypotheses) == 1


def test_forced_finish_turns_get_room_and_give_up_after_two_empty_replies(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM([Reply(None, None, "length"), Reply(None, None, "length"),
                       Reply(None, None, "length"), Reply(None, None, "length")])
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp, max_iterations=4))
    assert len(llm.calls) == 2
    assert llm.calls[0]["tool_choice"] == {"type": "function", "function": {"name": "finish"}}
    assert llm.calls[0]["tools"] == ["finish"] and llm.calls[0]["max_tokens"] == 65536
    assert llm.calls[1]["reasoning_effort"] == "low"
    assert any("Call finish() RIGHT NOW" in str(m.get("content")) for m in llm.calls[0]["messages"])
    assert any("cut off" in str(m.get("content")) for m in llm.calls[1]["messages"])
    assert not res.hypotheses
    assert any("2 forced attempts" in q and "length" in q for q in res.open_questions)


def test_a_finish_that_is_not_an_object_is_bounced_then_recorded_empty(tmp_path):
    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    llm = ScriptedLLM([[raw(1, "finish", '["not", "an", "object"]')],
                       [raw(2, "finish", '{"findings": "{broken"}')],
                       [raw(3, "finish", '[]')]])
    runner._llm = llm
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    replies = tool_replies(llm)
    assert replies["call_1"].startswith("finish() arguments were not a JSON object")
    assert replies["call_2"].startswith("finish() arguments were not a JSON object")
    assert len(llm.calls) == 3 and not res.hypotheses
    assert any("not a JSON object" in q for q in res.open_questions)


def test_legacy_fakes_without_finish_reason_still_drive_a_skill(tmp_path):
    class Legacy:
        async def complete_with_tools(self, messages, tools, system=None, tool_choice=None):
            return None, [tc(1, "finish", EMPTY)]

    runner, _ = make_runner(tmp_path)
    rp = str(make_repo(tmp_path / "repo"))
    runner._llm = Legacy()
    res = asyncio.run(runner.run_skill("hunt-injection-sqli-cmdi", rp))
    assert res.hypotheses == [] and not res.open_questions
