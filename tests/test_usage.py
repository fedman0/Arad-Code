import asyncio
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import openai._base_client as _openai_base
import pytest
from openai import AsyncOpenAI

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Config, _config_from_data
from core.db import EvidenceStore
from core.llm import LLMClient
from core.runner import SkillRunner
from core.usage import BudgetExceeded, Usage, UsageMeter, cost_for, format_cost, usage_scope

httpx = getattr(_openai_base, "httpx2", None) or getattr(_openai_base, "httpx")

PRICING = {"test-model": {"input": 2.0, "output": 10.0, "cached_input": 0.5}}
USAGE = {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200,
         "prompt_tokens_details": {"cached_tokens": 400},
         "completion_tokens_details": {"reasoning_tokens": 50}}


def completion(message, usage=USAGE):
    body = {"id": "c1", "object": "chat.completion", "created": 0, "model": "test-model",
            "choices": [{"index": 0, "finish_reason": "stop", "message": message}]}
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(200, json=body)


def bad_request(message, param, code):
    return httpx.Response(400, json={"error": {"message": message, "type": "invalid_request_error",
                                               "param": param, "code": code}})


class FakeAPI:
    def __init__(self, reply=None, strict=True):
        self.requests = []
        self.reply = reply
        self.strict = strict

    def __call__(self, request):
        body = json.loads(request.content)
        self.requests.append(body)
        if self.strict and "max_tokens" in body:
            return bad_request("Unsupported parameter: 'max_tokens' is not supported with this "
                               "model. Use 'max_completion_tokens' instead.", "max_tokens",
                               "unsupported_parameter")
        if self.strict and "temperature" in body:
            return bad_request("Unsupported value: 'temperature' does not support 0.0 with this "
                               "model. Only the default (1) value is supported.", "temperature",
                               "unsupported_value")
        if self.reply is not None:
            return self.reply(body)
        return completion({"role": "assistant", "content": "ok"})


def make_client(api, api_base="https://llm.example.test/v1", meter=None, **cfg_kw):
    cfg = Config(api_key="k", api_base=api_base, model="test-model", pricing=PRICING, **cfg_kw)
    client = LLMClient(cfg, meter=meter or UsageMeter(PRICING))
    client._client = AsyncOpenAI(api_key="k", base_url=api_base, max_retries=0,
                                 http_client=httpx.AsyncClient(transport=httpx.MockTransport(api)))
    return client


def test_cost_uses_cached_price_for_cached_tokens():
    assert cost_for(PRICING, "test-model", 1000, 400, 200) == pytest.approx(
        (600 * 2.0 + 400 * 0.5 + 200 * 10.0) / 1_000_000)
    assert cost_for(PRICING, "vendor/test-model", 1000, 0, 0) == pytest.approx(0.002)
    assert cost_for(PRICING, "unknown", 1000, 0, 0) is None
    assert cost_for({"m": {"input": "x", "output": 1}}, "m", 1, 0, 0) is None


def test_meter_tracks_scopes_and_unknown_prices():
    meter = UsageMeter(PRICING)
    token = usage_scope.set("skill-a@1")
    try:
        meter.record("test-model", 1000, 200, 400, 50, 1.5)
        meter.record("other-model", 10, 5)
    finally:
        usage_scope.reset(token)
    meter.record("test-model", 1, 1)
    per = meter.for_scope("skill-a@1")
    assert set(per) == {"test-model", "other-model"}
    assert per["test-model"].reasoning_tokens == 50 and per["test-model"].cost_known
    assert not per["other-model"].cost_known
    assert meter.total.calls == 3 and not meter.total.cost_known
    assert format_cost(per["other-model"]) == "?"
    assert format_cost(meter.total).endswith("+?")


def test_budget_checks():
    meter = UsageMeter(PRICING, budget_usd=0.001)
    meter.check()
    meter.record("test-model", 1000, 0)
    with pytest.raises(BudgetExceeded, match="budget reached"):
        meter.check()
    tokens = UsageMeter(token_budget=100)
    tokens.record("x", 60, 50)
    with pytest.raises(BudgetExceeded, match="token budget"):
        tokens.check()


def test_client_adapts_to_rejected_parameters_and_records_usage():
    api = FakeAPI()
    client = make_client(api)
    assert asyncio.run(client.complete([{"role": "user", "content": "hi"}])) == "ok"
    final = api.requests[-1]
    assert "max_tokens" not in final and final["max_completion_tokens"] == 16384
    assert "temperature" not in final
    assert len(api.requests) == 3
    asyncio.run(client.complete([{"role": "user", "content": "again"}]))
    assert len(api.requests) == 4
    u = client.meter.total
    assert u.calls == 2 and u.prompt_tokens == 2000 and u.cached_tokens == 800
    assert u.reasoning_tokens == 100
    assert u.cost == pytest.approx(2 * (600 * 2.0 + 400 * 0.5 + 200 * 10.0) / 1_000_000)


def test_openai_endpoint_starts_with_max_completion_tokens():
    api = FakeAPI(strict=False)
    client = make_client(api, api_base="https://api.openai.com/v1")
    asyncio.run(client.complete([{"role": "user", "content": "hi"}]))
    assert len(api.requests) == 1 and "max_completion_tokens" in api.requests[0]


def test_other_errors_are_not_retried():
    calls = []

    def api(request):
        calls.append(1)
        return bad_request("This model's maximum context length is 8192 tokens.", "messages",
                           "context_length_exceeded")

    client = make_client(api)
    with pytest.raises(Exception, match="maximum context length"):
        asyncio.run(client.complete([{"role": "user", "content": "hi"}]))
    assert len(calls) == 1


def test_openrouter_cost_is_taken_from_the_provider():
    def reply(body):
        assert body["usage"] == {"include": True}
        return completion({"role": "assistant", "content": "ok"},
                          usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
                                 "cost": 0.0123})

    client = make_client(FakeAPI(reply=reply, strict=False), api_base="https://openrouter.ai/api/v1")
    asyncio.run(client.complete([{"role": "user", "content": "hi"}]))
    assert client.meter.total.cost == pytest.approx(0.0123)


def test_missing_usage_counts_as_an_unmeasured_call():
    client = make_client(FakeAPI(reply=lambda b: completion({"role": "assistant", "content": "x"},
                                                            usage=None), strict=False))
    asyncio.run(client.complete([{"role": "user", "content": "hi"}]))
    assert client.meter.total.calls == 1 and not client.meter.total.cost_known


def test_budget_stops_before_the_request_is_sent():
    api = FakeAPI(strict=False)
    meter = UsageMeter(PRICING, budget_usd=0.0001)
    client = make_client(api, meter=meter)
    asyncio.run(client.complete([{"role": "user", "content": "hi"}]))
    with pytest.raises(BudgetExceeded):
        asyncio.run(client.complete([{"role": "user", "content": "hi"}]))
    assert len(api.requests) == 1


def test_streaming_records_usage_from_the_final_chunk():
    def reply(body):
        assert body["stream_options"] == {"include_usage": True}
        chunks = [
            {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
             "choices": [{"index": 0, "delta": {"content": "hel"}, "finish_reason": None}]},
            {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
             "choices": [{"index": 0, "delta": {"content": "lo"}, "finish_reason": "stop"}]},
            {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
             "choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9}},
        ]
        text = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
        return httpx.Response(200, text=text, headers={"content-type": "text/event-stream"})

    client = make_client(FakeAPI(reply=reply, strict=False))

    async def collect():
        return "".join([t async for t in client.complete_stream([{"role": "user", "content": "x"}])])

    assert asyncio.run(collect()) == "hello"
    assert client.meter.total.prompt_tokens == 7 and client.meter.total.completion_tokens == 2


def test_config_parses_usage_settings():
    cfg = _config_from_data({"pricing": PRICING, "budget_usd": "2.5", "token_budget": 1000,
                             "transcripts": "false", "max_retries": 7})
    assert cfg.budget_usd == 2.5 and cfg.token_budget == 1000 and cfg.max_retries == 7
    assert cfg.transcripts is False and cfg.resolved_transcripts() is None
    with pytest.raises(ValueError, match="budget_usd"):
        _config_from_data({"budget_usd": "lots"})
    with pytest.raises(ValueError, match="pricing"):
        _config_from_data({"pricing": ["x"]})
    assert Config(db_path=":memory:").resolved_transcripts() is None
    assert Config(db_path="/tmp/x/e.db").resolved_transcripts() == Path("/tmp/x/transcripts")


class NoMCP:
    async def find_project_for_repo(self, repo):
        return None

    async def close(self):
        pass


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "views.py").write_text("def search(request):\n    return request.GET['q']\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "i"], cwd=repo,
                   check=True)
    return repo


def test_skill_run_persists_usage_transcript_and_model(tmp_path):
    finding = {"hypotheses": [{
        "actor": "anonymous user", "capability": "send a query", "entry_point": "app/views.py:search",
        "security_boundary": "HTTP", "violated_invariant": "query echoed back unescaped",
        "observable_impact": "reflected xss", "severity": 6, "confidence": 3, "exposure": "internet",
        "model": "spoofed-model"}], "coverage": [], "open_questions": []}

    def reply(body):
        return completion({"role": "assistant", "content": None, "tool_calls": [
            {"id": "t1", "type": "function",
             "function": {"name": "finish", "arguments": json.dumps({"findings": finding})}}]})

    repo = make_repo(tmp_path)
    db_path = tmp_path / "state" / "e.db"
    cfg = Config(api_key="k", api_base="https://llm.example.test/v1", model="test-model",
                 pricing=PRICING, db_path=str(db_path))
    db = EvidenceStore(db_path)
    runner = SkillRunner(cfg, db, NoMCP())
    runner._llm._client = AsyncOpenAI(
        api_key="k", base_url=cfg.api_base, max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(FakeAPI(reply=reply, strict=False))))

    result = asyncio.run(runner.run_skill("hunt-xss", str(repo)))
    assert result.model == "test-model"
    assert result.usage["calls"] == 1 and result.usage["prompt_tokens"] == 1000
    assert result.hypotheses and all(h.model == "test-model" for h in result.hypotheses)
    assert all(h.model == "test-model" for h in db.list_hypotheses(str(repo)))

    rows = db.list_usage(str(repo))
    assert [(r["scope"], r["model"], r["usage"].calls) for r in rows] == [("hunt-xss", "test-model", 1)]
    runs = db.list_runs(str(repo))
    assert runs[0]["run_id"] == runner.run_id and runs[0]["models"] == ["test-model"]

    files = list((tmp_path / "state" / "transcripts").rglob("*.jsonl"))
    assert len(files) == 1
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600
    events = [json.loads(line) for line in files[0].read_text().splitlines()]
    assert events[0]["type"] == "start" and events[0]["scope"] == "hunt-xss"
    assert events[0]["model"] == "test-model" and events[0]["system"]
    assert events[-1]["type"] == "end" and events[-1]["status"] == "done"
    assert events[-1]["usage"]["calls"] == 1
    roles = [e["message"]["role"] for e in events if e["type"] == "message"]
    assert roles == ["user", "assistant", "tool"]


def test_interrupted_skill_still_records_spend(tmp_path):
    def reply(body):
        return completion({"role": "assistant", "content": None, "tool_calls": [
            {"id": "t1", "type": "function",
             "function": {"name": "list_dir", "arguments": json.dumps({"path": "."})}}]})

    repo = make_repo(tmp_path)
    cfg = Config(api_key="k", api_base="https://llm.example.test/v1", model="test-model",
                 pricing=PRICING, db_path=str(tmp_path / "e.db"), budget_usd=0.004)
    db = EvidenceStore(tmp_path / "e.db")
    runner = SkillRunner(cfg, db, NoMCP())
    runner._llm._client = AsyncOpenAI(
        api_key="k", base_url=cfg.api_base, max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(FakeAPI(reply=reply, strict=False))))
    with pytest.raises(BudgetExceeded):
        asyncio.run(runner.run_skill("hunt-xss", str(repo)))
    rows = db.list_usage(str(repo))
    assert rows and rows[0]["usage"].calls == 2
    ends = [json.loads(l) for f in (tmp_path / "transcripts").rglob("*.jsonl")
            for l in f.read_text().splitlines() if '"end"' in l]
    assert ends and ends[0]["status"] == "interrupted"


def test_usage_round_trips_through_dict():
    u = Usage(calls=2, prompt_tokens=10, cost=0.5, unpriced_calls=1)
    d = u.to_dict()
    assert d["total_tokens"] == 10 and d["cost_known"] is False
    assert Usage.from_dict(d) == u
