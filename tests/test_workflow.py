import asyncio
from pathlib import Path

import pytest

from core.workflow import WorkflowContext, run_workflow_script

WF = Path(__file__).resolve().parent / "fixtures" / "wf"


class FakeRunner:
    def __init__(self, votes):
        self.votes = list(votes)
        self.calls = []

    async def run_prompt(self, prompt, repo_path, extra_context, schema):
        self.calls.append(prompt[:30])
        await asyncio.sleep(0)
        if schema and "is_real" in str(schema):
            return {"is_real": self.votes.pop(0), "reasoning": "r", "confidence": 5}
        return {"ok": 1}


class R2:
    async def run_prompt(self, **kw):
        return {"reasoning": "?"}


def test_verify_workflow_script_events():
    async def main():
        events = []

        def on_event(e, d):
            events.append((e, d))
            if e == "agent_end" and d["record"].label == "scanner":
                raise RuntimeError("ui callback boom")

        r = FakeRunner([True, True, False])
        res = await run_workflow_script(str(WF / "verify_wf.py"), runner=r, repo_path="/x", on_event=on_event)
        return events, res

    events, res = asyncio.run(main())
    names = [e for e, _ in events]
    labels = [d.label for e, d in events if e == "agent_start"]
    assert len(set(labels)) == len(labels)
    assert res["findings"][0]["confirmed"] is True, res
    assert names[-1] == "phase_end", "last phase closed"
    ends = [d["record"].label for e, d in events if e == "agent_end"]
    assert "scanner" in ends and not any(e == "agent_error" and d["record"].label == "scanner" for e, d in events)
    perr = [d for e, d in events if e == "pipeline_error"]
    assert res["pipeline"] == [-1.0, -1.0, 1.0, 1.0, 0.5, 0.5]
    assert [(p["item"], p["error"]) for p in perr] == [(2, "division by zero")]


def test_inconclusive_verification_and_unknown_phase():
    async def main():
        ctx = WorkflowContext()
        ev2 = []
        ctx.on_event(lambda e, d: ev2.append((e, d)))
        ctx.bind(R2(), "/x")
        out = await ctx.verify_finding({"id": "F2"})
        inc = [d["round"] for e, d in ev2 if e == "inconclusive_vote"]
        vc = [d["round"] for e, d in ev2 if e == "votes_counted"]
        assert inc == [0, 1] and vc == [0, 1, 2] and out["confirmed"] is None
        vlabels = [d.label for e, d in ev2 if e == "agent_start"]
        assert len(set(vlabels)) == 9, vlabels
        res = await ctx.agent("x", phase="Nope")
        assert "error" in res and ev2[-1][0] == "agent_error"

    asyncio.run(main())


def test_sync_workflow_script():
    res = asyncio.run(run_workflow_script(str(WF / "sync_wf.py"), runner=R2(), repo_path=""))
    assert res == {"ok": True}


def test_non_python_workflow_script_rejected():
    with pytest.raises(ValueError, match="expected a Python file ending in .py"):
        asyncio.run(run_workflow_script(str(WF / "sync_wf.txt"), runner=R2(), repo_path=""))


def test_pipeline_concurrency_cap():
    async def main():
        ctx3 = WorkflowContext()
        active = [0]
        peak = [0]

        async def stage(x):
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            await asyncio.sleep(0.01)
            active[0] -= 1
            return x

        await ctx3.pipeline(list(range(30)), stage, concurrency=4)
        return peak[0]

    assert asyncio.run(main()) == 4
