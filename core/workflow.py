from __future__ import annotations
import asyncio
import importlib.util
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

_VOTE_COUNT = 3
_VOTE_THRESHOLD = 2
_VOTE_RETRIES = 2

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_real": {"type": "boolean"},
        "reasoning": {"type": "string"},
        "confidence": {"type": "integer"},
        "refutation": {"type": "string"},
    },
    "required": ["is_real", "reasoning", "confidence"],
    "additionalProperties": False,
}


@dataclass
class PhaseInfo:
    name: str
    title: str = ""
    detail: str = ""
    started_at: float = field(default_factory=time.monotonic)
    ended_at: Optional[float] = None
    agents_started: int = 0
    agents_done: int = 0

    def elapsed(self) -> float:
        end = self.ended_at or time.monotonic()
        return end - self.started_at

    def finish(self):
        self.ended_at = time.monotonic()


@dataclass
class AgentRecord:
    label: str
    phase: Optional[str]
    started_at: float = field(default_factory=time.monotonic)
    ended_at: Optional[float] = None
    error: Optional[str] = None

    def finish(self, error: Optional[str] = None):
        self.ended_at = time.monotonic()
        self.error = error


class WorkflowContext:
    def __init__(self):
        self._phases: list[PhaseInfo] = []
        self._current_phase: Optional[PhaseInfo] = None
        self._agents: list[AgentRecord] = []
        self._on_event: Optional[Callable[[str, Any], None]] = None
        self._runner = None
        self._repo_path: str = ""

    def bind(self, runner, repo_path: str):
        self._runner = runner
        self._repo_path = repo_path

    def on_event(self, cb: Callable[[str, Any], None]):
        self._on_event = cb

    def _emit(self, event: str, data: Any = None):
        if self._on_event:
            self._on_event(event, data)

    def _get_phase(self, name: Optional[str]) -> Optional[PhaseInfo]:
        if name:
            for p in self._phases:
                if p.name == name:
                    return p
        return self._current_phase

    async def phase(self, name: str, *, title: str = "", detail: str = "") -> PhaseInfo:
        if self._current_phase and not self._current_phase.ended_at:
            self._current_phase.finish()
            self._emit("phase_end", self._current_phase)
        p = PhaseInfo(name=name, title=title or name, detail=detail)
        self._current_phase = p
        self._phases.append(p)
        self._emit("phase_start", p)
        return p

    async def agent(
        self,
        prompt: str,
        *,
        label: str = "",
        phase: Optional[str] = None,
        schema: Optional[dict] = None,
        runner=None,
        repo_path: str = "",
        extra_context: str = "",
    ) -> dict:
        _runner = runner or self._runner
        _repo = repo_path or self._repo_path

        if _runner is None:
            raise RuntimeError("agent() requires a runner — call ctx.bind(runner, repo_path) first")

        rec = AgentRecord(label=label or prompt[:40], phase=phase)
        self._agents.append(rec)

        p = self._get_phase(phase)
        if p:
            p.agents_started += 1

        self._emit("agent_start", rec)

        try:
            result = await _runner.run_prompt(
                prompt=prompt,
                repo_path=_repo,
                extra_context=extra_context,
                schema=schema,
            )
            rec.finish()
            if p:
                p.agents_done += 1
            self._emit("agent_end", {"record": rec, "result": result})
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            rec.finish(error=str(exc))
            if p:
                p.agents_done += 1
            self._emit("agent_error", {"record": rec, "error": str(exc)})
            return {"error": str(exc)}

    async def parallel(self, tasks: list) -> list:
        coros = []
        for t in tasks:
            if asyncio.iscoroutine(t):
                coros.append(t)
            elif callable(t):
                r = t()
                coros.append(r if asyncio.iscoroutine(r) else asyncio.coroutine(lambda v=r: v)())
            else:
                coros.append(asyncio.sleep(0, result=t))
        return list(await asyncio.gather(*coros, return_exceptions=False))

    async def pipeline(self, items: list, *fns) -> list:
        results = list(items)
        for fn in fns:
            next_results = []
            for item in results:
                r = fn(item)
                if asyncio.iscoroutine(r):
                    r = await r
                if isinstance(r, list):
                    next_results.extend(r)
                elif r is not None:
                    next_results.append(r)
            results = next_results
        return results

    async def verify_finding(
        self,
        finding: dict,
        *,
        runner=None,
        repo_path: str = "",
        _round: int = 0,
    ) -> dict:
        _runner = runner or self._runner
        _repo = repo_path or self._repo_path

        if _round >= _VOTE_RETRIES:
            return {**finding, "confirmed": False, "verification_note": f"inconclusive after {_VOTE_RETRIES+1} rounds"}

        perspective_notes = [
            "Try to REFUTE this finding. Look for missing checks, wrong assumptions, unreachable paths.",
            "Verify from the perspective of data flow. Trace the actual input path to the sink.",
            "Verify from the perspective of the attacker. What exact steps are needed? Are they realistic?",
        ]

        vote_prompts = [
            (
                f"Adversarially verify this security finding ({i+1}/{_VOTE_COUNT}). "
                f"{perspective_notes[i % len(perspective_notes)]}\n\n"
                f"Finding:\n{finding}\n\n"
                f"Answer with is_real (true/false), reasoning, confidence (1-10), "
                f"and refutation (what would make this NOT a vulnerability)."
            )
            for i in range(_VOTE_COUNT)
        ]

        votes = await self.parallel([
            lambda p=p, i=i: self.agent(
                p, label=f"verify:{finding.get('id', '?')}:v{i+1}",
                phase="Verify", schema=VERDICT_SCHEMA,
                runner=_runner, repo_path=_repo,
            )
            for i, p in enumerate(vote_prompts)
        ])

        true_votes = [v for v in votes if v.get("is_real")]
        false_votes = [v for v in votes if not v.get("is_real")]

        self._emit("votes_counted", {
            "finding": finding.get("id", "?"),
            "true": len(true_votes),
            "false": len(false_votes),
            "round": _round,
        })

        if len(true_votes) >= _VOTE_THRESHOLD:
            return {**finding, "confirmed": True, "votes": votes}
        if len(false_votes) >= _VOTE_THRESHOLD:
            return {**finding, "confirmed": False, "votes": votes}

        self._emit("inconclusive_vote", {"finding": finding.get("id", "?"), "round": _round})
        return await self.verify_finding(
            finding, runner=_runner, repo_path=_repo, _round=_round + 1
        )

    def phases(self) -> list[PhaseInfo]:
        return list(self._phases)

    def agents(self) -> list[AgentRecord]:
        return list(self._agents)


async def run_workflow_script(
    script_path: str,
    *,
    runner,
    repo_path: str,
    args: Any = None,
    on_event: Optional[Callable[[str, Any], None]] = None,
) -> Any:
    ctx = WorkflowContext()
    ctx.bind(runner, repo_path)
    if on_event:
        ctx.on_event(on_event)

    spec = importlib.util.spec_from_file_location("_workflow", script_path)
    mod = importlib.util.module_from_spec(spec)

    mod.ctx = ctx
    mod.agent = ctx.agent
    mod.parallel = ctx.parallel
    mod.pipeline = ctx.pipeline
    mod.phase = ctx.phase
    mod.verify_finding = ctx.verify_finding
    mod.args = args

    spec.loader.exec_module(mod)

    if hasattr(mod, "run") and callable(mod.run):
        return await mod.run()
    return {"phases": len(ctx.phases()), "agents": len(ctx.agents())}
