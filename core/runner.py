from __future__ import annotations
import asyncio
import itertools
import json
import re
import subprocess
from typing import Any, Optional
from .config import Config
from .llm import LLMClient, Reply
from .db import EvidenceStore
from .memory_mcp import CodebaseMemoryClient
from .models import (
    Hypothesis, Evidence, CoverageItem, EntryPoint, Guard, SkillResult, FunctionSummary,
    OpenQuestion, ConflictRecord, ReturnValueContract, NegativeEvidence,
)
from .profile import ProjectProfile, load_profile
from .cache import (
    completed_skills, fanout_progress, forget_skills, mark_skill_done, record_fanout,
)
from .prompts import (
    SYSTEM_PROMPT, HUNT_SYSTEM_PROMPT, _NE_INSTRUCTION, HUNT_OUTPUT_CONTRACT, OUTPUT_CONTRACT,
)
from .tool_specs import TOOLS, _PROMPT_TOOL_NAMES
from .evidence_gate import (
    _synthesize_evidence_from_tools, _gate_hypothesis_status, _build_tool_call_index,
    _cap_method_per_evidence, _apply_quality_caps, _inject_minimum_obligations, _apply_profile,
    _read_spans, _read_verified,
)
from .intake import (
    _as_list, _without_id, _prepare_model_hypothesis, _validate_model_hypothesis,
    _apply_model_demotion, _finish_problems, _prepare_model_evidence, _existing_id,
    _merge_model_claims,
)
from .tool_exec import ToolExecutor
from .reconcile import EvidenceReconciler
from .skills import MAINTENANCE_PHASE, SkillCatalog
from .transcript import new_run_id, open_transcript
from .usage import Usage, UsageMeter, usage_scope
from .context import ContextWindow
from .stack import StackProfile, describe, detect_stack
from .fanout import (
    GRAPH_ROUTES_QUERY, Target, assignment, coverage_key, inventory, make_batches,
    parse_graph_routes, target_from_name, uncovered,
)
from .db import UNDECIDED_BLOCKER
from .usage import BudgetExceeded


_DEFAULT_TURNS = 30
_NO_INVENTORY = (
    "# Assigned entry points\n"
    "No entry points have been recorded for this repository yet. Find them yourself (route "
    "registrations, message consumers, scheduled jobs, CLI commands) and review as many as you "
    "can. Record a coverage item with kind \"entry_point\" for every one you reach a decision on."
)
_KNOWN_FINDINGS = 60
_GRAPH_PAGES = 200
_FINISH_CHOICE = {"type": "function", "function": {"name": "finish"}}
_FORCED_TURNS = 6
_EMPTY_FORCED_LIMIT = 2
_FINISH_RETRIES = 2
_ROOM_FACTOR = 4
_ROOM_CAP = 65536

_FORCE_FINISH = (
    "You have used enough iterations. Call finish() RIGHT NOW with all findings "
    "you have gathered so far. Include every hypothesis with its evidence. "
    "Do not call any other tool, only finish()."
)
_FORCE_FINISH_MAP = (
    "Your skill saves a map to the threat model: if you have not saved it yet, "
    "put it in threat_model_update."
)
_FORCED_REFUSED = (
    "Not run: only finish() is available now. Call finish() with the findings you have."
)
_CONTINUE = (
    "Continue the skill: call a tool to keep investigating, "
    "or call finish() with your structured findings."
)
_CONTINUE_FORCED = "Only finish() is available now. Call finish() with the findings you have."
_CUT = (
    "Your reply was cut off at the token limit before it ended. Keep replies short: "
    "a few tool calls per turn and brief text. Continue the skill."
)
_CUT_FORCED = (
    "Your reply was cut off at the token limit before finish() was called. Call finish() "
    "now: one sentence per description, snippets limited to the cited lines."
)
_FINISH_CUT = (
    "finish() was cut off at the token limit before its JSON ended, so nothing was "
    "recorded. Call finish() again with shorter text: one sentence per description, "
    "snippets limited to the cited lines, and no fields you do not need."
)
_FINISH_BAD_JSON = (
    "finish() arguments were not a JSON object, so nothing was recorded. Call finish() "
    "again with a findings object: {\"hypotheses\": [...], \"evidence\": [...], "
    "\"coverage\": [...], \"open_questions\": [...]}."
)


def _focus(chunk: "list[Target]") -> tuple[str, ...]:
    tokens: list[str] = []
    for t in chunk:
        head = re.split(r"[:{*\[]", t.path, maxsplit=1)[0].rstrip("/")
        if len(head) > 1:
            tokens.append(head)
        if t.handler and t.file_path:
            tokens.append(t.file_path)
    return tuple(dict.fromkeys(tokens))


def _decided(coverage) -> list[str]:
    return [c.name for c in coverage if c.kind == "entry_point" and c.status != "unseen"]


def _with_context(text: str, extra_context: str) -> str:
    extra_context = (extra_context or "").strip()
    return f"{text}\n\n{extra_context}" if extra_context else text


def _short(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _unwrap_findings(args: dict) -> Optional[dict]:
    raw = args.get("findings", args)
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
    return raw if isinstance(raw, dict) else None


def _saves_map(skill_text: str) -> bool:
    return "save_threat_model" in skill_text or "amend_threat_model" in skill_text


def _force_finish(map_skill: bool) -> str:
    return f"{_FORCE_FINISH} {_FORCE_FINISH_MAP}" if map_skill else _FORCE_FINISH


def _add_note(messages: list[dict], note: str) -> None:
    last = messages[-1] if messages else None
    if last is not None and last.get("role") == "tool":
        messages[-1] = {**last, "content": f"{last.get('content') or ''}\n\n{note}"}
    else:
        messages.append({"role": "user", "content": note})


def _rejection(problems: list[str], forced: bool) -> str:
    shown = "\n".join(f"- {p}" for p in problems[:20])
    if len(problems) > 20:
        shown += f"\n- and {len(problems) - 20} more"
    return (
        "Findings NOT recorded. Fix these and call finish() again"
        + (" (only finish() is available now)" if forced else "") + ":\n" + shown +
        "\n\nEvery hypothesis needs at least one item in the top-level `evidence` array "
        "(file_path, line_start, line_end, snippet, anchor_text copied verbatim from the "
        "file, hypothesis_index). A hypothesis you cannot cite may stay as a lead: give it "
        "confidence 3 or less and say in `uncertainty` what is missing."
    )


class SkillRunner(ToolExecutor, EvidenceReconciler):
    def __init__(self, cfg: Config, db: EvidenceStore, mcp: CodebaseMemoryClient,
                 mcp_manager=None):
        self._cfg = cfg
        self.meter = UsageMeter(cfg.pricing, cfg.budget_usd, cfg.token_budget)
        self.run_id = new_run_id()
        self._llm = LLMClient(cfg, meter=self.meter)
        self._scope_seq = itertools.count(1)
        self._tier_clients: dict[str, LLMClient] = {}
        self._stack_cache: dict[str, StackProfile] = {}
        self._db = db
        self._mcp = mcp
        self._mcp_manager = mcp_manager
        self._skills_dir = cfg.resolved_skills()
        self._skills = SkillCatalog(self._skills_dir)
        self._profile_cache: dict[str, ProjectProfile] = {}
        self._project_cache: dict[str, Optional[str]] = {}
        self._on_tool_event: Optional[Any] = None

    def set_event_handler(self, handler) -> None:
        """Set a callback for tool call events.

        handler(event, data) is called with:
          event="tool_call"  data={"name": str, "args": dict, "iteration": int}
          event="tool_result" data={"name": str, "result": str, "iteration": int}
        """
        self._on_tool_event = handler

    def _emit_tool(self, event: str, data: dict) -> None:
        if self._on_tool_event:
            data.setdefault("skill", usage_scope.get().rsplit("@", 1)[0])
            try:
                self._on_tool_event(event, data)
            except Exception:
                pass

    def _profile(self, repo_path: str) -> ProjectProfile:
        if repo_path not in self._profile_cache:
            self._profile_cache[repo_path] = load_profile(
                repo_path,
                external_path=self._cfg.profile_path or None,
                trust_repo_profile=self._cfg.trust_repo_profile,
                use_cache=True,
            )
        return self._profile_cache[repo_path]

    def _load_skill(self, skill_name: str) -> str:
        return self._skills.body(skill_name)

    def _get_skill_phase(self, skill_name: str) -> str:
        info = self._skills.find(skill_name)
        return info.phase if info else ""

    def _get_commit(self, repo_path: str) -> str:
        try:
            r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_path,
                               capture_output=True, text=True, timeout=5)
            return r.stdout.strip()[:12] if r.returncode == 0 else ""
        except Exception:
            return ""

    def _build_initial_context(self, repo_path: str, focus: tuple[str, ...] = ()) -> str:
        parts: list[str] = []
        profile_text = self._profile(repo_path).to_prompt()
        if profile_text:
            parts.append(profile_text)
        threat_model = self._db.get_threat_model(repo_path, brief=True)
        if threat_model:
            parts.append("# Threat Model (built by prior skill — use this as your starting context)\n" + threat_model)
        entry_points = self._db.list_entry_points(repo_path)
        if entry_points:
            eps = [f"  {ep.kind} {ep.path} -> {ep.handler_qn} ({ep.file_path}:{ep.line})"
                   for ep in entry_points[:30]]
            parts.append("Known entry points:\n" + "\n".join(eps))
        guards = self._db.list_guards(repo_path)
        if guards:
            gs = [f"  {g.location_qn} covers_all={g.covers_all_paths}" for g in guards[:20]]
            parts.append("Known guards:\n" + "\n".join(gs))
        hypotheses = self._db.list_hypotheses(repo_path)
        if hypotheses:
            tokens = [f.lower() for f in focus if f]
            ranked = sorted(hypotheses, key=lambda h: (
                not any(tok in (h.entry_point or "").lower() for tok in tokens), -h.priority, h.id))
            shown = ranked[:_KNOWN_FINDINGS]
            hs = [f"  [{h.id}] {h.cwe or '-'} {_short(h.entry_point, 70)}: "
                  f"{_short(h.violated_invariant, 90)} (status={h.status})" for h in shown]
            if len(ranked) > len(shown):
                hs.append(f"  ... and {len(ranked) - len(shown)} more; list_hypotheses shows them all")
            parts.append("Findings already recorded. Do not report any of these again as a new "
                         "hypothesis; to add evidence to one, give its id as existing_id:\n"
                         + "\n".join(hs))

        open_questions = self._db.list_open_questions(repo_path, status="open")
        if open_questions:
            high = [q for q in open_questions if q.impact == "blocks_finding"]
            medium = [q for q in open_questions if q.impact == "affects_confidence"]
            parts_oq = []
            if high:
                parts_oq.append("BLOCKING:\n" + "\n".join(
                    f"  [{q.id}] {q.question}" + (f"\n  hint: {q.resolution_hint}" if q.resolution_hint else "")
                    for q in high[:10]))
            if medium:
                parts_oq.append("CONFIDENCE-AFFECTING:\n" + "\n".join(
                    f"  [{q.id}] {q.question}" for q in medium[:10]))
            if parts_oq:
                parts.append("Open questions from prior skills:\n" + "\n\n".join(parts_oq))

        conflicts = self._db.list_conflicts(repo_path, status="open")
        if conflicts:
            cs = [f"  [{c.id}] {c.kind} ({c.severity}): {c.description}" for c in conflicts[:10]]
            parts.append("Known conflicts:\n" + "\n".join(cs))

        return "\n\n".join(parts)

    def _save_threat_model_update(self, repo_path: str, skill_name: str, update) -> None:
        if not isinstance(update, dict):
            return
        content = str(update.get("content") or "").strip()
        if not content:
            return
        base, amendments = self._db.threat_model_parts(repo_path) or ("", [])
        if content == base.strip() or any(content == str(a.get("content") or "").strip()
                                          for a in amendments):
            return
        if update.get("base") is True and not base.strip() and len(content) >= 400:
            self._db.save_threat_model(repo_path, content, skill_name)
            return
        summary = update.get("summary") if isinstance(update.get("summary"), str) else ""
        self._db.amend_threat_model(repo_path, content, skill_name, summary)

    def _model_name(self, llm) -> str:
        return getattr(llm, "model", "") or self._cfg.model

    def _llm_for(self, tier: str = "main"):
        model = {"fast": self._cfg.fast_model, "verify": self._cfg.verify_model}.get(tier, "")
        if not model or model == self._model_name(self._llm):
            return self._llm
        client = self._tier_clients.get(model)
        if client is None:
            client = LLMClient(self._cfg, model=model, meter=self.meter)
            self._tier_clients[model] = client
        return client

    def _llm_for_skill(self, skill_name: str):
        info = self._skills.find(skill_name)
        return self._llm_for(info.tier if info else "main")

    def _window(self) -> ContextWindow:
        return ContextWindow(self._cfg.context_char_limit,
                             history_chars=self._cfg.history_char_limit)

    def _begin_scope(self, name: str, repo_path: str, llm, system: str):
        key = f"{name}@{next(self._scope_seq)}"
        token = usage_scope.set(key)
        transcript = open_transcript(self._cfg.resolved_transcripts(), self.run_id, repo_path, name,
                                     {"model": self._model_name(llm), "system": system})
        return key, token, transcript

    def _end_scope(self, key: str, token, transcript, name: str, repo_path: str,
                   status: str) -> Usage:
        usage_scope.reset(token)
        per_model = self.meter.for_scope(key)
        total = Usage()
        for model, u in per_model.items():
            total.add(u)
            try:
                self._db.save_usage(self.run_id, repo_path, name, model, u)
            except Exception:
                pass
        transcript.close(status=status, models=sorted(per_model), usage=total.to_dict())
        return total

    def _room(self) -> int:
        base = max(1, int(self._cfg.max_tokens or 1))
        return max(base, min(base * _ROOM_FACTOR, _ROOM_CAP))

    async def _turn(self, llm, transcript, messages: list[dict], tools: list[dict],
                    system: str, tool_choice=None, window: Optional[ContextWindow] = None,
                    room: bool = False, brief: bool = False) -> Reply:
        transcript.sync(messages)
        wire = window.view(messages) if window is not None else messages
        if hasattr(llm, "complete_turn"):
            extra: dict = {}
            if room:
                extra["max_tokens"] = self._room()
            if brief:
                extra["reasoning_effort"] = "low"
            return await llm.complete_turn(wire, tools, system=system, tool_choice=tool_choice,
                                           **extra)
        content, tool_calls = await llm.complete_with_tools(wire, tools, system=system,
                                                            tool_choice=tool_choice)
        return Reply(content, tool_calls, None)

    async def run_skill(
        self,
        skill_name: str,
        repo_path: str,
        extra_context: str = "",
        max_iterations: Optional[int] = None,
        verbose: bool = False,
        negative_evidence: Optional[bool] = None,
        label: Optional[str] = None,
        focus: tuple[str, ...] = (),
    ) -> SkillResult:
        if negative_evidence is None:
            negative_evidence = bool(self._cfg.negative_evidence)
        info = self._skills.find(skill_name)
        if info is not None and info.fanout and label is None:
            try:
                results = await self.run_fanout(skill_name, repo_path, verbose=verbose,
                                                negative_evidence=negative_evidence,
                                                max_iterations=max_iterations,
                                                extra_context=extra_context)
            except BudgetExceeded as exc:
                finished = getattr(exc, "fanout_results", [])
                exc.saved_batches = len(finished)
                exc.partial = self._combine(skill_name, repo_path, finished)
                raise
            return self._combine(skill_name, repo_path, results)
        if max_iterations is None:
            max_iterations = (info.max_turns if info and info.max_turns else _DEFAULT_TURNS)
        scope = label or skill_name
        llm = self._llm_for_skill(skill_name)
        system = HUNT_SYSTEM_PROMPT if skill_name.startswith("hunt-") else SYSTEM_PROMPT
        key, token, transcript = self._begin_scope(scope, repo_path, llm, system)
        status = "interrupted"
        try:
            result = await self._run_skill_inner(
                skill_name, repo_path, extra_context, max_iterations, verbose,
                negative_evidence, llm, transcript, focus)
            status = "done"
        finally:
            usage = self._end_scope(key, token, transcript, scope, repo_path, status)
        result.model = self._model_name(llm)
        result.usage = usage.to_dict()
        return result

    async def _run_skill_inner(
        self,
        skill_name: str,
        repo_path: str,
        extra_context: str,
        max_iterations: int,
        verbose: bool,
        negative_evidence: bool,
        llm,
        transcript,
        focus: tuple[str, ...] = (),
    ) -> SkillResult:
        skill_text = self._load_skill(skill_name)
        commit = self._get_commit(repo_path)
        known_context = self._build_initial_context(repo_path, focus)
        phase = self._get_skill_phase(skill_name)
        _ne_eligible = negative_evidence and phase in ("p3", "p4", "")

        project_name = await self._project_for(repo_path)
        mcp_hint = (
            f"\n# Codebase Graph Index\nProject name: `{project_name}`\n"
            "The engine passes it to get_architecture(), search_graph(), trace_path(), "
            "get_code_snippet() and search_code() for you."
            if project_name else
            "\n# Codebase Graph Index\nThis repository has no graph index, so get_architecture(), "
            "search_graph(), trace_path(), get_code_snippet() and search_code() are unavailable. "
            "Use list_dir, read_file, parse_file_structure, find_all_usages and grep."
        )
        orientation = (
            f"Start by calling get_architecture(project=\"{project_name}\") to orient yourself, "
            "then use the other tools to read real code and build evidence."
            if project_name else
            "Start with list_dir and parse_file_structure to orient yourself, then read real "
            "code and build evidence."
        )

        is_hunt = skill_name.startswith("hunt-")
        active_system_prompt = HUNT_SYSTEM_PROMPT if is_hunt else SYSTEM_PROMPT
        _active_contract = HUNT_OUTPUT_CONTRACT if is_hunt else OUTPUT_CONTRACT
        start_instruction = (
            f"Repository: {repo_path}  (commit: {commit})\n\n"
            "# Skill Contract\n"
            f"{skill_text}\n\n"
            f"{_active_contract}\n"
            f"{_NE_INSTRUCTION if _ne_eligible else ''}"
            f"# Known Context\n{known_context}\n"
            f"{mcp_hint}\n"
            f"{f'# Additional Context{chr(10)}{extra_context}' if extra_context else ''}\n\n"
            "Follow the Skill Contract steps in order. Call finish() when done."
        ) if is_hunt else (
            f"Repository: {repo_path}  (commit: {commit})\n\n"
            "# Skill Contract\n"
            f"{skill_text}\n\n"
            f"{OUTPUT_CONTRACT}\n"
            f"{_NE_INSTRUCTION if _ne_eligible else ''}"
            f"# Known Context\n{known_context}\n"
            f"{mcp_hint}\n"
            f"{f'# Additional Context{chr(10)}{extra_context}' if extra_context else ''}\n\n"
            f"{orientation} Call finish() when done."
        )
        initial_msg = start_instruction

        messages: list[dict] = [{"role": "user", "content": initial_msg}]
        transcript.bind(messages)
        window = self._window()
        findings: Optional[dict] = None

        finish_tool = next(t for t in TOOLS if t["function"]["name"] == "finish")
        nudge_at = max(0, max_iterations - _FORCED_TURNS)
        map_skill = _saves_map(skill_text)
        brief = False
        refused = False
        empty_forced = 0
        finish_retries = 0
        no_output = ""
        for iteration in range(max_iterations):
            forced = iteration >= nudge_at
            if forced and iteration == nudge_at:
                _add_note(messages, _force_finish(map_skill))
            tools_to_use = [finish_tool] if forced and refused else TOOLS
            reply = await self._turn(
                llm, transcript, messages, tools_to_use, active_system_prompt,
                tool_choice=_FINISH_CHOICE if forced else None,
                window=window, room=forced or brief, brief=brief,
            )
            transcript.event("turn", iteration=iteration, finish_reason=reply.finish_reason,
                             forced=forced, brief=brief)
            content, tool_calls = reply.content, reply.tool_calls
            cut = reply.truncated
            brief = False

            assistant_msg: dict = {"role": "assistant"}
            if content:
                assistant_msg["content"] = content
            if tool_calls:
                assistant_msg["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ]
            if "content" in assistant_msg or "tool_calls" in assistant_msg:
                messages.append(assistant_msg)

            if not tool_calls:
                if content:
                    try:
                        start = content.find("{")
                        end = content.rfind("}") + 1
                        if start >= 0 and end > start:
                            parsed = json.loads(content[start:end])
                            if isinstance(parsed, dict) and isinstance(parsed.get("findings"), dict):
                                findings = parsed["findings"]
                            elif isinstance(parsed, dict) and "hypotheses" in parsed:
                                findings = parsed
                    except Exception:
                        pass
                if isinstance(findings, dict) or iteration + 1 >= max_iterations:
                    break
                if "content" not in assistant_msg:
                    messages.append({"role": "assistant", "content": "(no response)"})
                    if forced:
                        empty_forced += 1
                        if empty_forced >= _EMPTY_FORCED_LIMIT:
                            no_output = (f"the model gave no finish() output in {empty_forced} "
                                         f"forced attempts (last finish_reason="
                                         f"{reply.finish_reason or 'none'})")
                            break
                brief = cut or (forced and not content)
                if cut:
                    nudge = _CUT_FORCED if forced else _CUT
                else:
                    nudge = _CONTINUE_FORCED if forced else _CONTINUE
                messages.append({"role": "user", "content": nudge})
                continue

            finish_args: Optional[dict] = None
            tool_results: list[dict] = []

            for tc in tool_calls:
                name = tc.function.name
                broken = False
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                    broken = True
                if not isinstance(args, dict):
                    args = {}
                    broken = True

                if name == "finish":
                    raw_findings = None if broken else _unwrap_findings(args)
                    can_retry = finish_retries < _FINISH_RETRIES and iteration + 1 < max_iterations
                    if raw_findings is None and can_retry:
                        finish_retries += 1
                        brief = cut
                        result_text = _FINISH_CUT if cut else _FINISH_BAD_JSON
                    elif raw_findings is None:
                        why = "cut off at the token limit" if cut else "not a JSON object"
                        finish_args = {"hypotheses": [], "coverage": [], "open_questions": [
                            f"finish() arguments were {why}; nothing was recorded"]}
                        result_text = "Findings recorded."
                    else:
                        problems = _finish_problems(
                            raw_findings, commit,
                            {h.id for h in self._db.list_hypotheses(repo_path)})
                        if problems and can_retry:
                            finish_retries += 1
                            result_text = _rejection(problems, forced)
                        else:
                            finish_args = raw_findings
                            result_text = "Findings recorded."
                elif forced:
                    refused = True
                    result_text = _FORCED_REFUSED
                elif broken:
                    brief = brief or cut
                    result_text = (
                        f"The arguments of this {name} call were cut off at the token limit; "
                        "call it again, with fewer calls per turn." if cut else
                        f"The arguments of this {name} call were not valid JSON; call it again."
                    )
                else:
                    if verbose:
                        print(f"  [{iteration}] tool={name} args={json.dumps(args)[:120]}")
                    self._emit_tool("tool_call", {"name": name, "args": args, "iteration": iteration})
                    result_text = await self._execute_tool(name, args, repo_path, skill_name)
                    if verbose:
                        print(f"  → {result_text[:200]}")
                    self._emit_tool("tool_result", {"name": name, "result": result_text[:200], "iteration": iteration})

                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })

            messages.extend(tool_results)

            if finish_args is not None:
                findings = finish_args
                break

        if findings is None or not isinstance(findings, dict):
            why = no_output or f"no finish() call within {max_iterations} iterations"
            findings = {"hypotheses": [], "coverage": [], "open_questions": [
                f"skill {skill_name} produced no structured output: {why}"
            ]}

        validation_errors: list[str] = []
        hypotheses = []
        hypothesis_by_index: dict[int, Hypothesis] = {}
        raw_hypotheses = _as_list(findings.get("hypotheses"))
        merged: list[Hypothesis] = []
        claims: dict[str, list[dict]] = {}
        for raw_idx, h_data in enumerate(raw_hypotheses):
            if not isinstance(h_data, dict):
                validation_errors.append(f"hypothesis[{raw_idx}] is not an object")
                continue
            existing = _existing_id(h_data)
            if existing:
                prior = self._db.get_hypothesis(repo_path, existing)
                if prior is not None:
                    if all(m.id != prior.id for m in merged):
                        merged.append(prior)
                    claims.setdefault(prior.id, []).append(h_data)
                    hypothesis_by_index[raw_idx] = next(m for m in merged if m.id == prior.id)
                    continue
                validation_errors.append(
                    f"hypothesis[{raw_idx}]: existing_id {existing!r} is not a recorded finding; "
                    "kept as a new hypothesis")
            h_data, demotion = _prepare_model_hypothesis(h_data, commit)
            h_data["skill_source"] = skill_name
            h_data["model"] = self._model_name(llm)
            h, error = _validate_model_hypothesis(h_data)
            if h is None:
                validation_errors.append(
                    f"hypothesis[{raw_idx}] validation error: "
                    f"{str(h_data.get('violated_invariant', ''))[:80]} ({error})")
                continue
            _apply_model_demotion(h, demotion, commit)
            hypotheses.append(h)
            hypothesis_by_index[raw_idx] = h

        coverage = []
        for c in _as_list(findings.get("coverage")):
            try:
                coverage.append(CoverageItem.model_validate(c))
            except Exception:
                pass

        entry_points: list[EntryPoint] = []
        for i, ep_data in enumerate(_as_list(findings.get("entry_points_found"))):
            try:
                entry_points.append(EntryPoint.model_validate(ep_data))
            except Exception as ex:
                validation_errors.append(f"entry_point[{i}] invalid: {ex}")

        guards: list[Guard] = []
        for i, g_data in enumerate(_as_list(findings.get("guards_found"))):
            try:
                guards.append(Guard.model_validate(g_data))
            except Exception as ex:
                validation_errors.append(f"guard[{i}] invalid: {ex}")

        auto_conflicts: list[ConflictRecord] = []

        evidence_items: list[Evidence] = []
        for i, e_data in enumerate(_as_list(findings.get("evidence"))):
            try:
                e_data = dict(e_data)
                e_data.pop("id", None)
                e_data.pop("stale", None)
                # defaulting to 0 attached every unlabeled item to the first
                # hypothesis, promoting it on other findings' evidence while the
                # rest were left with none
                if "hypothesis_index" in e_data:
                    hyp_idx = e_data.pop("hypothesis_index")
                elif len(raw_hypotheses) == 1:
                    hyp_idx = 0
                else:
                    validation_errors.append(
                        f"evidence[{i}]: hypothesis_index missing and {len(raw_hypotheses)} "
                        "hypotheses present; cannot attribute evidence"
                    )
                    continue
                if isinstance(hyp_idx, str) and hyp_idx.strip().isdigit():
                    hyp_idx = int(hyp_idx.strip())
                if isinstance(hyp_idx, bool) or not isinstance(hyp_idx, int) \
                        or not (0 <= hyp_idx < len(raw_hypotheses)):
                    validation_errors.append(f"evidence[{i}]: hypothesis_index {hyp_idx} out of range")
                    continue
                if hyp_idx not in hypothesis_by_index:
                    validation_errors.append(
                        f"evidence[{i}]: hypothesis_index {hyp_idx} refers to a hypothesis "
                        "that failed validation")
                    continue
                e_data = _prepare_model_evidence(e_data)
                e_data["hypothesis_id"] = hypothesis_by_index[hyp_idx].id
                e_data["commit"] = commit
                evidence_items.append(Evidence.model_validate(e_data))
            except Exception as ex:
                validation_errors.append(f"evidence[{i}] invalid: {ex}")

        evidence_items, ev_conflicts = self._verify_evidence_items(repo_path, evidence_items)
        auto_conflicts.extend(ev_conflicts)

        tool_index = _build_tool_call_index(messages)
        run_tools = frozenset(name for name, _ in tool_index)
        spans = _read_spans(tool_index, repo_path)
        for ev in evidence_items:
            seen = _read_verified(ev, spans, repo_path)
            capped = _cap_method_per_evidence(
                ev.analysis_quality.method, ev.file_path, ev.description,
                tool_index, run_tools, read_verified=seen,
            )
            if seen and capped == "structural" and _cap_method_per_evidence(
                    ev.analysis_quality.method, ev.file_path, ev.description,
                    tool_index, run_tools) != "structural":
                ev.analysis_quality.limitations.append(
                    "structural because read_file showed the cited lines and the anchor was found "
                    "in them; no graph or parser tool was used")
            if capped != ev.analysis_quality.method:
                ev.analysis_quality.limitations.append(
                    f"method downgraded {ev.analysis_quality.method}→{capped}: "
                    f"no matching tool call found for this evidence"
                )
                ev.analysis_quality.method = capped

        structured_questions: list[OpenQuestion] = []
        for sq_data in _as_list(findings.get("structured_questions")):
            try:
                sq = OpenQuestion.model_validate(_without_id(sq_data))
                sq.raised_by_skill = skill_name
                structured_questions.append(sq)
            except Exception as ex:
                validation_errors.append(f"structured_question invalid: {ex}")

        fn_summaries: list[FunctionSummary] = []
        for fs_data in _as_list(findings.get("function_summaries")):
            try:
                fs = FunctionSummary.model_validate(_without_id(fs_data))
                fs.created_by_skill = skill_name
                fs.commit = commit
                fn_summaries.append(fs)
            except Exception as ex:
                validation_errors.append(f"function_summary invalid: {ex}")

        ignored_returns: list[ReturnValueContract] = []
        for rc_data in _as_list(findings.get("ignored_returns")):
            try:
                rc = ReturnValueContract.model_validate(_without_id(rc_data))
                rc.created_by_skill = skill_name
                ignored_returns.append(rc)
            except Exception as ex:
                validation_errors.append(f"ignored_return invalid: {ex}")

        llm_conflicts: list[ConflictRecord] = []
        for i, c_data in enumerate(_as_list(findings.get("conflicts"))):
            try:
                llm_conflicts.append(ConflictRecord.model_validate(_without_id(c_data)))
            except Exception as ex:
                validation_errors.append(f"conflict[{i}] invalid: {ex}")

        for h in hypotheses:
            if h.guard_coverage == "all_paths" and h.uncovered_paths:
                auto_conflicts.append(ConflictRecord(
                    kind="guard_mismatch",
                    description=(
                        f"Hypothesis {h.id} claims guard_coverage=all_paths "
                        f"but lists {len(h.uncovered_paths)} uncovered path(s)"
                    ),
                    left=f"{h.id}.guard_coverage=all_paths",
                    right=f"{h.id}.uncovered_paths={h.uncovered_paths[:2]}",
                    severity="degrades_confidence",
                ))

        all_conflicts = auto_conflicts + llm_conflicts

        db_open_questions = self._db.list_open_questions(repo_path, status="open")
        all_open_questions = db_open_questions + structured_questions
        profile = self._profile(repo_path)

        for h in hypotheses:
            ev_for_h = [e for e in evidence_items if e.hypothesis_id == h.id]
            if not ev_for_h:
                synthetic = _synthesize_evidence_from_tools(h, tool_index, run_tools, commit,
                                                            repo_path=repo_path)
                evidence_items.extend(synthetic)
                ev_for_h = synthetic
            ev_ids = {e.id for e in ev_for_h}
            # word-boundary match: an 8-hex id is a substring of longer hex tokens,
            # so a plain `in` let one finding's conflict block an unrelated one
            id_re = re.compile(rf"\b{re.escape(h.id)}\b")
            conf_for_h = [
                c for c in all_conflicts
                if (h.id in (c.left, c.right)
                    or id_re.search(c.description)
                    or any(f"evidence/{eid}" in (c.left, c.right) for eid in ev_ids))
            ]
            _apply_quality_caps(h, ev_for_h)
            _inject_minimum_obligations(h)
            # profile first: it sets exposure (which the gate reads) and can
            # reject outright, so running it after let an override of
            # exposure=unreachable still export
            _apply_profile(h, ev_for_h, profile, commit=commit)
            h.status = _gate_hypothesis_status(h, ev_for_h, conf_for_h, all_open_questions)
            h.priority = h.compute_priority()

        updated: list[Hypothesis] = []
        for h in merged:
            added = [e for e in evidence_items if e.hypothesis_id == h.id and not e.stale]
            if not added:
                continue
            for e in added:
                e.merged_by = skill_name
            _merge_model_claims(h, claims.get(h.id, []))
            if h.status in ("rejected", "blocked") and h.rejected_by != "human":
                h.uncertainty.append(
                    f"reopened by new evidence from {skill_name} after it was {h.status}"
                    + (f" ({h.rejection_reason})" if h.rejection_reason else ""))
                h.status = "initial"
                h.rejected_by = None
                h.rejection_reason = None
                h.rejection_condition = ""
                h.rejected_at_commit = ""
            ev_all = self._db.get_evidence_for_hypothesis(h.id) + added
            ev_ids = {e.id for e in added}
            conf_for_h = self._db.get_conflicts_for_hypothesis(h.id, repo_path) + [
                c for c in all_conflicts
                if h.id in (c.left, c.right) or any(f"evidence/{eid}" in (c.left, c.right) for eid in ev_ids)]
            h.uncertainty.append(f"{len(added)} evidence item(s) added by {skill_name}")
            _apply_quality_caps(h, ev_all)
            _inject_minimum_obligations(h)
            _apply_profile(h, ev_all, profile, commit=commit)
            h.status = _gate_hypothesis_status(h, ev_all, conf_for_h, all_open_questions)
            h.priority = h.compute_priority()
            updated.append(h)

        _raw_oq = findings.get("open_questions")
        if isinstance(_raw_oq, list):
            open_questions = list(_raw_oq)
        elif isinstance(_raw_oq, str) and _raw_oq.strip():
            open_questions = [_raw_oq]
        else:
            open_questions = []
        open_questions += validation_errors

        if _ne_eligible:
            from .peer_analysis import _normalize_path as _norm_ep
            from .sarif import _normalise_cwe
            ne_raw = _as_list(findings.get("negative_evidence"))
            ne_items: list[NegativeEvidence] = []
            for idx, ne_data in enumerate(ne_raw):
                try:
                    ne = NegativeEvidence(
                        entry_point=_norm_ep(ne_data["entry_point"]),
                        safe_from=_normalise_cwe(ne_data.get("safe_from", "")) or ne_data.get("safe_from", ""),
                        because=ne_data["because"],
                        anchor_file=ne_data["anchor_file"],
                        anchor_line=int(ne_data["anchor_line"]),
                        anchor_text=ne_data["anchor_text"],
                        commit=commit,
                    )
                    ne_items.append(ne)
                except Exception as ex:
                    open_questions.append(f"negative_evidence[{idx}] invalid: {ex}")
            self._verify_negative_evidence(repo_path, ne_items)
            for ne in ne_items:
                if ne.anchor_stale:
                    open_questions.append(
                        f"negative_evidence discarded (born-stale anchor): "
                        f"{ne.entry_point} anchor_file={ne.anchor_file}:{ne.anchor_line}"
                    )
                else:
                    self._db.save_negative_evidence(repo_path, ne)

        self._save_threat_model_update(repo_path, skill_name, findings.get("threat_model_update"))
        result = SkillResult(
            skill_name=skill_name,
            repo_path=repo_path,
            commit=commit,
            hypotheses=hypotheses,
            evidence=evidence_items,
            coverage=coverage,
            open_questions=open_questions,
            structured_questions=structured_questions,
            function_summaries=fn_summaries,
            conflicts=all_conflicts,
            ignored_returns=ignored_returns,
            entry_points_found=entry_points,
            guards_found=guards,
        )
        self._db.save_skill_result(repo_path, result)
        self._clear_undecided(repo_path, coverage)
        for h in updated:
            self._db.save_hypothesis(repo_path, h)
        result.merged = [h.id for h in updated]
        return result

    async def _run_skill_list(self, skills: list[str], repo_path: str,
                              verbose: bool, resume: bool,
                              on_progress=None,
                              negative_evidence: Optional[bool] = None,
                              conditional: frozenset = frozenset(),
                              skill_gating: Optional[bool] = None) -> list[SkillResult]:
        """Run skills, recording each completion so an interrupted scan can resume.

        A scan is many minutes of paid LLM calls; losing all of it to one Ctrl+C
        is the difference between a tool you can stop and one you must babysit.
        """
        commit = self._get_commit(repo_path)
        done = completed_skills(repo_path, commit) if resume else set()
        if not resume:
            # only drop progress for the skills this invocation will redo;
            # `--phase p4` used to wipe a completed full run's record
            forget_skills(repo_path, commit, skills)

        gating = self._cfg.skill_gating if skill_gating is None else skill_gating
        stack = await self._stack(repo_path) if gating else None
        concurrency = max(1, int(self._cfg.concurrency or 1))
        results: list[SkillResult] = []
        reported_skips: set[str] = set()
        batch: list[str] = []

        async def run_one(name: str, parallel: bool) -> SkillResult:
            if on_progress:
                on_progress(name, "started", {"model": self._model_name(self._llm_for_skill(name)),
                                              "parallel": parallel})
            try:
                result = await self.run_skill(name, repo_path, verbose=verbose,
                                             negative_evidence=negative_evidence)
            except BaseException:
                if on_progress:
                    on_progress(name, "interrupted", None)
                raise
            mark_skill_done(repo_path, commit, name)
            self._db.delete_coverage(repo_path, "skill", name)
            if on_progress:
                on_progress(name, "done", result)
            return result

        async def flush() -> None:
            names = list(batch)
            batch.clear()
            if len(names) == 1:
                results.append(await run_one(names[0], False))
                return
            if not names:
                return
            gate = asyncio.Semaphore(concurrency)

            async def guarded(name: str) -> SkillResult:
                async with gate:
                    return await run_one(name, True)

            tasks = [asyncio.ensure_future(guarded(n)) for n in names]
            try:
                results.extend(await asyncio.gather(*tasks))
            except BaseException:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise

        for name in skills:
            if name in done:
                if on_progress and name not in reported_skips:
                    on_progress(name, "skipped", None)
                reported_skips.add(name)
                continue
            info = self._skills.find(name)
            reason = ""
            if stack is not None and info is not None and info.requires \
                    and not stack.has_any(info.requires):
                reason = f"no {describe(info.requires)} found"
            elif gating and info is not None and info.optional and not self._cfg.optional_skills:
                reason = "optional, off unless optional_skills is on or --all-skills is given"
            if reason:
                mark_skill_done(repo_path, commit, name)
                self._db.upsert_coverage(repo_path, CoverageItem(
                    kind="skill", name=name, status="not_applicable", exclusion_reason=reason),
                    force=True)
                if on_progress:
                    on_progress(name, "not_applicable", reason)
                continue
            if info is not None and info.fanout:
                await flush()
                results.extend(await self.run_fanout(
                    name, repo_path, verbose=verbose, negative_evidence=negative_evidence,
                    resume=resume, on_progress=on_progress, track=True))
                mark_skill_done(repo_path, commit, name)
                self._db.delete_coverage(repo_path, "skill", name)
                continue
            if info is not None and info.parallel and concurrency > 1:
                batch.append(name)
                continue
            await flush()
            if name in conditional and not self._has_blocking_questions(repo_path):
                mark_skill_done(repo_path, commit, name)
                continue
            results.append(await run_one(name, False))
        await flush()
        return results

    async def _graph_routes(self, repo_path: str) -> list[tuple[str, str, str]]:
        query = getattr(self._mcp, "query_graph", None)
        if query is None:
            return []
        project = await self._project_for(repo_path)
        if not project:
            return []
        routes: list[tuple[str, str, str]] = []
        page: dict = {}
        seen: set = set()
        for _ in range(_GRAPH_PAGES):
            try:
                result = await query(GRAPH_ROUTES_QUERY, project=project, fmt="json", **page)
            except Exception:
                break
            routes.extend(parse_graph_routes(result))
            if not isinstance(result, dict) or not result.get("has_more"):
                break
            if result.get("next_cursor"):
                page = {"cursor": result["next_cursor"]}
            elif isinstance(result.get("next_offset"), int):
                page = {"offset": result["next_offset"]}
            else:
                break
            marker = tuple(page.items())
            if marker in seen:
                break
            seen.add(marker)
        return routes

    def _flag_undecided(self, repo_path: str, skill_name: str, targets: list[Target]) -> None:
        rows = [r for r in self._db.coverage_detail(repo_path) if r["kind"] == "entry_point"]
        decided = [r["name"] for r in rows if r["status"] != "unseen"
                   and not self._db.is_undecided_flag(r["status"], r["blocker"])]
        for t in uncovered(targets, decided):
            self._db.upsert_coverage(repo_path, CoverageItem(
                kind="entry_point", name=t.name, status="needs_follow_up",
                blocker=f"{skill_name} {UNDECIDED_BLOCKER}"))

    def _clear_undecided(self, repo_path: str, coverage) -> None:
        decided = _decided(coverage)
        if not decided:
            return
        for row in self._db.coverage_detail(repo_path):
            if row["kind"] != "entry_point" or not self._db.is_undecided_flag(row["status"], row["blocker"]):
                continue
            target = target_from_name(row["name"])
            if target is not None and not uncovered([target], decided):
                self._db.delete_coverage(repo_path, "entry_point", row["name"])

    async def run_fanout(self, skill_name: str, repo_path: str, verbose: bool = False,
                         negative_evidence: Optional[bool] = None, resume: bool = False,
                         on_progress=None, max_iterations: Optional[int] = None,
                         extra_context: str = "", track: bool = False) -> list[SkillResult]:
        info = self._skills.find(skill_name)
        size = info.batch if info is not None else 6
        commit = self._get_commit(repo_path)
        targets = inventory(self._db.list_entry_points(repo_path), await self._graph_routes(repo_path))
        if not targets:
            label = f"{skill_name}#00"
            if on_progress:
                on_progress(label, "started", {"model": self._model_name(self._llm_for_skill(skill_name)),
                                               "parallel": False})
            try:
                result = await self.run_skill(skill_name, repo_path,
                                              extra_context=_with_context(_NO_INVENTORY, extra_context),
                                              max_iterations=max_iterations, verbose=verbose,
                                              negative_evidence=negative_evidence, label=label)
            except BaseException:
                if on_progress:
                    on_progress(label, "interrupted", None)
                raise
            if on_progress:
                on_progress(label, "done", result)
            return [result]
        gate = asyncio.Semaphore(max(1, int(self._cfg.concurrency or 1)))
        finished: dict[str, SkillResult] = {}
        order: list[str] = []

        async def one(label: str, index: int, total: int, chunk: list[Target], retry: bool):
            async with gate:
                if on_progress:
                    on_progress(label, "started", {"model": self._model_name(self._llm_for_skill(skill_name)),
                                                   "parallel": True})
                try:
                    result = await self.run_skill(
                        skill_name, repo_path,
                        extra_context=_with_context(assignment(chunk, index, total), extra_context),
                        max_iterations=max_iterations, verbose=verbose,
                        negative_evidence=negative_evidence, label=label, focus=_focus(chunk))
                except BaseException:
                    if on_progress:
                        on_progress(label, "interrupted", None)
                    raise
                left = uncovered(chunk, _decided(result.coverage))
                finished[label] = result
                if track:
                    record_fanout(repo_path, commit, skill_name, retry,
                                  [t.name for t in chunk], [t.name for t in left])
                if on_progress:
                    on_progress(label, "done", result)
                return left

        async def run_plan(plan: list[list[Target]], prefix: str, retry: bool) -> list[Target]:
            labels = [f"{skill_name}#{prefix}{i:02d}" for i in range(1, len(plan) + 1)]
            order.extend(labels)
            tasks = [asyncio.ensure_future(one(label, i, len(plan), chunk, retry))
                     for i, (label, chunk) in enumerate(zip(labels, plan), 1)]
            try:
                outcomes = await asyncio.gather(*tasks)
            except BaseException:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            return [t for left in outcomes for t in left]

        def results() -> list[SkillResult]:
            return [finished[label] for label in order if label in finished]

        def resolve(names: list[str]) -> list[Target]:
            by_key = {t.key: t for t in targets}
            out: dict = {}
            for name in names:
                t = target_from_name(name)
                if t is not None:
                    out.setdefault(t.key, by_key.get(t.key, t))
            return list(out.values())

        try:
            progress = fanout_progress(repo_path, commit, skill_name) if track and resume else {}
            reviewed = {coverage_key(n) for n in progress.get("reviewed", [])}
            pending = [t for t in targets if t.key not in reviewed]
            left = await run_plan(make_batches(pending, size), "", False) if pending else []
            if track:
                progress = fanout_progress(repo_path, commit, skill_name)
                retried = {coverage_key(n) for n in progress.get("retried", [])}
                missing = [t for t in resolve(progress.get("undecided", [])) if t.key not in retried]
            else:
                missing = left
            failed = await run_plan(make_batches(missing, size), "r", True) if missing else []
            if track:
                failed = resolve(fanout_progress(repo_path, commit, skill_name).get("failed", []))
        except BudgetExceeded as exc:
            exc.fanout_results = results()
            raise
        self._flag_undecided(repo_path, skill_name, failed)
        return results()

    def _combine(self, skill_name: str, repo_path: str, results: list[SkillResult]) -> SkillResult:
        out = SkillResult(skill_name=skill_name, repo_path=repo_path,
                          commit=self._get_commit(repo_path))
        total = Usage()
        for r in results:
            out.hypotheses.extend(r.hypotheses)
            out.evidence.extend(r.evidence)
            out.coverage.extend(r.coverage)
            out.open_questions.extend(r.open_questions)
            out.entry_points_found.extend(r.entry_points_found)
            out.guards_found.extend(r.guards_found)
            out.conflicts.extend(r.conflicts)
            out.merged.extend(m for m in r.merged if m not in out.merged)
            total.add(Usage.from_dict(r.usage or {}))
        out.model = results[0].model if results else self._model_name(self._llm_for_skill(skill_name))
        out.usage = total.to_dict()
        return out

    async def _stack(self, repo_path: str) -> StackProfile:
        if repo_path not in self._stack_cache:
            self._stack_cache[repo_path] = await asyncio.to_thread(detect_stack, repo_path)
        return self._stack_cache[repo_path]

    def _phase_skills(self, phase: str) -> list[str]:
        phase = phase.strip().lower()
        if phase.isdigit():
            phase = f"p{phase}"
        return [s.name for s in self._skills.phase_skills(phase)]

    def _all_skills(self) -> list[str]:
        phases = self._skills.phases()
        maintenance_skills = (self._phase_skills(MAINTENANCE_PHASE)
                              if MAINTENANCE_PHASE in phases else [])
        names: list[str] = []
        for phase in phases:
            if phase == MAINTENANCE_PHASE:
                continue
            names.extend(maintenance_skills)
            names.extend(self._phase_skills(phase))
        if not names:
            names.extend(maintenance_skills)
        return names

    def _maintenance_skills(self) -> frozenset:
        if MAINTENANCE_PHASE not in self._skills.phases():
            return frozenset()
        return frozenset(self._phase_skills(MAINTENANCE_PHASE))

    def _has_blocking_questions(self, repo_path: str) -> bool:
        return any(q.impact == "blocks_finding"
                   for q in self._db.list_open_questions(repo_path, status="open"))

    async def run_phase(self, phase: str, repo_path: str, verbose: bool = False,
                        resume: bool = False, on_progress=None,
                        negative_evidence: Optional[bool] = None,
                        skill_gating: Optional[bool] = None) -> list[SkillResult]:
        results = await self._run_skill_list(
            self._phase_skills(phase), repo_path, verbose, resume, on_progress,
            negative_evidence=negative_evidence, skill_gating=skill_gating)
        self.reconcile(repo_path)
        return results

    async def run_all(self, repo_path: str, verbose: bool = False,
                      resume: bool = False, on_progress=None,
                      negative_evidence: Optional[bool] = None,
                      skill_gating: Optional[bool] = None) -> list[SkillResult]:
        results = await self._run_skill_list(
            self._all_skills(), repo_path, verbose, resume, on_progress,
            negative_evidence=negative_evidence,
            conditional=self._maintenance_skills(), skill_gating=skill_gating)
        self.reconcile(repo_path)
        return results

    async def verify_hypothesis(self, hyp_id: str, repo_path: str, verbose: bool = False) -> dict:
        llm = self._llm_for("verify")
        key, token, transcript = self._begin_scope(f"verify:{hyp_id}", repo_path, llm, SYSTEM_PROMPT)
        status = "interrupted"
        try:
            verdict = await self._verify_inner(hyp_id, repo_path, verbose, llm, transcript)
            status = "done"
        finally:
            self._end_scope(key, token, transcript, f"verify:{hyp_id}", repo_path, status)
        return verdict

    async def _verify_inner(self, hyp_id: str, repo_path: str, verbose: bool,
                            llm, transcript) -> dict:
        hypotheses = self._db.list_hypotheses(repo_path)
        hyp = next((h for h in hypotheses if h.id == hyp_id), None)
        if not hyp:
            raise ValueError(f"Hypothesis {hyp_id} not found")

        initial_msg = f"""Adversarially verify this hypothesis. Your job is to REFUTE it.

{hyp.model_dump_json(indent=2)}

Use tools to read the actual code for each step in the execution_path.
Check every item in counterevidence — are the claimed guards actually effective?
Check: is the entry point reachable? Is the field actually user-controlled? Is there a downstream guard?

When done, call finish() with:
{{
  "hypotheses": [],
  "coverage": [],
  "open_questions": [],
  "verdict": {{
    "is_real": true/false,
    "suggested_status": "reproduced|refuted|blocked|evidence_supported",
    "refutation_reason": "string or null",
    "confirmed_steps": ["steps verified in code"],
    "failed_steps": ["steps that don't hold"]
  }}
}}"""

        VERIFY_TOOLS = TOOLS[:-1] + [{
            "type": "function",
            "function": {
                "name": "finish",
                "description": "Submit verification verdict.",
                "parameters": {
                    "type": "object",
                    "required": ["findings"],
                    "properties": {
                        "findings": {
                            "type": "object",
                            "required": ["hypotheses", "coverage", "open_questions", "verdict"],
                            "properties": {
                                "hypotheses": {"type": "array", "items": {}},
                                "coverage": {"type": "array", "items": {}},
                                "open_questions": {"type": "array", "items": {"type": "string"}},
                                "verdict": {
                                    "type": "object",
                                    "required": ["is_real", "suggested_status"],
                                    "properties": {
                                        "is_real": {"type": "boolean"},
                                        "suggested_status": {"type": "string"},
                                        "refutation_reason": {"type": ["string", "null"]},
                                        "confirmed_steps": {"type": "array", "items": {"type": "string"}},
                                        "failed_steps": {"type": "array", "items": {"type": "string"}},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }]

        messages: list[dict] = [{"role": "user", "content": initial_msg}]
        transcript.bind(messages)
        window = self._window()
        verdict: dict = {}

        for iteration in range(25):
            content, tool_calls = await self._turn(
                llm, transcript, messages, VERIFY_TOOLS, SYSTEM_PROMPT, window=window
            )
            assistant_msg: dict = {"role": "assistant"}
            if content:
                assistant_msg["content"] = content
            if tool_calls:
                assistant_msg["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ]
            messages.append(assistant_msg)

            if not tool_calls:
                break

            finish_args = None
            tool_results = []
            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                if name == "finish":
                    finish_args = args.get("findings", args)
                    tool_results.append({"role": "tool", "tool_call_id": tc.id,
                                         "content": "Verdict recorded."})
                else:
                    if verbose:
                        print(f"  [verify-{iteration}] {name}({json.dumps(args)[:100]})")
                    res = await self._execute_tool(name, args, repo_path, "verify")
                    tool_results.append({"role": "tool", "tool_call_id": tc.id, "content": res})

            messages.extend(tool_results)
            if finish_args is not None:
                if isinstance(finish_args, str):
                    try:
                        finish_args = json.loads(finish_args)
                    except (json.JSONDecodeError, TypeError):
                        finish_args = {}
                if isinstance(finish_args, dict):
                    verdict = finish_args.get("verdict", finish_args)
                if not isinstance(verdict, dict):
                    verdict = {}
                break

        _REVIEW_STATUS_MAP = {
            "reproduced": "evidence_supported",
            "evidence_supported": "evidence_supported",
            "refuted": "refuted",
            "blocked": "blocked",
            "initial": "initial",
        }
        suggested = str(verdict.get("suggested_status") or hyp.status)
        new_status = _REVIEW_STATUS_MAP.get(suggested, hyp.status)
        if hyp.status == "human_confirmed" or hyp.rejected_by == "human":
            new_status = hyp.status
        if suggested == "reproduced":
            verdict["suggested_status"] = "evidence_supported"
            verdict.setdefault("notes", [])
            if isinstance(verdict.get("notes"), list):
                verdict["notes"].append(
                    "downgraded from reproduced: code review cannot prove execution; "
                    "use ValidationRun from runtime instrumentation"
                )

        if new_status != hyp.status:
            hyp.status = new_status

        all_db_conflicts = self._db.get_conflicts_for_hypothesis(hyp.id, repo_path)
        all_db_evidence = self._db.get_evidence_for_hypothesis(hyp.id)
        db_open_questions = self._db.list_open_questions(repo_path, status="open")
        hyp.status = _gate_hypothesis_status(hyp, all_db_evidence, all_db_conflicts, db_open_questions)
        if hyp.status == "refuted":
            hyp.rejected_at_commit = self._get_commit(repo_path)
            reason = verdict.get("refutation_reason")
            if reason:
                hyp.rejection_reason = str(reason)
        hyp.verified_with = self._model_name(llm)
        verdict["model"] = hyp.verified_with
        self._db.save_hypothesis(repo_path, hyp)
        self.reconcile(repo_path)

        return verdict

    async def run_prompt(
        self,
        prompt: str,
        repo_path: str = "",
        extra_context: str = "",
        schema: Optional[dict] = None,
        system_override: Optional[str] = None,
        max_iterations: int = 20,
    ) -> Any:
        llm = self._llm
        system = system_override or SYSTEM_PROMPT
        key, token, transcript = self._begin_scope("prompt", repo_path, llm, system)
        status = "interrupted"
        try:
            result = await self._run_prompt_inner(prompt, repo_path, extra_context, schema,
                                                  system, max_iterations, llm, transcript)
            status = "done"
        finally:
            self._end_scope(key, token, transcript, "prompt", repo_path, status)
        return result

    async def _run_prompt_inner(
        self,
        prompt: str,
        repo_path: str,
        extra_context: str,
        schema: Optional[dict],
        system: str,
        max_iterations: int,
        llm,
        transcript,
    ) -> Any:
        commit = self._get_commit(repo_path) if repo_path else ""

        parts = [prompt]
        if repo_path:
            parts.append(f"\nRepository: {repo_path}  (commit: {commit})")
        if extra_context:
            parts.append(f"\nContext: {extra_context}")
        if schema:
            parts.append(
                f"\nWhen done, call finish() with a JSON result matching this schema:\n"
                f"{json.dumps(schema, indent=2)}"
            )

        messages: list[dict] = [{"role": "user", "content": "\n".join(parts)}]
        transcript.bind(messages)
        window = self._window()

        base_tools = [t for t in TOOLS[:-1] if t["function"]["name"] in _PROMPT_TOOL_NAMES]

        mcp_tools: list[dict] = []
        if self._mcp_manager:
            try:
                mcp_tools = await self._mcp_manager.list_all_tools()
            except Exception:
                pass

        finish_tool = {
            "type": "function",
            "function": {
                "name": "finish",
                "description": "Submit your final result.",
                "parameters": {
                    "type": "object",
                    "required": ["result"],
                    "properties": {
                        "result": schema if schema else {"type": "object", "additionalProperties": True},
                    },
                },
            },
        }
        run_tools = base_tools + mcp_tools + [finish_tool]
        advertised_mcp = {
            t.get("function", {}).get("name", "") for t in mcp_tools if isinstance(t, dict)
        }
        result: Any = None

        for _iteration in range(max_iterations):
            content, tool_calls = await self._turn(
                llm, transcript, messages, run_tools, system, window=window
            )

            assistant_msg: dict = {"role": "assistant"}
            if content:
                assistant_msg["content"] = content
            if tool_calls:
                assistant_msg["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ]
            messages.append(assistant_msg)

            if not tool_calls:
                if content:
                    try:
                        start = content.find("{")
                        end = content.rfind("}") + 1
                        if start >= 0 and end > start:
                            result = json.loads(content[start:end])
                        else:
                            import logging as _logging
                            _logging.getLogger(__name__).warning(
                                "run_prompt: model returned non-JSON text (len=%d); result will be empty dict",
                                len(content),
                            )
                    except Exception:
                        import logging as _logging
                        _logging.getLogger(__name__).warning(
                            "run_prompt: model response not parseable as JSON (len=%d); result will be empty dict",
                            len(content),
                        )
                break

            finish_args = None
            tool_results: list[dict] = []

            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}

                if name == "finish":
                    finish_args = args.get("result", args)
                    result_text = "Result recorded."
                elif name.startswith("mcp__") and self._mcp_manager:
                    name_parts = name.split("__", 2)
                    if name not in advertised_mcp:
                        result_text = f"Tool {name} is not available in this session."
                    elif len(name_parts) != 3:
                        result_text = f"Malformed MCP tool name (expected mcp__server__tool): {name}"
                    else:
                        _, mcp_name, tool_name = name_parts
                        if "__" in mcp_name:
                            result_text = (f"Ambiguous MCP server name contains '__': {mcp_name} — "
                                           "rename the server in ~/.claude.json")
                        else:
                            result_text = await self._mcp_manager.call_tool(mcp_name, tool_name, args)
                elif name in _PROMPT_TOOL_NAMES:
                    result_text = await self._execute_tool(name, args, repo_path or ".")
                else:
                    result_text = f"Tool {name} is not available in this session."

                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })

            messages.extend(tool_results)

            if finish_args is not None:
                result = finish_args
                break

        return result

    def submit_workflow_finding(
        self,
        repo_path: str,
        h_data: dict,
        evidence_data: Optional[list[dict]] = None,
    ) -> str:
        """Route a workflow-originated finding through the same FP machine as skill findings.

        Applies quality caps, minimum obligations, gate, and persists to DB.
        Returns the (possibly merged) hypothesis id.
        """
        commit = self._get_commit(repo_path) or self._db.get_commit(repo_path) or ""
        h_data, demotion = _prepare_model_hypothesis(h_data, commit)
        h_data["model"] = self._model_name(self._llm)
        h, error = _validate_model_hypothesis(h_data)
        if h is None:
            raise ValueError(f"invalid workflow finding: {error}")
        _apply_model_demotion(h, demotion, commit)
        evidence: list[Evidence] = []
        for e_raw in evidence_data or []:
            e_raw = dict(e_raw)
            e_raw.pop("id", None)
            e_raw.pop("stale", None)
            e_raw = _prepare_model_evidence(e_raw)
            e_raw["hypothesis_id"] = h.id
            e_raw["commit"] = commit
            evidence.append(Evidence.model_validate(e_raw))
        evidence, ev_conflicts = self._verify_evidence_items(repo_path, evidence)
        for e in evidence:
            if e.analysis_quality.method == "semantic":
                e.analysis_quality.method = "structural"
                e.analysis_quality.limitations.append(
                    "method capped to structural: tool-call history unavailable "
                    "for workflow submissions"
                )
        all_open_questions = self._db.list_open_questions(repo_path, "open")
        _apply_quality_caps(h, evidence)
        _inject_minimum_obligations(h)
        _apply_profile(h, evidence, self._profile(repo_path), commit=commit)
        db_conflicts = self._db.get_conflicts_for_hypothesis(h.id, repo_path)
        all_conflicts = db_conflicts + ev_conflicts
        h.status = _gate_hypothesis_status(h, evidence, all_conflicts, all_open_questions)
        h.priority = h.compute_priority()
        self._db.save_hypothesis(repo_path, h)
        for e in evidence:
            e.hypothesis_id = h.id
            self._db.save_evidence(repo_path, e)
        for c in ev_conflicts:
            self._db.save_conflict(repo_path, c)
        return h.id

    async def close(self) -> None:
        for client in self._tier_clients.values():
            try:
                await client.aclose()
            except Exception:
                pass
        for model, u in self.meter.for_scope("").items():
            try:
                self._db.save_usage(self.run_id, "", "chat", model, u)
            except Exception:
                pass
        await self._mcp.close()
        if self._mcp_manager:
            await self._mcp_manager.close()
