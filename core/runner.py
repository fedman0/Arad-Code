from __future__ import annotations
import json
import re
import subprocess
from typing import Any, Optional
from .config import Config
from .llm import LLMClient
from .db import EvidenceStore
from .memory_mcp import CodebaseMemoryClient
from .models import (
    Hypothesis, Evidence, CoverageItem, EntryPoint, Guard, SkillResult, FunctionSummary,
    OpenQuestion, ConflictRecord, ReturnValueContract, NegativeEvidence,
)
from .profile import ProjectProfile, load_profile
from .cache import clear_run_state, completed_skills, mark_skill_done
from .prompts import (
    SYSTEM_PROMPT, HUNT_SYSTEM_PROMPT, _NE_INSTRUCTION, HUNT_OUTPUT_CONTRACT, OUTPUT_CONTRACT,
)
from .tool_specs import TOOLS, _PROMPT_TOOL_NAMES
from .evidence_gate import (
    _synthesize_evidence_from_tools, _gate_hypothesis_status, _build_tool_call_index,
    _cap_method_per_evidence, _apply_quality_caps, _inject_minimum_obligations, _apply_profile,
)
from .intake import (
    _as_list, _without_id, _prepare_model_hypothesis, _validate_model_hypothesis,
    _apply_model_demotion,
)
from .tool_exec import ToolExecutor
from .reconcile import EvidenceReconciler
from .skills import MAINTENANCE_PHASE, SkillCatalog


class SkillRunner(ToolExecutor, EvidenceReconciler):
    def __init__(self, cfg: Config, db: EvidenceStore, mcp: CodebaseMemoryClient,
                 mcp_manager=None):
        self._cfg = cfg
        self._llm = LLMClient(cfg)
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

    def _build_initial_context(self, repo_path: str) -> str:
        parts: list[str] = []
        profile_text = self._profile(repo_path).to_prompt()
        if profile_text:
            parts.append(profile_text)
        threat_model = self._db.get_threat_model(repo_path)
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
            hs = [f"  [{h.id}] {h.violated_invariant} (status={h.status})" for h in hypotheses[:10]]
            parts.append("Existing hypotheses (avoid duplicates):\n" + "\n".join(hs))

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

    async def run_skill(
        self,
        skill_name: str,
        repo_path: str,
        extra_context: str = "",
        max_iterations: int = 30,
        verbose: bool = False,
        negative_evidence: bool = False,
    ) -> SkillResult:
        skill_text = self._load_skill(skill_name)
        commit = self._get_commit(repo_path)
        known_context = self._build_initial_context(repo_path)
        phase = self._get_skill_phase(skill_name)
        _ne_eligible = negative_evidence and phase in ("p3", "p4", "")

        if repo_path not in self._project_cache:
            self._project_cache[repo_path] = await self._mcp.find_project_for_repo(repo_path)
        project_name = self._project_cache.get(repo_path)
        mcp_hint = (
            f"\n# Codebase Graph Index\nProject name: `{project_name}`\n"
            "Pass this as the `project` argument to get_architecture(), search_graph(), "
            "trace_path(), get_code_snippet(), and search_code()."
            if project_name else ""
        )

        is_hunt = skill_name.startswith("hunt-")
        active_system_prompt = HUNT_SYSTEM_PROMPT if is_hunt else SYSTEM_PROMPT
        _active_contract = HUNT_OUTPUT_CONTRACT if is_hunt else OUTPUT_CONTRACT
        start_instruction = (
            f"Repository: {repo_path}  (commit: {commit})\n\n"
            f"Project name for all graph tools: `{project_name or '<project>'}`\n\n"
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
            f"Start by calling get_architecture(project=\"{project_name or '<project>'}\") to orient yourself, then use the other tools to read real code and build evidence. Call finish() when done."
        )
        initial_msg = start_instruction

        messages: list[dict] = [{"role": "user", "content": initial_msg}]
        findings: Optional[dict] = None

        finish_tool = next(t for t in TOOLS if t["function"]["name"] == "finish")
        nudge_at = max_iterations - 6
        for iteration in range(max_iterations):
            forced = iteration >= nudge_at
            if forced and iteration == nudge_at:
                messages.append({
                    "role": "user",
                    "content": (
                        "You have used enough iterations. Call finish() RIGHT NOW with all findings "
                        "you have gathered so far. Include every hypothesis with its evidence. "
                        "Do not call any other tool — only finish()."
                    ),
                })
            tools_to_use = [finish_tool] if forced else TOOLS
            content, tool_calls = await self._llm.complete_with_tools(
                messages, tools_to_use, system=active_system_prompt,
                tool_choice={"type": "function", "function": {"name": "finish"}} if forced else None,
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
                messages.append({
                    "role": "user",
                    "content": (
                        "Continue the skill: call a tool to keep investigating, "
                        "or call finish() with your structured findings."
                    ),
                })
                continue

            finish_args: Optional[dict] = None
            tool_results: list[dict] = []

            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}

                if name == "finish":
                    raw_findings = args.get("findings", args)
                    if isinstance(raw_findings, str):
                        try:
                            raw_findings = json.loads(raw_findings)
                        except (json.JSONDecodeError, TypeError):
                            raw_findings = {"hypotheses": [], "coverage": [],
                                            "open_questions": [f"finish() called with non-JSON string"]}
                    finish_args = raw_findings if isinstance(raw_findings, dict) else {"hypotheses": [], "coverage": [], "open_questions": []}
                    result_text = "Findings recorded."
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

            # tool_choice="finish" is forced once iteration >= nudge_at (set above)

        if findings is None or not isinstance(findings, dict):
            findings = {"hypotheses": [], "coverage": [], "open_questions": [
                f"skill {skill_name} did not produce structured output after {max_iterations} iterations"
            ]}

        validation_errors: list[str] = []
        hypotheses = []
        hypothesis_by_index: dict[int, Hypothesis] = {}
        raw_hypotheses = _as_list(findings.get("hypotheses"))
        for raw_idx, h_data in enumerate(raw_hypotheses):
            if not isinstance(h_data, dict):
                validation_errors.append(f"hypothesis[{raw_idx}] is not an object")
                continue
            h_data, demotion = _prepare_model_hypothesis(h_data, commit)
            h_data["skill_source"] = skill_name
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
                e_data["hypothesis_id"] = hypothesis_by_index[hyp_idx].id
                e_data["commit"] = commit
                evidence_items.append(Evidence.model_validate(e_data))
            except Exception as ex:
                validation_errors.append(f"evidence[{i}] invalid: {ex}")

        evidence_items, ev_conflicts = self._verify_evidence_items(repo_path, evidence_items)
        auto_conflicts.extend(ev_conflicts)

        tool_index = _build_tool_call_index(messages)
        run_tools = frozenset(name for name, _ in tool_index)
        for ev in evidence_items:
            capped = _cap_method_per_evidence(
                ev.analysis_quality.method, ev.file_path, ev.description,
                tool_index, run_tools,
            )
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
        return result

    async def _run_skill_list(self, skills: list[str], repo_path: str,
                              verbose: bool, resume: bool,
                              on_progress=None,
                              negative_evidence: bool = False,
                              conditional: frozenset = frozenset()) -> list[SkillResult]:
        """Run skills, recording each completion so an interrupted scan can resume.

        A scan is many minutes of paid LLM calls; losing all of it to one Ctrl+C
        is the difference between a tool you can stop and one you must babysit.
        """
        commit = self._get_commit(repo_path)
        done = completed_skills(repo_path, commit) if resume else set()
        if not resume:
            # only drop progress for the skills this invocation will redo;
            # `--phase p4` used to wipe a completed full run's record
            keep = {s for s in completed_skills(repo_path, commit) if s not in skills}
            clear_run_state(repo_path)
            for name in keep:
                mark_skill_done(repo_path, commit, name)

        results: list[SkillResult] = []
        reported_skips: set[str] = set()
        for name in skills:
            if name in done:
                if on_progress and name not in reported_skips:
                    on_progress(name, "skipped", None)
                reported_skips.add(name)
                continue
            if name in conditional and not self._has_blocking_questions(repo_path):
                mark_skill_done(repo_path, commit, name)
                continue
            if on_progress:
                on_progress(name, "started", None)
            try:
                result = await self.run_skill(name, repo_path, verbose=verbose,
                                             negative_evidence=negative_evidence)
            except BaseException:
                if on_progress:
                    on_progress(name, "interrupted", None)
                raise
            results.append(result)
            mark_skill_done(repo_path, commit, name)
            if on_progress:
                on_progress(name, "done", result)
        return results

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
                        negative_evidence: bool = False) -> list[SkillResult]:
        results = await self._run_skill_list(
            self._phase_skills(phase), repo_path, verbose, resume, on_progress,
            negative_evidence=negative_evidence)
        self.reconcile(repo_path)
        return results

    async def run_all(self, repo_path: str, verbose: bool = False,
                      resume: bool = False, on_progress=None,
                      negative_evidence: bool = False) -> list[SkillResult]:
        results = await self._run_skill_list(
            self._all_skills(), repo_path, verbose, resume, on_progress,
            negative_evidence=negative_evidence,
            conditional=self._maintenance_skills())
        self.reconcile(repo_path)
        return results

    async def verify_hypothesis(self, hyp_id: str, repo_path: str,
                                 verbose: bool = False) -> dict:
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
        verdict: dict = {}

        for iteration in range(25):
            content, tool_calls = await self._llm.complete_with_tools(
                messages, VERIFY_TOOLS, system=SYSTEM_PROMPT
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
        system = system_override or SYSTEM_PROMPT
        result: Any = None

        for _iteration in range(max_iterations):
            content, tool_calls = await self._llm.complete_with_tools(
                messages, run_tools, system=system
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
        h, error = _validate_model_hypothesis(h_data)
        if h is None:
            raise ValueError(f"invalid workflow finding: {error}")
        _apply_model_demotion(h, demotion, commit)
        evidence: list[Evidence] = []
        for e_raw in evidence_data or []:
            e_raw = dict(e_raw)
            e_raw.pop("id", None)
            e_raw.pop("stale", None)
            e_raw.pop("hypothesis_index", None)
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
        await self._mcp.close()
        if self._mcp_manager:
            await self._mcp_manager.close()
