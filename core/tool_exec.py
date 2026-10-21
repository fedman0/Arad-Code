from __future__ import annotations
import asyncio
import json
import subprocess
from pathlib import Path
from typing import Optional
from .models import (
    FunctionSummary, OpenQuestion, ConflictRecord, AnalysisQuality, ReturnValueContract,
)
from .code_analysis import run_semgrep, list_dir, run_shell
from .tool_specs import _THREADED_TOOLS
from .evidence_gate import (
    _gate_hypothesis_status, _apply_quality_caps, _inject_minimum_obligations,
    _READ_FILE_MAX_LINES, _READ_HEAD_LINES, _READ_FROM_LINES,
)
from .intake import _EXPOSURE_VALUES

_GRAPH_TOOLS = frozenset({
    "search_graph", "trace_path", "get_code_snippet", "search_code", "get_architecture",
})

_NO_GRAPH = (
    "{name} is unavailable: the code graph has no index for this repository "
    "(run `init <repo>` before scanning to build it). Use list_dir, read_file, "
    "parse_file_structure, find_all_usages and grep instead."
)


class ToolExecutor:
    async def _project_for(self, repo_path: str) -> Optional[str]:
        if repo_path not in self._project_cache:
            self._project_cache[repo_path] = await self._mcp.find_project_for_repo(repo_path)
        return self._project_cache[repo_path]

    def _resolve_path(self, repo_path: str, rel: str) -> Optional[Path]:
        repo = Path(repo_path).resolve()
        try:
            full = (repo / rel).resolve()
            full.relative_to(repo)
            return full
        except (ValueError, OSError):
            return None

    def _read_file(self, repo_path: str, file_path: str,
                   start_line: Optional[int] = None, end_line: Optional[int] = None) -> str:
        target = self._resolve_path(repo_path, file_path)
        if target is None:
            return "Access denied: path outside repository"
        if not target.exists():
            return f"File not found: {file_path}"
        try:
            start_line = int(start_line) if start_line is not None else None
            end_line = int(end_line) if end_line is not None else None
        except (TypeError, ValueError):
            return "start_line and end_line must be integers"
        try:
            all_lines = target.read_text(errors="replace").splitlines()
            total = len(all_lines)
            if start_line is None and end_line is not None:
                start_line = 1
            if start_line is not None:
                s = max(0, start_line - 1)
                e = end_line if end_line is not None else s + _READ_FROM_LINES
                if s >= total:
                    return f"start_line {start_line} is past the end of the file ({total} lines)"
                if e <= s:
                    return f"Empty range: end_line must be >= start_line (file has {total} lines)"
                e = min(e, s + _READ_FILE_MAX_LINES, total)
            else:
                s, e = 0, min(_READ_HEAD_LINES, total)
            body = "\n".join(f"{s + i + 1:4}: {l}" for i, l in enumerate(all_lines[s:e]))
            if e < total:
                body += f"\n[showing lines {s + 1}-{e} of {total}; use start_line/end_line to read more]"
            return body
        except Exception as ex:
            return f"Error: {ex}"

    def _grep(self, repo_path: str, pattern: str, path: Optional[str] = None,
              file_glob: Optional[str] = None, max_matches: int = 100,
              multiline: bool = False) -> str:
        if path:
            safe = self._resolve_path(repo_path, path)
            if safe is None:
                return "Access denied: path outside repository"
            search_path = str(safe)
        else:
            search_path = repo_path
        try:
            max_matches = max(1, int(max_matches))
        except (TypeError, ValueError):
            max_matches = 100
        try:
            cmd = ["rg", "--line-number", "--no-heading", "--hidden", "-g", "!.git",
                   f"-m{max_matches}"]
            if file_glob:
                cmd.extend(["-g", file_glob])
            if multiline:
                cmd.append("-U")
            cmd.extend(["-e", pattern, "--", search_path])
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                               timeout=20, stdin=subprocess.DEVNULL)
            if r.returncode == 2 and not r.stdout:
                return f"grep error: {r.stderr.strip()[:800]}"
            return r.stdout[:12000] or "No matches"
        except FileNotFoundError:
            try:
                cmd = ["grep", "-rnE", f"-m{max_matches}", "--exclude-dir=.git"]
                if multiline:
                    return "grep error: multiline search requires ripgrep (rg) to be installed"
                if file_glob:
                    cmd.extend(["--include", file_glob])
                cmd.extend(["-e", pattern, "--", search_path])
                r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                   timeout=20, stdin=subprocess.DEVNULL)
                if r.returncode == 2 and not r.stdout:
                    return f"grep error: {r.stderr.strip()[:800]}"
                return r.stdout[:12000] or "No matches"
            except Exception as ex:
                return f"grep error: {ex}"
        except Exception as ex:
            return f"Error: {ex}"

    def _execute_local_tool(self, name: str, args: dict, repo_path: str) -> str:
        if name == "read_file":
            return self._read_file(repo_path, args["file_path"],
                                   args.get("start_line"), args.get("end_line"))
        if name == "grep":
            return self._grep(repo_path, args["pattern"], args.get("path"),
                              args.get("file_glob"), args.get("max_matches", 100),
                              bool(args.get("multiline", False)))
        if name == "list_dir":
            return list_dir(repo_path, args.get("path", ""), args.get("max_entries", 80))
        if name == "parse_file_structure":
            from .language_adapter import get_adapter_for
            file_path = args["file_path"]
            adapter = get_adapter_for(file_path)
            result = adapter.enumerate_symbols(repo_path, file_path)
            out: dict = {"file": file_path, "symbols": result.items}
            if result.quality.limitations or result.quality.method != "structural":
                out["analysis_quality"] = result.quality.model_dump()
            if result.error:
                out["error"] = result.error
            return json.dumps(out, indent=2)
        if name == "find_all_usages":
            from .language_adapter import get_default_adapter
            symbol_name = args["symbol_name"]
            max_m = args.get("max_matches", 100)
            adapter = get_default_adapter()
            result = adapter.find_references(repo_path, symbol_name, args.get("file_glob"), max_m)
            if not result.items:
                return "No usages found"
            quality_note = ""
            if result.quality.limitations:
                quality_note = (
                    f"\n[quality: method={result.quality.method}, "
                    f"confidence={result.quality.confidence}, "
                    f"limitations={result.quality.limitations}]"
                )
            if result.truncated:
                quality_note += "\n[results truncated at adapter level]"
            return "\n".join(result.items[:max_m]) + quality_note
        if name == "run_semgrep":
            return run_semgrep(repo_path, args.get("pattern", ""),
                               args.get("language"), args.get("rules"))
        if name == "shell":
            return run_shell(repo_path, args["command"])
        return "Unknown tool"

    async def _execute_tool(self, name: str, args: dict, repo_path: str, skill_name: str = "") -> str:
        try:
            return await self._execute_tool_inner(name, args, repo_path, skill_name)
        except Exception as ex:
            return f"Tool error ({name}): {ex}"

    async def _execute_tool_inner(self, name: str, args: dict, repo_path: str, skill_name: str = "") -> str:
        project = None
        if name in _GRAPH_TOOLS:
            project = await self._project_for(repo_path)
            if project is None:
                return _NO_GRAPH.format(name=name)
        if name == "search_graph":
            filtered = {k: v for k, v in args.items()
                        if k in ("name_pattern", "label", "qn_pattern", "limit")}
            filtered["project"] = project
            r = await self._mcp.search_graph(**filtered)
            return r or "No results in the code graph for this query"
        if name == "trace_path":
            filtered = {k: v for k, v in args.items()
                        if k in ("function_name", "mode", "depth", "direction")}
            if filtered.get("mode") == "called_by":
                filtered["mode"] = "calls"
                filtered.setdefault("direction", "inbound")
            filtered["project"] = project
            r = await self._mcp.trace_path(**filtered)
            return r or "No results"
        if name == "get_code_snippet":
            r = await self._mcp.get_code_snippet(args["qualified_name"], project=project)
            return r or "Symbol not found in graph index — try read_file instead"
        if name == "search_code":
            r = await self._mcp.search_code(args["pattern"], args.get("limit", 50), project=project,
                                            regex=bool(args.get("regex", False)))
            return r or "No results"
        if name == "get_architecture":
            r = await self._mcp.get_architecture(args.get("aspects"), project=project)
            return r or "No architecture data available"
        if name in _THREADED_TOOLS:
            return await asyncio.to_thread(self._execute_local_tool, name, args, repo_path)
        if name == "save_threat_model":
            content = args.get("content", "")
            if len(content) < 400:
                return (
                    "Threat model too short — minimum 400 chars. "
                    "Include ## Overview, ## Trust Boundaries, ## Attack Surface, ## Severity Calibration."
                )
            self._db.save_threat_model(repo_path, content, skill_name)
            return "Threat model saved and will be visible to all subsequent skills."
        if name == "amend_threat_model":
            addendum = args.get("addendum", "")
            if not addendum.strip():
                return "Addendum cannot be empty."
            ok = self._db.amend_threat_model(repo_path, addendum, skill_name)
            return "Amendment recorded." if ok else "No threat model exists yet — call save_threat_model first."
        if name == "save_function_summary":
            qn = args.get("qualified_name", "")
            fp = args.get("file_path", "")
            line = args.get("line", 0)
            if not qn or not fp:
                return "qualified_name and file_path are required."
            method = args.get("quality_method", "textual")
            quality = AnalysisQuality(
                method=method,
                confidence="medium" if method != "textual" else "low",
            )
            fs = FunctionSummary(
                qualified_name=qn,
                file_path=fp,
                line=line,
                created_by_skill=skill_name,
                commit=self._get_commit(repo_path),
                inputs=args.get("inputs", []),
                reads=args.get("reads", []),
                writes=args.get("writes", []),
                external_effects=args.get("external_effects", []),
                guards=args.get("guards", []),
                transformations=args.get("transformations", []),
                failure_behavior=args.get("failure_behavior", ""),
                preconditions=args.get("preconditions", []),
                guarantees=args.get("guarantees", []),
                required_authority=args.get("required_authority", []),
                unresolved_calls=args.get("unresolved_calls", []),
                quality=quality,
            )
            self._db.save_function_summary(repo_path, fs)
            return f"Function summary saved for {qn}."
        if name == "get_function_summary":
            qn = args.get("qualified_name", "")
            if not qn:
                return "qualified_name is required."
            fs = self._db.get_function_summary(repo_path, qn, current_commit=self._get_commit(repo_path))
            if fs is None:
                return f"No summary found for {qn}."
            return fs.model_dump_json(indent=2)
        if name == "log_open_question":
            question = args.get("question", "").strip()
            if not question:
                return "question cannot be empty."
            impact = args.get("impact", "informational")
            oq = OpenQuestion(
                question=question,
                raised_by_skill=skill_name,
                impact=impact,
                affects_hypothesis_ids=args.get("affects_hypothesis_ids", []),
                resolution_hint=args.get("resolution_hint"),
            )
            self._db.save_open_question(repo_path, oq)
            return f"Open question recorded (id={oq.id}, impact={impact})."
        if name == "flag_conflict":
            kind = args.get("kind", "")
            desc = args.get("description", "").strip()
            if not kind or not desc:
                return "kind and description are required."
            cf = ConflictRecord(
                kind=kind,
                description=desc,
                left=args.get("left", ""),
                right=args.get("right", ""),
                severity=args.get("severity", "degrades_confidence"),
            )
            self._db.save_conflict(repo_path, cf)
            return f"Conflict recorded (id={cf.id}, kind={kind}, severity={cf.severity})."
        if name == "get_open_questions":
            questions = self._db.list_open_questions(repo_path, status="open")
            if not questions:
                return "No open questions from prior skills."
            lines = []
            for q in questions[:20]:
                affects = f" affects={','.join(q.affects_hypothesis_ids)}" if q.affects_hypothesis_ids else ""
                lines.append(f"[{q.id}] impact={q.impact} skill={q.raised_by_skill}{affects}\n  {q.question}")
                if q.resolution_hint:
                    lines.append(f"  hint: {q.resolution_hint}")
            return "\n".join(lines)
        if name == "record_return_contract":
            fn_qn = args.get("function_qualified_name", "")
            fp = args.get("file_path", "")
            if not fn_qn or not fp:
                return "function_qualified_name and file_path are required."
            rc = ReturnValueContract(
                function_qualified_name=fn_qn,
                file_path=fp,
                line=args.get("line", 0),
                return_type=args.get("return_type", ""),
                security_relevance=args.get("security_relevance", "high"),
                expected_handling=args.get("expected_handling", "must_check"),
                consequence_if_ignored=args.get("consequence_if_ignored", ""),
                created_by_skill=skill_name,
            )
            self._db.save_return_contract(repo_path, rc)
            return f"Return contract recorded (id={rc.id}, function={fn_qn}, handling={rc.expected_handling})."
        if name == "list_hypotheses":
            rows = self._db.list_hypotheses(repo_path)
            if args.get("status"):
                rows = [h for h in rows if h.status == args["status"]]
            if args.get("min_priority") is not None:
                rows = [h for h in rows if h.priority >= int(args["min_priority"])]
            total_count = len(rows)
            limit = int(args.get("limit") or 40)
            rows = rows[:limit]
            if not rows:
                return "No hypotheses match."
            out = []
            for h in rows:
                out.append(
                    f"[{h.id}] sev={h.severity} conf={h.confidence} prio={h.priority} "
                    f"status={h.status} exposure={h.exposure}\n"
                    f"   entry: {h.entry_point}\n"
                    f"   invariant: {h.violated_invariant}\n"
                    f"   impact: {h.observable_impact}"
                )
            if len(rows) < total_count:
                out.append(f"[showing {len(rows)}/{total_count} — use limit/status/min_priority to filter]")
            return "\n".join(out)
        if name == "get_hypothesis":
            h = self._db.get_hypothesis(repo_path, args.get("hypothesis_id", ""))
            if h is None:
                return f"No hypothesis {args.get('hypothesis_id')!r} in this repository."
            ev = self._db.get_evidence_for_hypothesis(h.id)
            parts = [
                f"[{h.id}] status={h.status} sev={h.severity} conf={h.confidence} "
                f"prio={h.priority} exposure={h.exposure} cwe={h.cwe or '-'}",
                f"actor: {h.actor}",
                f"capability: {h.capability}",
                f"entry_point: {h.entry_point}",
                f"violated_invariant: {h.violated_invariant}",
                f"observable_impact: {h.observable_impact}",
                f"reachability={h.reachability} input_control={h.input_control} "
                f"guard_coverage={h.guard_coverage}",
            ]
            if h.preconditions:
                parts.append("preconditions:\n" + "\n".join(f"  {p}" for p in h.preconditions))
            if h.execution_path:
                parts.append("execution_path:\n" + "\n".join(f"  {s}" for s in h.execution_path))
            if h.counterevidence:
                parts.append("counterevidence:\n" + "\n".join(f"  {c}" for c in h.counterevidence))
            if h.proof_obligations:
                parts.append("proof_obligations:\n" + "\n".join(
                    f"  [{ob.status}/{ob.claim_type}] {ob.question}" for ob in h.proof_obligations))
            if ev:
                parts.append("evidence:\n" + "\n".join(
                    f"  {e.file_path}:{e.line_start}-{e.line_end} "
                    f"({e.analysis_quality.method}) {e.description}" for e in ev))
            if h.composed_of:
                parts.append(f"composed_of: {', '.join(h.composed_of)}")
            if h.enables:
                parts.append(f"enables: {', '.join(h.enables)}")
            return "\n".join(parts)
        if name == "resolve_open_question":
            qid = args.get("question_id", "")
            resolution = args.get("resolution", "")
            if not qid or not resolution:
                return "question_id and resolution are both required."
            q_obj = next((q for q in self._db.list_open_questions(repo_path, "open")
                          if q.id == qid), None)
            ok = self._db.resolve_open_question(repo_path, qid, resolution, skill_name)
            if ok and q_obj:
                all_open_questions = self._db.list_open_questions(repo_path, "open")
                for h_id in q_obj.affects_hypothesis_ids:
                    h = self._db.get_hypothesis(repo_path, h_id)
                    if h and h.status not in ("rejected", "refuted", "blocked", "human_confirmed"):
                        ev_for_h = self._db.get_evidence_for_hypothesis(h.id)
                        conf_for_h = self._db.get_conflicts_for_hypothesis(h.id, repo_path)
                        _inject_minimum_obligations(h)
                        h.status = _gate_hypothesis_status(h, ev_for_h, conf_for_h, all_open_questions)
                        self._db.save_hypothesis(repo_path, h)
            return (f"Open question {qid} resolved." if ok
                    else f"No open question {qid!r} in this repository.")
        if name == "amend_hypothesis":
            hyp_id = args.get("hypothesis_id", "")
            reason = args.get("reason", "")
            if not hyp_id or not reason:
                return "hypothesis_id and reason are both required."
            h = self._db.get_hypothesis(repo_path, hyp_id)
            if h is None:
                return f"No hypothesis {hyp_id!r} in this repository."
            changes = []
            if args.get("confidence") is not None:
                old = h.confidence
                h.confidence = max(0, min(10, int(args["confidence"])))
                changes.append(f"confidence {old}->{h.confidence}")
            if args.get("exposure"):
                if args["exposure"] not in _EXPOSURE_VALUES:
                    return (f"Invalid exposure {args['exposure']!r}; use one of: "
                            f"{', '.join(sorted(_EXPOSURE_VALUES))}.")
                old = h.exposure
                h.exposure = args["exposure"]
                changes.append(f"exposure {old}->{h.exposure}")
            for target in args.get("enables") or []:
                if target not in h.enables:
                    if self._db.get_hypothesis(repo_path, target) is None:
                        return f"Cannot enable {target!r}: no such hypothesis in this repository."
                    h.enables.append(target)
                    changes.append(f"enables+={target}")
            if not changes:
                return "Nothing to amend."
            h.uncertainty.append(f"amended by {skill_name}: {reason}")
            ev_for_h = self._db.get_evidence_for_hypothesis(h.id)
            _apply_quality_caps(h, ev_for_h)
            _inject_minimum_obligations(h)
            conf_for_h = self._db.get_conflicts_for_hypothesis(h.id, repo_path)
            all_open_questions = self._db.list_open_questions(repo_path, "open")
            h.status = _gate_hypothesis_status(h, ev_for_h, conf_for_h, all_open_questions)
            h.priority = h.compute_priority()
            self._db.save_hypothesis(repo_path, h)
            return f"Amended {hyp_id}: {', '.join(changes)}."
        if name == "flag_ignored_return":
            fn_qn = args.get("function_qualified_name", "")
            caller = args.get("caller_location", "")
            if not fn_qn or not caller:
                return "function_qualified_name and caller_location are required."
            rc = self._db.get_return_contract(repo_path, fn_qn)
            if rc is None:
                return f"No return contract for {fn_qn}. Call record_return_contract first."
            rc.ignored_at.append(caller)
            self._db.save_return_contract(repo_path, rc)
            if rc.expected_handling == "must_check":
                cf = ConflictRecord(
                    kind="capability_mismatch",
                    description=(
                        f"Return value of {fn_qn} ignored at {caller}. "
                        f"Contract: must_check. Consequence: {rc.consequence_if_ignored}"
                    ),
                    left=fn_qn,
                    right=caller,
                    severity="degrades_confidence",
                )
                self._db.save_conflict(repo_path, cf)
                return f"Flagged ignored return at {caller} (auto_conflict={cf.id}, severity=degrades_confidence)."
            return f"Flagged ignored return at {caller} (handling={rc.expected_handling}, no auto-conflict)."
        if name == "get_return_contracts":
            contracts = self._db.list_return_contracts(repo_path)
            if not contracts:
                return "No return value contracts recorded yet."
            lines = []
            for c in contracts[:20]:
                lines.append(
                    f"[{c.id}] {c.function_qualified_name} returns {c.return_type} "
                    f"handling={c.expected_handling} relevance={c.security_relevance}"
                )
                if c.ignored_at:
                    lines.append(f"  ignored_at: {', '.join(c.ignored_at[:5])}")
            return "\n".join(lines)
        if name == "reject_hypothesis":
            hyp_id = args.get("hypothesis_id", "")
            reason = args.get("reason", "")
            if not hyp_id or not reason:
                return "hypothesis_id and reason are required."
            condition = args.get("rejection_condition") or ""
            controlling_ids = args.get("rejection_controlling_evidence_ids") or []
            h = self._db.get_hypothesis(repo_path, str(hyp_id))
            if h is None:
                return f"Hypothesis {hyp_id} not found."
            if h.status == "human_confirmed" or h.rejected_by == "human":
                return (f"Hypothesis {hyp_id} carries a human triage decision "
                        f"({h.status}); it was not changed.")
            h.status = "rejected"
            h.rejected_by = "model"
            h.rejected_at_commit = self._get_commit(repo_path)
            h.rejection_reason = str(reason)
            h.rejection_condition = str(condition)
            h.rejection_controlling_evidence_ids = (
                [str(x) for x in controlling_ids] if isinstance(controlling_ids, list) else []
            )
            self._db.save_hypothesis(repo_path, h)
            return f"Hypothesis {hyp_id} rejected. Reason and condition recorded."
        return "Unknown tool"
