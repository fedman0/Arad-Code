from __future__ import annotations
import asyncio
import json
import re
import subprocess
from pathlib import Path
from typing import Optional
from .models import (
    FunctionSummary, OpenQuestion, ConflictRecord, AnalysisQuality, ReturnValueContract,
)
from .code_analysis import run_semgrep, list_dir, run_shell, _relative_lines
from .tool_specs import _THREADED_TOOLS
from .evidence_gate import (
    _gate_hypothesis_status, _apply_quality_caps, _inject_minimum_obligations,
    _READ_FILE_MAX_LINES, _READ_HEAD_LINES, _READ_FROM_LINES,
)
from .intake import _EXPOSURE_VALUES

_GRAPH_TOOLS = frozenset({
    "search_graph", "trace_path", "get_code_snippet", "search_code", "get_architecture",
    "query_graph",
})

_SEARCH_GRAPH_ARGS = ("name_pattern", "label", "qn_pattern", "limit", "query", "semantic_query",
                      "file_pattern", "relationship", "include_connected", "offset")
_TRACE_PATH_ARGS = ("function_name", "mode", "depth", "direction", "parameter_name",
                    "risk_labels", "limit", "cursor")
_SNIPPET_ARGS = ("include_neighbors", "source_mode", "start_line", "max_lines", "member_offset")
_TRACE_MODES = frozenset({"calls", "data_flow", "cross_service"})
_GRAPH_WRITE = re.compile(
    r"(?<![\w.$])(create|merge|delete|detach|set|remove|drop|load\s+csv|call|foreach)(?![\w$])", re.I)
_CYPHER_NOISE = re.compile(
    r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`[^`]*`|//[^\n]*|/\*.*?\*/", re.S)
_TEXT_JOIN = {"query": " ", "name_pattern": "|", "qn_pattern": "|"}
_TEXT_ARGS = ("name_pattern", "label", "qn_pattern", "query", "file_pattern", "relationship")
_LIST_HYPOTHESES_MAX = 60


def _one_line(text: Optional[str], limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _writes_graph(query: str) -> bool:
    return bool(_GRAPH_WRITE.search(_CYPHER_NOISE.sub(" ", query or "")))


def _text_arg(key: str, value) -> str:
    if isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value
                 if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip()]
        joiner = _TEXT_JOIN.get(key)
        return joiner.join(items) if joiner else (items[0] if items else "")
    return value.strip() if isinstance(value, str) else ""


def _clamp(value, low: int, high: int, default: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def _search_graph_args(args: dict) -> dict:
    out = {k: v for k, v in args.items() if k in _SEARCH_GRAPH_ARGS}
    for key in _TEXT_ARGS:
        if key in out:
            text = _text_arg(key, out[key])
            if text:
                out[key] = text
            else:
                out.pop(key)
    sq = out.get("semantic_query")
    if isinstance(sq, str):
        sq = [sq]
    if isinstance(sq, list):
        sq = [s.strip() for s in sq if isinstance(s, str) and s.strip()][:5]
    if sq and not out.get("query"):
        out["semantic_query"] = sq
    else:
        out.pop("semantic_query", None)
    if "limit" in out:
        out["limit"] = _clamp(out["limit"], 1, 200, 20)
    if "offset" in out:
        out["offset"] = _clamp(out["offset"], 0, 100000, 0)
    return out


def _trace_path_args(args: dict) -> dict:
    out = {k: v for k, v in args.items() if k in _TRACE_PATH_ARGS}
    if out.get("mode") == "called_by":
        out["mode"] = "calls"
        out.setdefault("direction", "inbound")
    if out.get("mode") is not None and out["mode"] not in _TRACE_MODES:
        out["mode"] = "calls"
    if "depth" in out:
        out["depth"] = _clamp(out["depth"], 1, 10, 3)
    if "limit" in out:
        out["limit"] = _clamp(out["limit"], 1, 500, 100)
    if not isinstance(out.get("cursor"), str) or not out["cursor"].strip():
        out.pop("cursor", None)
    out.setdefault("depth", 3)
    return out


def _snippet_args(args: dict) -> dict:
    out = {k: v for k, v in args.items() if k in _SNIPPET_ARGS}
    if "max_lines" in out:
        out["max_lines"] = _clamp(out["max_lines"], 1, 500, 200)
    if "start_line" in out:
        out["start_line"] = _clamp(out["start_line"], 1, 10_000_000, 1)
    if out.get("source_mode") not in (None, "auto", "full", "outline"):
        out.pop("source_mode")
    if "member_offset" in out:
        out["member_offset"] = _clamp(out["member_offset"], 0, 1_000_000, 0)
    return out


def _query_graph_page(args: dict) -> dict:
    out: dict = {}
    if isinstance(args.get("cursor"), str) and args["cursor"].strip():
        out["cursor"] = args["cursor"].strip()
    elif args.get("offset") is not None:
        out["offset"] = _clamp(args["offset"], 0, 10_000_000, 0)
    return out

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
        repo = Path(repo_path).resolve()
        if path:
            safe = self._resolve_path(repo_path, path)
            if safe is None:
                return "Access denied: path outside repository"
            search_path = safe.relative_to(repo).as_posix() or "."
        else:
            search_path = "."
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
                               timeout=20, stdin=subprocess.DEVNULL, cwd=str(repo))
            if r.returncode == 2 and not r.stdout:
                return f"grep error: {r.stderr.strip()[:800]}"
            return _relative_lines(r.stdout)[:12000] or "No matches"
        except FileNotFoundError:
            try:
                cmd = ["grep", "-rnE", f"-m{max_matches}", "--exclude-dir=.git"]
                if multiline:
                    return "grep error: multiline search requires ripgrep (rg) to be installed"
                if file_glob:
                    cmd.extend(["--include", file_glob])
                cmd.extend(["-e", pattern, "--", search_path])
                r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                   timeout=20, stdin=subprocess.DEVNULL, cwd=str(repo))
                if r.returncode == 2 and not r.stdout:
                    return f"grep error: {r.stderr.strip()[:800]}"
                return _relative_lines(r.stdout)[:12000] or "No matches"
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
            filtered = _search_graph_args(args)
            filtered["project"] = project
            r = await self._mcp.search_graph(**filtered)
            return r or "No results in the code graph for this query"
        if name == "trace_path":
            filtered = _trace_path_args(args)
            filtered["project"] = project
            r = await self._mcp.trace_path(**filtered)
            short = str(filtered.get("function_name") or "").rsplit(".", 1)[-1].strip()
            if r and short and '"function not found"' in r[:300]:
                r += (f"\nThe code graph has no node for {short}. Functions assigned to a const "
                      "(arrow functions), object methods and library calls are often missing "
                      f"from it; find_all_usages(symbol_name=\"{short}\") lists the uses by text.")
            return r or "No results"
        if name == "get_code_snippet":
            r = await self._mcp.get_code_snippet(args["qualified_name"], project=project,
                                                 **_snippet_args(args))
            return r or "Symbol not found in graph index — try read_file instead"
        if name == "query_graph":
            query = str(args.get("query") or "").strip()
            if not query:
                return "query is required: a read-only Cypher MATCH ... RETURN statement."
            if _writes_graph(query):
                return ("query_graph is read-only: use MATCH ... WHERE ... RETURN without "
                        "CREATE, MERGE, SET, DELETE, REMOVE, DROP, LOAD CSV or CALL.")
            r = await self._mcp.query_graph_text(query, project=project,
                                                 max_rows=_clamp(args.get("max_rows"), 1, 500, 100),
                                                 **_query_graph_page(args))
            return r or "No rows"
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
            summary = args.get("summary") if isinstance(args.get("summary"), str) else ""
            self._db.amend_threat_model(repo_path, addendum, skill_name, summary)
            return "Amendment recorded."
        if name == "get_threat_model":
            text = self._db.get_threat_model_section(repo_path, str(args.get("section") or ""))
            if text is None:
                return ("No threat model exists yet. amend_threat_model records a map even so; "
                        "the base sections come from save_threat_model.")
            if not text:
                return (f"No threat model section matches {args.get('section')!r}. Call "
                        "get_threat_model without section to list the amendments.")
            return text
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
            terms = str(args.get("query") or "").lower().split()
            if terms:
                rows = [h for h in rows if all(t in " ".join(
                    (h.id, h.cwe or "", h.entry_point or "", h.violated_invariant or "",
                     h.skill_source or "")).lower() for t in terms)]
            total_count = len(rows)
            offset = max(0, int(args.get("offset") or 0))
            limit = max(1, min(int(args.get("limit") or 40), _LIST_HYPOTHESES_MAX))
            rows = rows[offset:offset + limit]
            if not rows:
                return (f"No hypotheses past offset {offset}; {total_count} match."
                        if total_count else "No hypotheses match.")
            out = [f"[{h.id}] {h.status} sev={h.severity} conf={h.confidence} {h.cwe or '-'} "
                   f"{h.exposure} | {_one_line(h.entry_point, 80)} | "
                   f"{_one_line(h.violated_invariant, 110)} | {_one_line(h.observable_impact, 60)}"
                   for h in rows]
            if offset or offset + len(rows) < total_count:
                out.append(f"[showing {offset + 1}-{offset + len(rows)} of {total_count}; narrow with "
                           "query, status or min_priority, or page with offset; get_hypothesis "
                           "gives the full record]")
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
