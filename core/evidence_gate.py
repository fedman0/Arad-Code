from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Optional
from .models import Hypothesis, Evidence, OpenQuestion, ConflictRecord
from .profile import ProjectProfile


def _synthesize_evidence_from_tools(
    h: "Hypothesis",
    tool_index: "list[tuple[str, dict]]",
    run_tools: "frozenset[str]",
    commit: str = "",
    repo_path: str = "",
) -> "list[Evidence]":
    """Create structural evidence records from tool calls that analysed relevant files.

    Only fires when the model submitted zero evidence for a hypothesis. The goal
    is to credit work the model demonstrably did (it called get_code_snippet or
    trace_path on the right file) even though it forgot to populate the evidence
    array in finish().
    """
    import re as _re
    from pathlib import Path as _P
    from .models import Evidence, AnalysisQuality

    if not (run_tools & (_SEMANTIC_TOOLS | _STRUCTURAL_TOOLS)):
        return []

    ep_raw = _re.sub(r':\d+$', '', h.entry_point or "")
    ep_base = _P(ep_raw).stem.lower()
    if len(ep_base) < 4:
        return []

    # Build set of basenames to look for in tool args
    targets: set[str] = {ep_base}
    for step in (h.execution_path or []):
        m = _re.search(r'([\w./-]+\.[A-Za-z]\w*)', step)
        if m:
            targets.add(_P(m.group(1)).stem.lower())

    best_name: str = ""
    best_args: dict = {}
    best_method = ""

    for name, args in tool_index:
        if name not in (_SEMANTIC_TOOLS | _STRUCTURAL_TOOLS):
            continue
        if name == "query_graph" and not any(t in str(args.get("_result") or "").lower()
                                             for t in targets):
            continue
        for k, v in args.items():
            if k not in _IDENTITY_ARG_KEYS or not isinstance(v, str) or len(v) < 4:
                continue
            v_l = v.lower()
            for tgt in targets:
                if tgt in v_l:
                    method = "semantic" if name in _SEMANTIC_TOOLS else "structural"
                    if not best_method or _METHOD_ORDER.index(method) > _METHOD_ORDER.index(best_method):
                        best_name, best_args, best_method = name, args, method
                    break

    if not best_method:
        return []

    file_match = _re.match(r'^\s*([\w./-]+\.[A-Za-z]\w*)(?::.*)?$', ep_raw)
    file_path = file_match.group(1) if file_match else ""
    if not file_path:
        arg_path = best_args.get("file_path") or best_args.get("path")
        file_path = arg_path if isinstance(arg_path, str) else ""
    if not file_path:
        return []
    if repo_path:
        repo = _P(repo_path).resolve()
        try:
            resolved = (repo / file_path).resolve()
            resolved.relative_to(repo)
        except (ValueError, OSError):
            return []
        if not resolved.is_file():
            return []

    id_args = {k: v for k, v in best_args.items() if k in _IDENTITY_ARG_KEYS and isinstance(v, str)}
    desc = f"auto:{best_name}({', '.join(f'{k}={v[:40]}' for k, v in id_args.items())})"
    return [Evidence(
        hypothesis_id=h.id,
        kind="trace" if best_name in _SEMANTIC_TOOLS else "code",
        description=desc,
        file_path=file_path,
        line_start=0,
        line_end=0,
        snippet="",
        commit=commit,
        analysis_quality=AnalysisQuality(
            method=best_method,
            confidence="low",
            limitations=["auto-synthesized from tool call history; no model-provided evidence"],
        ),
    )]


def _gate_hypothesis_status(
    h: "Hypothesis",
    evidence: "list[Evidence]",
    conflicts: "list[ConflictRecord]",
    open_questions: "list[OpenQuestion] | None" = None,
) -> str:
    """Derive status from the evidence rather than trusting what the model claimed.

    The model never sends `status` (it is not in FINDINGS_SCHEMA), so this must
    be able to promote as well as demote — otherwise every hypothesis stays
    `initial` forever and nothing is ever exported.
    """
    if h.status in ("rejected", "refuted", "blocked", "human_confirmed", "needs_recheck"):
        return h.status

    valid_ev = [e for e in evidence if not e.stale]
    if h.exposure == "unreachable":
        return "initial"
    for c in conflicts:
        if c.severity == "blocks_finding" and c.status == "open":
            return "initial"
    for q in open_questions or []:
        if (q.impact == "blocks_finding" and q.status == "open"
                and h.id in q.affects_hypothesis_ids):
            return "initial"

    strong_methods = {"structural", "semantic"}
    _CONFIG_EXTS = {".yml", ".yaml", ".conf", ".env", ".ini", ".toml", ".cfg",
                    ".properties", ".json", ".xml"}
    _CONFIG_NAMES = {"dockerfile", "supervisord.conf", ".env", ".env.example",
                     ".env_example", "docker-compose.yml", "docker-compose.yaml"}

    def _is_config_file(path: str) -> bool:
        import os
        name = os.path.basename(path).lower()
        if name in _CONFIG_NAMES:
            return True
        _, ext = os.path.splitext(name)
        return ext in _CONFIG_EXTS

    required_obs = [ob for ob in h.proof_obligations if ob.required_for_finding]
    n_verified = sum(1 for ob in required_obs if ob.status == "verified")
    all_required_verified = n_verified == len(required_obs)
    verified_frac = (n_verified / len(required_obs)) if required_obs else 1.0

    has_strong_evidence = any(e.analysis_quality.method in strong_methods for e in valid_ev)
    has_config_evidence = any(_is_config_file(e.file_path) for e in valid_ev)

    # High-confidence partial-obligation override: a finding with confidence>=7
    # (requires structural evidence per _QUALITY_CONF_CAP), >=60% of required
    # obligations verified, and strong evidence may promote despite some unresolved
    # obligations. Those unresolved items remain in proof_obligations for review.
    high_conf_override = (
        has_strong_evidence
        and h.confidence >= 7
        and verified_frac >= 0.6
        and not any(ob.required_for_finding and ob.status == "refuted"
                    for ob in h.proof_obligations)
    )

    has_unresolved_required = any(
        ob.required_for_finding and ob.status in ("unresolved", "refuted")
        for ob in h.proof_obligations
    )
    if has_unresolved_required and not high_conf_override:
        return "initial"

    if not valid_ev:
        if not (all_required_verified and h.confidence >= 5):
            return "initial"

    if not has_strong_evidence:
        if not (has_config_evidence and all_required_verified):
            return "initial"

    return "reproduced" if h.status == "reproduced" else "evidence_supported"


_QUALITY_CONF_CAP = {"textual": 4, "inferred": 3, "structural": 7, "semantic": 10}


_MIN_ANCHOR_LEN = 12

_READ_FILE_MAX_LINES = 800
_READ_HEAD_LINES = 200
_READ_FROM_LINES = 150


def _read_window(start_line: Optional[int], end_line: Optional[int]) -> tuple[int, int]:
    if start_line is None and end_line is not None:
        start_line = 1
    if start_line is None:
        return 0, _READ_HEAD_LINES
    s = max(0, start_line - 1)
    e = end_line if end_line is not None else s + _READ_FROM_LINES
    return s, min(e, s + _READ_FILE_MAX_LINES)


def _read_spans(tool_index: "list[tuple[str, dict]]", repo_path: str) -> "list[tuple[Path, int, int]]":
    repo = Path(repo_path).resolve()
    spans: list[tuple[Path, int, int]] = []
    for name, args in tool_index:
        if name != "read_file" or not isinstance(args.get("file_path"), str):
            continue
        try:
            start = args.get("start_line")
            end = args.get("end_line")
            start = int(start) if start is not None else None
            end = int(end) if end is not None else None
            target = (repo / args["file_path"]).resolve()
            target.relative_to(repo)
        except (TypeError, ValueError, OSError):
            continue
        s, e = _read_window(start, end)
        if e > s:
            spans.append((target, s + 1, e))
    return spans


def _read_verified(ev: "Evidence", spans: "list[tuple[Path, int, int]]", repo_path: str) -> bool:
    if ev.stale or len(" ".join((ev.anchor_text or "").split())) < _MIN_ANCHOR_LEN:
        return False
    try:
        target = (Path(repo_path).resolve() / ev.file_path).resolve()
    except (OSError, ValueError):
        return False
    return any(path == target and lo <= ev.line_start and ev.line_end <= hi
               for path, lo, hi in spans)


_SEMANTIC_TOOLS = frozenset({
    "trace_path", "query_graph",
})


_STRUCTURAL_TOOLS = frozenset({
    "parse_file_structure", "find_all_usages", "search_graph",
    "run_semgrep", "get_code_snippet",
})


_METHOD_ORDER = ("textual", "inferred", "structural", "semantic")


def _tool_base(name: str) -> str:
    """Return the bare tool name, stripping mcp__server__ prefix if present."""
    return name.rsplit("__", 1)[-1] if "__" in name else name


def _cap_method_from_calls(method: str, called: frozenset[str]) -> str:
    """Cap a claimed analysis method against the set of tool names called.

    Used by tests. Production code uses _cap_method_per_evidence which is
    stricter: semantic requires a matching per-evidence tool call, not just
    any call in the run.

    semantic  → allowed only if a call-chain tool was used
    structural → allowed only if a code-structure tool was used
    textual   → always allowed
    inferred  → always allowed
    """
    if method == "semantic" and not (called & _SEMANTIC_TOOLS):
        method = "structural"
    if method == "structural" and not (called & (_SEMANTIC_TOOLS | _STRUCTURAL_TOOLS)):
        method = "textual"
    return method


def _extract_called_tools(messages: list[dict]) -> frozenset[str]:
    """Return the set of bare tool names called across all assistant turns."""
    names: set[str] = set()
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls") or []:
            raw = tc.get("function", {}).get("name", "")
            if raw:
                names.add(_tool_base(raw))
    return frozenset(names)


_GRAPH_TOOL_NAMES = frozenset({
    "search_graph", "trace_path", "get_code_snippet", "query_graph", "search_code",
    "get_architecture",
})
_FAILED_PREFIXES = (
    "Tool error (", "No results", "No rows", "Symbol not found in graph index",
    "query_graph is read-only", "query is required",
)
_CYPHER_STRING = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"")


def _failed_result(name: str, result: Optional[str]) -> bool:
    if result is None:
        return False
    text = result.strip()
    if text.startswith("Tool error ("):
        return True
    if name not in _GRAPH_TOOL_NAMES:
        return False
    return (not text or text.startswith(_FAILED_PREFIXES)
            or text.startswith(f"{name} is unavailable: the code graph has no index"))


def _cypher_literals(query: str) -> str:
    return " ".join(a or b for a, b in _CYPHER_STRING.findall(query or ""))


def _build_tool_call_index(messages: list[dict]) -> list[tuple[str, dict]]:
    """Return list of (bare_tool_name, parsed_args) for every tool call in the run."""
    results = {m.get("tool_call_id"): m.get("content") for m in messages
               if m.get("role") == "tool" and isinstance(m.get("content"), str)}
    index: list[tuple[str, dict]] = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls") or []:
            name = _tool_base(tc.get("function", {}).get("name", ""))
            if not name:
                continue
            try:
                args = json.loads(tc.get("function", {}).get("arguments", "{}"))
            except Exception:
                args = {}
            if not isinstance(args, dict):
                args = {}
            result = results.get(tc.get("id"))
            if _failed_result(name, result):
                continue
            if name == "query_graph":
                args = {"query": _cypher_literals(str(args.get("query") or "")),
                        "_result": result or ""}
            index.append((name, args))
    return index


def _result_names_file(args: dict, ev_file: str) -> bool:
    text = str(args.get("_result") or "").lower()
    path = (ev_file or "").strip().lstrip("./").lower()
    if not text or not path:
        return False
    return path in text or (len(Path(path).name) >= 4 and Path(path).name in text)


_IDENTITY_ARG_KEYS = frozenset({
    "function_name", "qualified_name", "query", "file_path",
    "name_pattern", "symbol", "path",
})


def _args_match_evidence(args: dict, ev_file: str, ev_desc: str) -> bool:
    """True if any identity arg value references the evidence's file or subject.

    Only _IDENTITY_ARG_KEYS are checked — control/enum args (mode, direction,
    limit, etc.) are skipped so accidental substring matches don't fire.
    """
    from pathlib import Path as _P
    ev_base = _P(ev_file or "").stem.lower()
    ev_file_l = (ev_file or "").lower()
    haystack = ev_file_l + " " + (ev_desc or "").lower()
    for k, v in args.items():
        if k not in _IDENTITY_ARG_KEYS:
            continue
        if not isinstance(v, str) or len(v) < 4:
            continue
        v_l = v.lower()
        if v_l in haystack:
            return True
        if ev_base and len(ev_base) >= 4 and ev_base in v_l:
            return True
    return False


def _cap_method_per_evidence(
    method: str,
    ev_file: str,
    ev_desc: str,
    tool_index: list[tuple[str, dict]],
    run_tools: frozenset[str],
    read_verified: bool = False,
) -> str:
    """Per-evidence method cap.

    semantic  — per-evidence: a _SEMANTIC_TOOLS call whose args mention
                this evidence's file or description must exist.
    structural — per-run: any structural tool must have been called at all
                (a file read covers all evidence from that file), or
                per-evidence: read_file showed the cited lines and the
                anchor was found in them (read_verified).
    textual   — always allowed.
    inferred  — always allowed.
    """
    if method not in ("semantic", "structural"):
        return method
    if method == "semantic":
        if not any(
            _result_names_file(args, ev_file) if name == "query_graph" else
            name in _SEMANTIC_TOOLS and _args_match_evidence(args, ev_file, ev_desc)
            for name, args in tool_index
        ):
            method = "structural"
    if method == "structural":
        if not (read_verified or run_tools & (_SEMANTIC_TOOLS | _STRUCTURAL_TOOLS)):
            method = "textual"
    return method


def _apply_quality_caps(h: "Hypothesis", evidence: "list[Evidence]",
                        missing_cap: "int | None" = _QUALITY_CONF_CAP["inferred"]) -> None:
    valid = [e for e in evidence if not e.stale]
    if not valid:
        if missing_cap is not None and h.confidence > missing_cap:
            h.confidence = missing_cap
        return
    own = [e for e in valid if not e.merged_by] or valid
    worst_cap = min(_QUALITY_CONF_CAP.get(e.analysis_quality.method, 4) for e in own)
    if h.confidence > worst_cap:
        h.confidence = worst_cap


def _inject_minimum_obligations(h: "Hypothesis") -> None:
    existing_required = {
        ob.claim_type for ob in h.proof_obligations if ob.required_for_finding
    }
    from .models import ProofObligation
    if "reachability" not in existing_required and h.reachability != "proven":
        h.proof_obligations.append(ProofObligation(
            question="Is the entry point reachable by the described actor?",
            status="unresolved",
            claim_type="reachability",
            required_for_finding=True,
            reason=f"engine-injected (reachability={h.reachability})",
        ))
    if "input_control" not in existing_required and h.input_control not in ("full", "partial"):
        h.proof_obligations.append(ProofObligation(
            question="Does the attacker control the security-relevant input?",
            status="unresolved",
            claim_type="input_control",
            required_for_finding=True,
            reason=f"engine-injected (input_control={h.input_control})",
        ))
    if "guard" not in existing_required and h.guard_coverage in ("unknown", "some_paths"):
        h.proof_obligations.append(ProofObligation(
            question="Are all attack paths free of effective guards?",
            status="unresolved",
            claim_type="guard",
            required_for_finding=True,
            reason=f"engine-injected (guard_coverage={h.guard_coverage})",
        ))


def _apply_profile(h: "Hypothesis", evidence: "list[Evidence]",
                   profile: "ProjectProfile", commit: str = "") -> None:
    if profile.is_empty():
        return

    override = profile.exposure_for(h.entry_point)
    if override:
        h.exposure = override

    rule_text = " ".join(filter(None, [h.violated_invariant, h.skill_source, h.capability]))
    for path in [e.file_path for e in evidence if e.file_path]:
        suppression = profile.suppression_for(h.cwe or "", rule_text, path)
        if suppression:
            h.status = "rejected"
            h.rejected_by = "profile"
            h.rejected_at_commit = commit
            h.rejection_reason = (
                f"suppressed by .llmsast.yaml: {suppression.reason} "
                f"(expires {suppression.expires.isoformat()})"
            )
            h.rejection_condition = f"{suppression.rule} in {suppression.path}"
            return
