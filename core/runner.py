from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any, Optional
from .config import Config
from .llm import LLMClient
from .db import EvidenceStore
from .memory_mcp import CodebaseMemoryClient
from .models import (
    Hypothesis, Evidence, CoverageItem, EntryPoint, Guard,
    SkillResult, ValidationRun, FINDINGS_SCHEMA,
    FunctionSummary, OpenQuestion, ConflictRecord, AnalysisQuality, ReturnValueContract,
)
from .code_analysis import (
    parse_file_structure, find_all_usages, run_semgrep, list_dir, run_shell
)
from .profile import ProjectProfile, load_profile

SYSTEM_PROMPT = """You are an expert security researcher performing authorized penetration testing on a codebase.

## Tool priority — follow this order:

1. **list_dir** — orient yourself before searching anything.
2. **get_architecture** — understand the tech stack and service map.
3. **search_graph / trace_path** — structural queries (call graphs, symbol resolution). PREFER over grep.
4. **get_code_snippet** — read a specific function by qualified name. Use after search_graph finds it.
5. **parse_file_structure** — get every class/method in a file with line numbers and decorators.
6. **read_file** — read a file or range when you need the actual code, not just the structure.
7. **find_all_usages** — find every caller/consumer of a symbol by name across the repo.
8. **run_semgrep** — use for taint flow analysis (user-input → SQL/shell/template), after you already understand the codebase structure. Pass a targeted pattern, not a generic scan.
9. **search_code** — graph-augmented text search. Good for finding registrations, annotations, config.
10. **grep** — LAST RESORT only when all above have failed or are unavailable.

## Analysis requirements:

For each potential vulnerability, before calling finish():
- Read the actual handler function (get_code_snippet / read_file), not just its name.
- Trace the full call chain (trace_path or manual read_file chain), step by step.
- Read every middleware/filter/policy in the path.
- Read the ORM context (OnModelCreating, global query filters).
- Read DB entity definitions.
- Read any validation classes.
- Then assess guards.

A finding REQUIRES:
- Actor, Capability, Entry point (file:line), Execution path (each step with file:line), Security boundary, Violated invariant, Observable impact.
- Counterevidence: each guard you ACTUALLY READ and why it doesn't stop the attack.
- Uncertainty: what you could NOT verify.
- reachability must be "proven" or "probable" — if still "unknown", investigate more or set confidence≤2.

Invalid: "this pattern suggests SQL injection". Valid: "UserController.Search at Controllers/UserController.cs:47 passes req.query.name directly to UserRepository.Search (read at Repos/UserRepo.cs:12), which calls context.Database.ExecuteSqlRaw($\"SELECT * FROM users WHERE name = '{name}'\") (read at line 18). No parameterization. ORM global filter not applicable to raw SQL (confirmed OnModelCreating at Data/AppDbContext.cs:30 — no query filters on User). No middleware sanitization (read Startup.cs:45-80)."

Never claim a guard is absent without reading the relevant code.

## Reusable summaries
- Call **get_open_questions** at the start to see what prior skills couldn't resolve.
- Call **get_function_summary** before re-analyzing a shared utility (repository, service, validator).
- Call **save_function_summary** after reading a shared utility so later skills skip re-analyzing it. Include: inputs (origin of each parameter), reads (state/DB accessed), writes (state modified), external_effects, guards (what checks it performs), transformations, failure_behavior, required_authority, unresolved_calls.

## Proof obligations
- For each hypothesis, populate `proof_obligations` — one entry per claim you need to verify. Mark each `verified` (with evidence_ref=file:line) or `unresolved` (with reason). Obligations with `required_for_finding=true` block the finding if `unresolved` OR `refuted`. Use `claim_type` to categorize: reachability, input_control, guard, impact, other.

## Conflicts
- Use **flag_conflict** when you discover a contradiction: a prior guard claim that doesn't hold, two paths with incompatible preconditions, or a claimed sanitizer that doesn't cover all forms of the input.

## Open questions
- Use **log_open_question** for anything that blocks or degrades a finding. Set impact=blocks_finding if the finding must not be reported until answered.

## Return value contracts
- For security-critical functions (authorization checks, ownership validation, payment status, lock acquisition), call **record_return_contract** once to document what the return value means.
- When you find a call site that ignores that return, call **flag_ignored_return** — for must_check contracts this auto-creates a blocks_finding conflict.
- Call **get_return_contracts** at skill start to see what prior skills already documented.

## Function contracts
- Use `preconditions` in save_function_summary to record what callers must guarantee before calling (e.g. "caller must own the resource", "tenant context must be set").
- Use `guarantees` to record what the function ensures when preconditions hold (e.g. "result is scoped to caller tenant", "only returns records the caller owns").
- When a caller does NOT satisfy a precondition, treat it as a potential authorization bypass.

## Rejected hypotheses
- When you rule out a hypothesis because a guard is effective, call **reject_hypothesis** with the reason instead of just setting it to refuted. Pass `rejection_condition` (the condition that must hold for this rejection to remain valid, e.g. "Guard X at file:line remains in place") and `rejection_controlling_evidence_ids` (the evidence IDs that prove the guard — if those become stale, the rejection should be re-evaluated)."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_graph",
            "description": "Find functions, classes, or routes by name pattern or label in the indexed code graph.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_pattern": {"type": "string", "description": "Substring or regex to match symbol names"},
                    "label": {"type": "string", "description": "Symbol kind: Function, Class, Route, Module"},
                    "qn_pattern": {"type": "string", "description": "Qualified name pattern"},
                    "limit": {"type": "integer", "default": 20},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trace_path",
            "description": "Trace call chains from a function. mode='calls' finds what it calls, mode='called_by' finds callers, mode='data_flow' follows data.",
            "parameters": {
                "type": "object",
                "required": ["function_name"],
                "properties": {
                    "function_name": {"type": "string"},
                    "mode": {"type": "string", "enum": ["calls", "called_by", "data_flow"], "default": "calls"},
                    "depth": {"type": "integer", "default": 5},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_code_snippet",
            "description": "Get the full source code for a symbol by qualified name.",
            "parameters": {
                "type": "object",
                "required": ["qualified_name"],
                "properties": {
                    "qualified_name": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Graph-augmented code search. Finds references and usages across the codebase.",
            "parameters": {
                "type": "object",
                "required": ["pattern"],
                "properties": {
                    "pattern": {"type": "string"},
                    "limit": {"type": "integer", "default": 50},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a source file from the repository. Use start_line/end_line to read a specific range.",
            "parameters": {
                "type": "object",
                "required": ["file_path"],
                "properties": {
                    "file_path": {"type": "string", "description": "Path relative to repo root"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep",
            "description": "Search for a literal string or regex pattern in the repository source files.",
            "parameters": {
                "type": "object",
                "required": ["pattern"],
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "Subdirectory to search in (relative to repo root)"},
                    "file_glob": {"type": "string", "description": "File pattern e.g. '*.cs' or '*.ts'"},
                    "max_matches": {"type": "integer", "default": 100},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_architecture",
            "description": "Get the overall project architecture, service map, and tech stack.",
            "parameters": {
                "type": "object",
                "properties": {
                    "aspects": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and subdirectories in the repository. Use at the start to understand project layout.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path within repo (empty = root)"},
                    "max_entries": {"type": "integer", "default": 80},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_file_structure",
            "description": "Parse a source file using tree-sitter AST and return all classes, functions, methods with line numbers and decorators. Use instead of reading the whole file when you need the structure.",
            "parameters": {
                "type": "object",
                "required": ["file_path"],
                "properties": {
                    "file_path": {"type": "string", "description": "Path relative to repo root"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_all_usages",
            "description": "Find every place in the codebase that references a symbol by name. Covers callers, field accesses, and type references.",
            "parameters": {
                "type": "object",
                "required": ["symbol_name"],
                "properties": {
                    "symbol_name": {"type": "string"},
                    "file_glob": {"type": "string", "description": "File pattern e.g. '*.cs'"},
                    "max_matches": {"type": "integer", "default": 100},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_semgrep",
            "description": "Run a targeted semgrep pattern for taint analysis or AST-aware pattern matching. Use for: user-input → SQL, user-input → shell, unsafe deserialization patterns. Prefer a specific pattern over a broad scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Semgrep pattern e.g. 'context.Database.ExecuteSqlRaw($\"...{...}...\")'"},
                    "language": {"type": "string", "description": "e.g. csharp, python, javascript"},
                    "rules": {"type": "string", "description": "Semgrep rule config e.g. 'p/default' or path to rule file"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell",
            "description": (
                "Run a read-only shell command with the repo as cwd. "
                "Whitelisted binaries: find, tree, git (log/blame/diff/show/grep), "
                "wc, head, tail, sort, uniq, cut, awk, sed, tr, jq, yq, "
                "file, strings, xxd, hexdump, base64, diff, stat, md5sum, sha256sum, openssl, xargs. "
                "Examples: 'git log --oneline -20', 'git blame src/auth/handler.go', "
                "'find . -name \"*.cs\" -newer go.mod', 'git diff HEAD~1 -- src/Payment.cs', "
                "'jq .scripts package.json', 'strings bin/server | grep -i password'."
            ),
            "parameters": {
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_threat_model",
            "description": (
                "Persist a threat model for this target, shared with all subsequent skills. "
                "Call once after initial architecture review. "
                "Required sections: ## Overview, ## Trust Boundaries, ## Attack Surface, ## Severity Calibration. "
                "Minimum 400 chars. If a model already exists, this overwrites it."
            ),
            "parameters": {
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": {"type": "string", "description": "Full threat model in Markdown"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "amend_threat_model",
            "description": (
                "Append a correction or discovery to the existing threat model without replacing it. "
                "Use when you find the base model was wrong or incomplete."
            ),
            "parameters": {
                "type": "object",
                "required": ["addendum"],
                "properties": {
                    "addendum": {"type": "string", "description": "Markdown correction or addition"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_function_summary",
            "description": (
                "Persist a reusable security summary for a function so later skills skip re-analyzing it. "
                "Include: inputs (origin of each parameter), reads (state/DB accessed), "
                "writes (state modified), external_effects (DB write/HTTP/file), "
                "guards (what checks it performs), transformations, failure_behavior, "
                "required_authority (what permissions caller must have), "
                "unresolved_calls (functions you couldn't analyze)."
            ),
            "parameters": {
                "type": "object",
                "required": ["qualified_name", "file_path", "line"],
                "properties": {
                    "qualified_name": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                    "inputs": {"type": "array", "items": {"type": "string"}},
                    "reads": {"type": "array", "items": {"type": "string"}},
                    "writes": {"type": "array", "items": {"type": "string"}},
                    "external_effects": {"type": "array", "items": {"type": "string"}},
                    "guards": {"type": "array", "items": {"type": "string"}},
                    "transformations": {"type": "array", "items": {"type": "string"}},
                    "failure_behavior": {"type": "string"},
                    "preconditions": {"type": "array", "items": {"type": "string"},
                                      "description": "What callers must guarantee before calling"},
                    "guarantees": {"type": "array", "items": {"type": "string"},
                                   "description": "What the function ensures when preconditions hold"},
                    "required_authority": {"type": "array", "items": {"type": "string"}},
                    "unresolved_calls": {"type": "array", "items": {"type": "string"}},
                    "quality_method": {
                        "type": "string",
                        "enum": ["semantic", "structural", "textual", "inferred"],
                        "description": "How this summary was derived",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_summary",
            "description": "Retrieve a previously saved security summary for a function by its qualified name.",
            "parameters": {
                "type": "object",
                "required": ["qualified_name"],
                "properties": {
                    "qualified_name": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "log_open_question",
            "description": (
                "Record a structured open question that blocks or degrades a finding. "
                "Use instead of (or in addition to) open_questions in finish(). "
                "impact=blocks_finding means the finding must not be reported until resolved."
            ),
            "parameters": {
                "type": "object",
                "required": ["question", "impact"],
                "properties": {
                    "question": {"type": "string"},
                    "impact": {"type": "string", "enum": ["blocks_finding", "affects_confidence", "informational"]},
                    "affects_hypothesis_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "hypothesis IDs this question blocks",
                    },
                    "resolution_hint": {
                        "type": "string",
                        "description": "how a future skill might resolve this",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "flag_conflict",
            "description": (
                "Record a contradiction in the analysis: e.g. a guard claimed complete but a bypass path was found, "
                "or two skills reach opposite conclusions about the same code. "
                "Conflicts are visible to all subsequent skills."
            ),
            "parameters": {
                "type": "object",
                "required": ["kind", "description", "left", "right"],
                "properties": {
                    "kind": {"type": "string", "enum": [
                        "guard_mismatch", "status_inconsistency",
                        "stale_reference", "contradicting_claims", "capability_mismatch",
                    ]},
                    "description": {"type": "string"},
                    "left": {"type": "string", "description": "first claim, hypothesis_id, or file:line"},
                    "right": {"type": "string", "description": "conflicting claim, hypothesis_id, or file:line"},
                    "severity": {"type": "string", "enum": ["blocks_finding", "degrades_confidence", "informational"]},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_open_questions",
            "description": "Retrieve open questions recorded by prior skills that are still unresolved.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_return_contract",
            "description": (
                "Mark a function's return value as security-relevant. "
                "Call once per function; subsequent flag_ignored_return calls reference it. "
                "Use for: authorization checks, ownership validation, payment status, lock acquisition."
            ),
            "parameters": {
                "type": "object",
                "required": ["function_qualified_name", "file_path", "line", "return_type"],
                "properties": {
                    "function_qualified_name": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                    "return_type": {"type": "string"},
                    "security_relevance": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "expected_handling": {"type": "string", "enum": ["must_check", "may_ignore", "context_dependent"]},
                    "consequence_if_ignored": {"type": "string", "description": "What goes wrong if caller ignores the return"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "flag_ignored_return",
            "description": (
                "Mark a call site that ignores a security-relevant return value. "
                "For must_check contracts, auto-creates a blocks_finding conflict."
            ),
            "parameters": {
                "type": "object",
                "required": ["function_qualified_name", "caller_location"],
                "properties": {
                    "function_qualified_name": {"type": "string"},
                    "caller_location": {"type": "string", "description": "file:line or qualified name of the ignoring call site"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_return_contracts",
            "description": "List return value contracts recorded by prior skills.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reject_hypothesis",
            "description": (
                "Mark a hypothesis as rejected with a documented reason. "
                "Use instead of simply not reporting it — the reason is stored so future skills can "
                "detect if the ruling control is later removed."
            ),
            "parameters": {
                "type": "object",
                "required": ["hypothesis_id", "reason"],
                "properties": {
                    "hypothesis_id": {"type": "string"},
                    "reason": {"type": "string", "description": "Why this hypothesis is ruled out (cite the specific guard/control and file:line)"},
                    "rejection_condition": {"type": "string", "description": "Condition that must hold for this rejection to remain valid (e.g. 'Guard X at file:line remains in place')"},
                    "rejection_controlling_evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "Evidence IDs that prove the guard — if these become stale, rejection should be re-evaluated"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Submit the final structured findings. Call this when analysis is complete.",
            "parameters": {
                "type": "object",
                "required": ["findings"],
                "properties": {
                    "findings": FINDINGS_SCHEMA,
                },
            },
        },
    },
]


def _gate_hypothesis_status(
    h: "Hypothesis",
    evidence: "list[Evidence]",
    conflicts: "list[ConflictRecord]",
    open_questions: "list[OpenQuestion] | None" = None,
) -> str:
    if h.status in ("rejected", "closed"):
        return h.status
    status = "evidence_supported" if h.status == "reproduced" else h.status
    if status != "evidence_supported":
        return status
    valid_ev = [e for e in evidence if not e.stale]
    if not valid_ev:
        return "initial"
    for c in conflicts:
        if c.severity == "blocks_finding" and c.status == "open":
            return "initial"
    if any(ob.required_for_finding and ob.status == "unresolved" for ob in h.proof_obligations):
        return "initial"
    if any(ob.required_for_finding and ob.status == "refuted" for ob in h.proof_obligations):
        return "initial"
    if open_questions:
        for q in open_questions:
            if q.impact == "blocks_finding" and q.status == "open":
                if not q.affects_hypothesis_ids or h.id in q.affects_hypothesis_ids:
                    return "initial"
    return status


_QUALITY_CONF_CAP = {"textual": 4, "inferred": 3, "structural": 7, "semantic": 10}


def _apply_quality_caps(h: "Hypothesis", evidence: "list[Evidence]") -> None:
    valid = [e for e in evidence if not e.stale]
    if not valid:
        return
    worst_cap = min(_QUALITY_CONF_CAP.get(e.analysis_quality.method, 4) for e in valid)
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
                   profile: "ProjectProfile") -> None:
    if profile.is_empty():
        return

    override = profile.exposure_for(h.entry_point)
    if override:
        h.exposure = override

    rule_text = " ".join(filter(None, [h.cwe, h.violated_invariant, h.skill_source]))
    paths = [e.file_path for e in evidence if e.file_path]
    for path in paths or [""]:
        suppression = profile.suppression_for(rule_text, path)
        if suppression:
            h.status = "rejected"
            h.rejection_reason = (
                f"suppressed by .llmsast.yaml: {suppression.reason} "
                f"(expires {suppression.expires.isoformat()})"
            )
            h.rejection_condition = f"{suppression.rule} in {suppression.path}"
            return


class SkillRunner:
    def __init__(self, cfg: Config, db: EvidenceStore, mcp: CodebaseMemoryClient):
        self._cfg = cfg
        self._llm = LLMClient(cfg)
        self._db = db
        self._mcp = mcp
        self._skills_dir = cfg.resolved_skills()

    def _load_skill(self, skill_name: str) -> str:
        for phase_dir in sorted(self._skills_dir.iterdir()):
            if not phase_dir.is_dir():
                continue
            p = phase_dir / f"{skill_name}.md"
            if p.exists():
                return p.read_text()
        raise FileNotFoundError(f"Skill '{skill_name}' not found in {self._skills_dir}")

    def _get_commit(self, repo_path: str) -> str:
        try:
            r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_path,
                               capture_output=True, text=True, timeout=5)
            return r.stdout.strip()[:12] if r.returncode == 0 else ""
        except Exception:
            return ""

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
            lines = target.read_text(errors="replace").splitlines()
            if start_line is not None:
                s = max(0, start_line - 1)
                e = end_line if end_line is not None else min(s + 150, len(lines))
                lines = lines[s:e]
                offset = s
            else:
                lines = lines[:200]
                offset = 0
            return "\n".join(f"{offset + i + 1:4}: {l}" for i, l in enumerate(lines))
        except Exception as ex:
            return f"Error: {ex}"

    def _grep(self, repo_path: str, pattern: str, path: Optional[str] = None,
              file_glob: Optional[str] = None, max_matches: int = 100) -> str:
        if path:
            safe = self._resolve_path(repo_path, path)
            if safe is None:
                return "Access denied: path outside repository"
            search_path = str(safe)
        else:
            search_path = repo_path
        try:
            cmd = ["rg", "--line-number", "--no-heading", f"-m{max_matches}"]
            if file_glob:
                cmd.extend(["-g", file_glob])
            cmd.extend([pattern, search_path])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return r.stdout[:12000] or "No matches"
        except FileNotFoundError:
            try:
                cmd = ["grep", "-rn", pattern, search_path]
                if file_glob:
                    cmd = ["grep", "-rn", "--include", file_glob, pattern, search_path]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                return r.stdout[:12000] or "No matches"
            except Exception as ex:
                return f"grep error: {ex}"
        except Exception as ex:
            return f"Error: {ex}"

    async def _execute_tool(self, name: str, args: dict, repo_path: str, skill_name: str = "") -> str:
        if name == "search_graph":
            r = await self._mcp.search_graph(**{k: v for k, v in args.items()})
            return json.dumps(r, indent=2) if r else "No results (codebase-memory-mcp may not be indexed)"
        if name == "trace_path":
            r = await self._mcp.trace_path(**args)
            return json.dumps(r, indent=2) if r else "No results"
        if name == "get_code_snippet":
            r = await self._mcp.get_code_snippet(args["qualified_name"])
            return r or "Symbol not found in graph index — try read_file instead"
        if name == "search_code":
            r = await self._mcp.search_code(args["pattern"], args.get("limit", 50))
            return json.dumps(r, indent=2) if r else "No results"
        if name == "get_architecture":
            r = await self._mcp.get_architecture(args.get("aspects"))
            return json.dumps(r, indent=2) if r else "No architecture data available"
        if name == "read_file":
            return self._read_file(repo_path, args["file_path"],
                                   args.get("start_line"), args.get("end_line"))
        if name == "grep":
            return self._grep(repo_path, args["pattern"], args.get("path"),
                              args.get("file_glob"), args.get("max_matches", 100))
        if name == "list_dir":
            return list_dir(repo_path, args.get("path", ""), args.get("max_entries", 80))
        if name == "parse_file_structure":
            from .language_adapter import get_adapter_for
            file_path = args["file_path"]
            adapter = get_adapter_for(file_path)
            result = adapter.enumerate_symbols(repo_path, file_path)
            import json as _json
            out: dict = {"file": file_path, "symbols": result.items}
            if result.quality.limitations or result.quality.method != "structural":
                out["analysis_quality"] = result.quality.model_dump()
            if result.error:
                out["error"] = result.error
            return _json.dumps(out, indent=2)
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
                lines.append(f"[{q.id}] impact={q.impact} skill={q.raised_by_skill}\n  {q.question}")
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
            condition = args.get("rejection_condition", "")
            controlling_ids = args.get("rejection_controlling_evidence_ids", [])
            hypotheses = self._db.list_hypotheses(repo_path)
            for h in hypotheses:
                if h.id == hyp_id:
                    h.status = "rejected"
                    h.rejection_reason = reason
                    h.rejection_condition = condition
                    h.rejection_controlling_evidence_ids = (
                        controlling_ids if isinstance(controlling_ids, list) else []
                    )
                    self._db.save_hypothesis(repo_path, h)
                    return f"Hypothesis {hyp_id} rejected. Reason and condition recorded."
            return f"Hypothesis {hyp_id} not found."
        return "Unknown tool"

    def _build_initial_context(self, repo_path: str) -> str:
        parts: list[str] = []
        profile_text = load_profile(repo_path).to_prompt()
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
    ) -> SkillResult:
        skill_text = self._load_skill(skill_name)
        commit = self._get_commit(repo_path)
        known_context = self._build_initial_context(repo_path)

        initial_msg = f"""Repository: {repo_path}  (commit: {commit})

# Skill Contract
{skill_text}

# Known Context
{known_context}
{f"# Additional Context\n{extra_context}" if extra_context else ""}

Start by calling get_architecture() to orient yourself, then use the other tools to read real code and build evidence. Call finish() when done."""

        messages: list[dict] = [{"role": "user", "content": initial_msg}]
        findings: Optional[dict] = None

        for iteration in range(max_iterations):
            content, tool_calls = await self._llm.complete_with_tools(
                messages, TOOLS, system=SYSTEM_PROMPT
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
                            findings = json.loads(content[start:end])
                    except Exception:
                        pass
                break

            finish_args: Optional[dict] = None
            tool_results: list[dict] = []

            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}

                if name == "finish":
                    finish_args = args.get("findings", args)
                    result_text = "Findings recorded."
                else:
                    if verbose:
                        print(f"  [{iteration}] tool={name} args={json.dumps(args)[:120]}")
                    result_text = await self._execute_tool(name, args, repo_path, skill_name)
                    if verbose:
                        print(f"  → {result_text[:200]}")

                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })

            messages.extend(tool_results)

            if finish_args is not None:
                findings = finish_args
                break

        if findings is None:
            findings = {"hypotheses": [], "coverage": [], "open_questions": [
                f"skill {skill_name} did not produce structured output after {max_iterations} iterations"
            ]}

        hypotheses = []
        for h_data in findings.get("hypotheses", []):
            h_data["skill_source"] = skill_name
            h_data["commit"] = commit
            h = Hypothesis.model_validate(h_data)
            if h.status == "reproduced":
                h.status = "evidence_supported"
            unresolved_obs = [ob for ob in h.proof_obligations if ob.status == "unresolved"]
            if unresolved_obs and h.status in ("evidence_supported", "reproduced"):
                h.status = "initial"
            h.priority = h.compute_priority()
            hypotheses.append(h)

        coverage = [CoverageItem.model_validate(c) for c in findings.get("coverage", [])]

        validation_errors: list[str] = []

        entry_points: list[EntryPoint] = []
        for i, ep_data in enumerate(findings.get("entry_points_found", [])):
            try:
                entry_points.append(EntryPoint.model_validate(ep_data))
            except Exception as ex:
                validation_errors.append(f"entry_point[{i}] invalid: {ex}")

        guards: list[Guard] = []
        for i, g_data in enumerate(findings.get("guards_found", [])):
            try:
                guards.append(Guard.model_validate(g_data))
            except Exception as ex:
                validation_errors.append(f"guard[{i}] invalid: {ex}")

        auto_conflicts: list[ConflictRecord] = []

        evidence_items: list[Evidence] = []
        for i, e_data in enumerate(findings.get("evidence", [])):
            try:
                e_data = dict(e_data)
                hyp_idx = e_data.pop("hypothesis_index", 0)
                if not (0 <= hyp_idx < len(hypotheses)):
                    validation_errors.append(f"evidence[{i}]: hypothesis_index {hyp_idx} out of range")
                    continue
                e_data["hypothesis_id"] = hypotheses[hyp_idx].id
                e_data.setdefault("commit", commit)
                evidence_items.append(Evidence.model_validate(e_data))
            except Exception as ex:
                validation_errors.append(f"evidence[{i}] invalid: {ex}")

        verified_evidence: list[Evidence] = []
        for ev in evidence_items:
            target = self._resolve_path(repo_path, ev.file_path)
            if target is None or not target.exists():
                auto_conflicts.append(ConflictRecord(
                    kind="stale_reference",
                    description=f"Evidence file does not exist: {ev.file_path}",
                    left=f"evidence/{ev.id}",
                    right=ev.file_path,
                    severity="blocks_finding",
                ))
                ev.analysis_quality.limitations.append(f"file not found: {ev.file_path}")
                ev.stale = True
                verified_evidence.append(ev)
                continue
            try:
                lines = target.read_text(errors="replace").splitlines()
                total = len(lines)
                if (ev.line_start < 1 or ev.line_start > total
                        or ev.line_end < ev.line_start or ev.line_end > total):
                    auto_conflicts.append(ConflictRecord(
                        kind="stale_reference",
                        description=(
                            f"Evidence line {ev.line_start} out of range "
                            f"(file has {total} lines): {ev.file_path}"
                        ),
                        left=f"evidence/{ev.id}",
                        right=f"{ev.file_path}:{ev.line_start}",
                        severity="blocks_finding",
                    ))
                    ev.analysis_quality.limitations.append(
                        f"line {ev.line_start} out of range (file has {total} lines)"
                    )
                    ev.stale = True
                else:
                    s = ev.line_start - 1
                    e = min(total, max(ev.line_end, ev.line_start))
                    ev.snippet = "\n".join(lines[s:e])
                    ev.analysis_quality.method = "structural"
                    ev.analysis_quality.confidence = "high"
                    if ev.anchor_text:
                        def _norm(t: str) -> str:
                            return " ".join(t.split())
                        anchor_norm = _norm(ev.anchor_text)
                        if anchor_norm in _norm(ev.snippet):
                            pass
                        else:
                            lo = max(0, s - 10)
                            hi = min(total, e + 10)
                            window = "\n".join(lines[lo:hi])
                            if anchor_norm in _norm(window):
                                for li, ln in enumerate(lines[lo:hi], start=lo + 1):
                                    if anchor_norm in _norm(ln):
                                        ev.line_start = li
                                        ev.line_end = li
                                        ev.snippet = "\n".join(lines[li - 1:min(total, li + 2)])
                                        break
                                ev.analysis_quality.confidence = "medium"
                                ev.analysis_quality.limitations.append(
                                    "anchor_text found outside claimed range; line numbers corrected"
                                )
                            else:
                                auto_conflicts.append(ConflictRecord(
                                    kind="stale_reference",
                                    description=(
                                        f"Evidence anchor_text not found at or near claimed lines "
                                        f"in {ev.file_path}:{ev.line_start}"
                                    ),
                                    left=f"evidence/{ev.id}",
                                    right=f"{ev.file_path}:{ev.line_start}",
                                    severity="blocks_finding",
                                ))
                                ev.analysis_quality.limitations.append(
                                    f"anchor_text {ev.anchor_text!r:.40} not found in ±10 lines"
                                )
                                ev.stale = True
            except Exception as ex:
                ev.analysis_quality.limitations.append(f"read error: {ex}")
            verified_evidence.append(ev)
        evidence_items = verified_evidence

        structured_questions: list[OpenQuestion] = []
        for sq_data in findings.get("structured_questions", []):
            try:
                sq = OpenQuestion.model_validate(sq_data)
                sq.raised_by_skill = skill_name
                structured_questions.append(sq)
            except Exception as ex:
                validation_errors.append(f"structured_question invalid: {ex}")

        fn_summaries: list[FunctionSummary] = []
        for fs_data in findings.get("function_summaries", []):
            try:
                fs = FunctionSummary.model_validate(fs_data)
                fs.created_by_skill = skill_name
                fs.commit = commit
                fn_summaries.append(fs)
            except Exception as ex:
                validation_errors.append(f"function_summary invalid: {ex}")

        ignored_returns: list[ReturnValueContract] = []
        for rc_data in findings.get("ignored_returns", []):
            try:
                rc = ReturnValueContract.model_validate(rc_data)
                rc.created_by_skill = skill_name
                ignored_returns.append(rc)
            except Exception as ex:
                validation_errors.append(f"ignored_return invalid: {ex}")

        llm_conflicts: list[ConflictRecord] = []
        for i, c_data in enumerate(findings.get("conflicts", [])):
            try:
                llm_conflicts.append(ConflictRecord.model_validate(c_data))
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
        profile = load_profile(repo_path)

        for h in hypotheses:
            ev_for_h = [e for e in evidence_items if e.hypothesis_id == h.id]
            ev_ids = {e.id for e in ev_for_h}
            conf_for_h = [
                c for c in all_conflicts
                if (h.id in (c.left, c.right)
                    or h.id in c.description
                    or any(f"evidence/{eid}" in (c.left, c.right) for eid in ev_ids))
            ]
            _apply_quality_caps(h, ev_for_h)
            _inject_minimum_obligations(h)
            h.status = _gate_hypothesis_status(h, ev_for_h, conf_for_h, all_open_questions)
            _apply_profile(h, ev_for_h, profile)
            h.priority = h.compute_priority()

        open_questions = findings.get("open_questions", []) + validation_errors

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

    async def run_phase(self, phase: str, repo_path: str,
                        verbose: bool = False) -> list[SkillResult]:
        phase_dir = self._skills_dir / phase
        if not phase_dir.exists():
            raise FileNotFoundError(f"Phase dir not found: {phase_dir}")
        results = []
        for sf in sorted(phase_dir.glob("*.md")):
            results.append(await self.run_skill(sf.stem, repo_path, verbose=verbose))
        return results

    async def run_all(self, repo_path: str, verbose: bool = False) -> list[SkillResult]:
        results = []
        for phase_dir in sorted(self._skills_dir.iterdir()):
            if not phase_dir.is_dir():
                continue
            for sf in sorted(phase_dir.glob("*.md")):
                results.append(await self.run_skill(sf.stem, repo_path, verbose=verbose))
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
                verdict = finish_args.get("verdict", finish_args)
                break

        _REVIEW_STATUS_MAP = {
            "reproduced": "evidence_supported",
            "evidence_supported": "evidence_supported",
            "refuted": "refuted",
            "blocked": "blocked",
            "initial": "initial",
        }
        suggested = verdict.get("suggested_status", hyp.status)
        new_status = _REVIEW_STATUS_MAP.get(suggested, hyp.status)
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

        all_db_conflicts = self._db.get_conflicts_for_hypothesis(hyp.id)
        all_db_evidence = self._db.get_evidence_for_hypothesis(hyp.id)
        db_open_questions = self._db.list_open_questions(repo_path, status="open")
        hyp.status = _gate_hypothesis_status(hyp, all_db_evidence, all_db_conflicts, db_open_questions)
        self._db.save_hypothesis(repo_path, hyp)

        return verdict
