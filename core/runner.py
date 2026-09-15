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
    SkillResult, ValidationRun, FINDINGS_SCHEMA
)
from .code_analysis import (
    parse_file_structure, find_all_usages, run_semgrep, list_dir, run_shell
)

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

Never claim a guard is absent without reading the relevant code."""

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

    async def _execute_tool(self, name: str, args: dict, repo_path: str) -> str:
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
            return parse_file_structure(repo_path, args["file_path"])
        if name == "find_all_usages":
            return find_all_usages(repo_path, args["symbol_name"],
                                   args.get("file_glob"), args.get("max_matches", 100))
        if name == "run_semgrep":
            return run_semgrep(repo_path, args.get("pattern", ""),
                               args.get("language"), args.get("rules"))
        if name == "shell":
            return run_shell(repo_path, args["command"])
        return "Unknown tool"

    def _build_initial_context(self, repo_path: str) -> str:
        parts: list[str] = []
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
                    result_text = await self._execute_tool(name, args, repo_path)
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

        open_questions = findings.get("open_questions", []) + validation_errors

        result = SkillResult(
            skill_name=skill_name,
            repo_path=repo_path,
            commit=commit,
            hypotheses=hypotheses,
            evidence=evidence_items,
            coverage=coverage,
            open_questions=open_questions,
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
                    res = await self._execute_tool(name, args, repo_path)
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
            self._db.save_hypothesis(repo_path, hyp)

        return verdict
