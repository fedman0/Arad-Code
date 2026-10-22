from __future__ import annotations
from .models import FINDINGS_SCHEMA


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_graph",
            "description": (
                "Find functions, methods, classes, routes or modules in the indexed code graph. "
                "name_pattern / qn_pattern match names (regex), query ranks symbols by keywords in "
                "their names and code (BM25), semantic_query ranks by meaning. Keyword and meaning "
                "search are helpers for finding candidates; read the code before relying on a hit. "
                "Rows carry the qualified name, file, lines and in/out degree."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name_pattern": {"type": "string", "description": "Regex or substring matched against symbol names"},
                    "label": {"type": "string", "description": "Symbol kind: Function, Method, Class, Route, Module, Variable"},
                    "qn_pattern": {"type": "string", "description": "Regex matched against qualified names"},
                    "query": {"type": "string", "description": "Keywords, e.g. 'sequelize query login'"},
                    "semantic_query": {"type": "array", "items": {"type": "string"},
                                       "description": "Phrases describing what the code does; not together with query"},
                    "file_pattern": {"type": "string", "description": "Restrict to files whose path matches, e.g. 'routes/'"},
                    "relationship": {"type": "string", "description": "Edge type the symbol must have, e.g. CALLS"},
                    "include_connected": {"type": "boolean", "description": "Also list each hit's direct neighbours"},
                    "limit": {"type": "integer", "default": 20},
                    "offset": {"type": "integer", "default": 0},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trace_path",
            "description": (
                "Trace call chains from a function. mode='calls' follows call edges, "
                "mode='data_flow' follows values, mode='cross_service' follows HTTP/async routes. "
                "direction='inbound' returns callers, 'outbound' returns callees, 'both' returns both. "
                "function_name is a short name or a qualified name from search_graph. "
                "An inbound chain from a sink to a route handler is the strongest proof that "
                "the sink is reachable, and evidence it supports counts as semantic."
            ),
            "parameters": {
                "type": "object",
                "required": ["function_name"],
                "properties": {
                    "function_name": {"type": "string"},
                    "mode": {"type": "string", "enum": ["calls", "data_flow", "cross_service"], "default": "calls"},
                    "direction": {"type": "string", "enum": ["inbound", "outbound", "both"], "default": "both"},
                    "depth": {"type": "integer", "default": 3},
                    "parameter_name": {"type": "string",
                                       "description": "data_flow only: follow this parameter of the function, e.g. 'req'"},
                    "risk_labels": {"type": "boolean", "description": "Label each hop with the risk it carries"},
                    "limit": {"type": "integer", "default": 100},
                    "cursor": {"type": "string", "description": "The `next` value of the previous reply, to get the next page"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_code_snippet",
            "description": (
                "Get the source of a symbol by qualified name (or short name). Long sources are "
                "clipped; continue with start_line. include_neighbors also lists its callers and "
                "callees."
            ),
            "parameters": {
                "type": "object",
                "required": ["qualified_name"],
                "properties": {
                    "qualified_name": {"type": "string"},
                    "include_neighbors": {"type": "boolean"},
                    "source_mode": {"type": "string", "enum": ["auto", "full", "outline"]},
                    "start_line": {"type": "integer"},
                    "max_lines": {"type": "integer"},
                    "member_offset": {"type": "integer", "description": "outline only: the next_member_offset of the previous reply"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_graph",
            "description": (
                "Read-only Cypher over the code graph for questions that span many symbols, e.g. "
                "MATCH (f:Function)-[:CALLS]->(g:Function) WHERE g.name = 'query' RETURN f.name, "
                "f.file_path LIMIT 50. Labels include Function, Method, Class, Module, File, Route; "
                "edges include CALLS, HANDLES, HTTP_CALLS, IMPORTS, DEFINES, USAGE, WRITES. "
                "A call chain it returns counts as semantic evidence."
            ),
            "parameters": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string"},
                    "max_rows": {"type": "integer", "default": 100},
                    "cursor": {"type": "string", "description": "The next_cursor of the previous reply, to get the next page"},
                    "offset": {"type": "integer", "description": "The next_offset of the previous reply, when there is no cursor"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Graph-augmented code search. Finds references and usages across the codebase. The pattern is literal unless regex=true.",
            "parameters": {
                "type": "object",
                "required": ["pattern"],
                "properties": {
                    "pattern": {"type": "string"},
                    "limit": {"type": "integer", "default": 50},
                    "regex": {"type": "boolean", "default": False},
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
            "description": (
                "Search the repository with a ripgrep (Rust) regex. Hidden files such as .github/ and .env "
                "are included; .git and gitignored files are not. No lookaround or backreferences. "
                "Set multiline=true to let the pattern match across lines (\\n)."
            ),
            "parameters": {
                "type": "object",
                "required": ["pattern"],
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "Subdirectory to search in (relative to repo root)"},
                    "file_glob": {"type": "string", "description": "File pattern e.g. '*.cs' or '*.ts'"},
                    "max_matches": {"type": "integer", "default": 100, "description": "Maximum matches per file"},
                    "multiline": {"type": "boolean", "default": False},
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
            "description": "Run a targeted semgrep pattern for taint analysis or AST-aware pattern matching. Use for: user-input → SQL, user-input → shell, unsafe deserialization patterns. Prefer a specific pattern over a broad scan. A pattern requires a language.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Semgrep pattern e.g. 'context.Database.ExecuteSqlRaw($\"...{...}...\")'"},
                    "language": {"type": "string", "description": "Required with pattern, e.g. csharp, python, javascript"},
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
                "Run one read-only command with the repo as cwd (no pipes, redirection, "
                "command substitution, ';' or '&&'; paths must stay inside the repository). "
                "ls, cat, sed, awk, grep, interpreters and build tools are not available: "
                "use list_dir, read_file (with start_line/end_line) and the grep tool for those. "
                "Allowed commands: git (log, show, blame, diff, ls-files, ls-tree, rev-parse, "
                "status, shortlog, describe, grep), find (name/path/type/size/time tests only, "
                "no -exec or -delete), tree, wc, head, tail, file, stat, sha256sum, sha1sum, "
                "md5sum, jq, diff, strings, cut. "
                "Examples: 'git log --oneline -20', 'git blame src/auth/handler.go', "
                "'find . -name \"*.cs\" -newer go.mod', 'git diff HEAD~1 -- src/Payment.cs', "
                "'jq .scripts package.json'."
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
            "name": "list_hypotheses",
            "description": (
                "List hypotheses already in the evidence store, with severity, exposure, "
                "entry point and impact. Required for chain composition and deduplication — "
                "never invent a hypothesis ID, always get it from here."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string",
                               "description": "Filter by status, e.g. evidence_supported, reproduced, initial"},
                    "min_priority": {"type": "integer", "description": "Only return priority >= this"},
                    "limit": {"type": "integer", "description": "Max rows (default 40)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_hypothesis",
            "description": (
                "Full detail for one hypothesis including its evidence, proof obligations "
                "and counterevidence. Use before composing it into a chain."
            ),
            "parameters": {
                "type": "object",
                "required": ["hypothesis_id"],
                "properties": {"hypothesis_id": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "resolve_open_question",
            "description": (
                "Close an open question once you have answered it from the code. "
                "Blocking questions suppress findings until resolved, so resolve every "
                "question you can actually answer."
            ),
            "parameters": {
                "type": "object",
                "required": ["question_id", "resolution"],
                "properties": {
                    "question_id": {"type": "string"},
                    "resolution": {"type": "string",
                                   "description": "The answer, citing file:line evidence"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "amend_hypothesis",
            "description": (
                "Adjust an existing hypothesis: raise or lower confidence with a reason, "
                "or link it into a chain via `enables`. Use when your analysis changes "
                "the standing of a finding a previous skill recorded."
            ),
            "parameters": {
                "type": "object",
                "required": ["hypothesis_id", "reason"],
                "properties": {
                    "hypothesis_id": {"type": "string"},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 10},
                    "exposure": {"type": "string",
                                 "enum": ["internet", "authenticated", "internal",
                                          "admin_only", "unreachable"]},
                    "enables": {"type": "array", "items": {"type": "string"},
                                "description": "Hypothesis IDs this one unlocks"},
                    "reason": {"type": "string"},
                },
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


_THREADED_TOOLS = frozenset({
    "read_file", "grep", "list_dir", "parse_file_structure", "find_all_usages",
    "run_semgrep", "shell",
})


_PROMPT_TOOL_NAMES = frozenset({
    "search_graph", "trace_path", "get_code_snippet", "search_code", "query_graph",
    "read_file", "grep", "get_architecture", "list_dir",
    "parse_file_structure", "find_all_usages", "run_semgrep", "shell",
    "list_hypotheses", "get_hypothesis", "get_open_questions",
    "get_return_contracts", "get_function_summary",
})
