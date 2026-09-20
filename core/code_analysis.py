from __future__ import annotations
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

try:
    from tree_sitter import Language, Parser
    from tree_sitter_language_pack import get_language, get_parser
    _HAS_TREE_SITTER = True
except ImportError:
    _HAS_TREE_SITTER = False

_EXT_TO_LANG = {
    ".py": "python",
    ".cs": "c_sharp",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".c": "c",
    ".h": "c",
    ".php": "php",
    ".kt": "kotlin",
    ".swift": "swift",
}

_QUERY_DEFS = {
    "python": """
        (function_definition name: (identifier) @name parameters: (parameters) @params) @func
        (class_definition name: (identifier) @class_name) @cls
    """,
    "c_sharp": """
        (method_declaration name: (identifier) @name) @func
        (class_declaration name: (identifier) @class_name) @cls
        (interface_declaration name: (identifier) @iface_name) @iface
    """,
    "typescript": """
        (function_declaration name: (identifier) @name) @func
        (method_definition key: (property_identifier) @name) @method
        (class_declaration name: (type_identifier) @class_name) @cls
        (interface_declaration name: (type_identifier) @iface_name) @iface
    """,
    "javascript": """
        (function_declaration name: (identifier) @name) @func
        (method_definition key: (property_identifier) @name) @method
        (class_declaration name: (identifier) @class_name) @cls
    """,
    "go": """
        (function_declaration name: (identifier) @name) @func
        (method_declaration name: (field_identifier) @name) @method
        (type_spec name: (type_identifier) @class_name) @cls
    """,
    "java": """
        (method_declaration name: (identifier) @name) @func
        (class_declaration name: (identifier) @class_name) @cls
        (interface_declaration name: (identifier) @iface_name) @iface
    """,
}


def _lang_for_file(file_path: str) -> Optional[str]:
    return _EXT_TO_LANG.get(Path(file_path).suffix.lower())


def parse_file_structure(repo_path: str, file_path: str) -> str:
    repo = Path(repo_path).resolve()
    full = (repo / file_path).resolve()
    try:
        full.relative_to(repo)
    except ValueError:
        return "Access denied"
    if not full.exists():
        return f"File not found: {file_path}"

    lang = _lang_for_file(file_path)
    if not lang or not _HAS_TREE_SITTER:
        data = json.loads(_fallback_structure(full.read_text(errors="replace"), file_path))
        data["_quality"] = {"used_ast": False}
        return json.dumps(data, indent=2)

    try:
        parser = get_parser(lang)
        source = full.read_bytes()
        tree = parser.parse(source)
        data = json.loads(_extract_structure(tree, source, lang, file_path))
        data["_quality"] = {"used_ast": True}
        return json.dumps(data, indent=2)
    except Exception:
        data = json.loads(_fallback_structure(full.read_text(errors="replace"), file_path))
        data["_quality"] = {"used_ast": False, "fallback_reason": "tree-sitter parse error"}
        return json.dumps(data, indent=2)


def _extract_structure(tree: Any, source: bytes, lang: str, file_path: str) -> str:
    lines = source.decode(errors="replace").splitlines()
    results: list[dict] = []

    def walk(node: Any, depth: int = 0):
        if node.type in ("function_definition", "method_declaration", "function_declaration",
                          "method_definition", "constructor_declaration"):
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters") or node.child_by_field_name("formal_parameters")
            name = name_node.text.decode() if name_node else "?"
            params = params_node.text.decode() if params_node else ""
            decorators = []
            prev = node.prev_named_sibling
            while prev and prev.type in ("decorator", "attribute"):
                decorators.insert(0, lines[prev.start_point[0]].strip())
                prev = prev.prev_named_sibling
            results.append({
                "kind": "function",
                "name": name,
                "signature": f"{name}{params}",
                "line_start": start,
                "line_end": end,
                "decorators": decorators,
            })
        elif node.type in ("class_declaration", "class_definition", "interface_declaration",
                            "interface_definition", "struct_item"):
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else "?"
            bases_node = node.child_by_field_name("bases") or node.child_by_field_name("superclasses")
            bases = bases_node.text.decode() if bases_node else ""
            results.append({
                "kind": "class",
                "name": name,
                "bases": bases,
                "line_start": start,
                "line_end": end,
            })
        for child in node.children:
            walk(child, depth + 1)

    walk(tree.root_node)
    return json.dumps({"file": file_path, "symbols": results}, indent=2)


def _fallback_structure(source: str, file_path: str) -> str:
    patterns = [
        (r"^\s*(?:public|private|protected|internal|static|async|override|virtual)?\s*"
         r"(?:class|interface|record|struct)\s+(\w+)", "class"),
        (r"^\s*(?:public|private|protected|internal|static|async|override|virtual|abstract)?\s*"
         r"\w[\w<>\[\],\s]*\s+(\w+)\s*\(", "function"),
        (r"^\s*def\s+(\w+)\s*\(", "function"),
        (r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(", "function"),
        (r"^\s*(?:func)\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(", "function"),
    ]
    results = []
    for i, line in enumerate(source.splitlines(), 1):
        for pattern, kind in patterns:
            m = re.match(pattern, line)
            if m:
                results.append({"kind": kind, "name": m.group(1), "line_start": i})
                break
    return json.dumps({"file": file_path, "symbols": results}, indent=2)


def find_all_usages(repo_path: str, symbol_name: str,
                    file_glob: Optional[str] = None, max_matches: int = 100) -> str:
    safe = re.escape(symbol_name)
    combined = rf'(?:\b{safe}\b|\.{safe}\b|>{safe}\b)'
    search_path = repo_path
    try:
        cmd = ["rg", "--line-number", "--no-heading", "-m", str(max_matches + 1)]
        if file_glob:
            cmd.extend(["-g", file_glob])
        cmd.extend([combined, search_path])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw_lines = [l for l in r.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        raw_lines = []
        for pat in [rf'\b{safe}\b', rf'\.{safe}\b', rf'>{safe}\b']:
            partial = _rg_grep(repo_path, pat, None, file_glob, max_matches // 3)
            raw_lines.extend(l for l in partial.splitlines() if l.strip())
    seen: set[str] = set()
    deduped: list[str] = []
    for line in raw_lines:
        parts = line.split(':', 2)
        key = ':'.join(parts[:2]) if len(parts) >= 2 else line
        if key not in seen:
            seen.add(key)
            deduped.append(line)
    truncated = len(deduped) > max_matches
    out = "\n".join(deduped[:max_matches])
    if truncated:
        out += "\n[TRUNCATED]"
    return out


def _rg_grep(repo_path: str, pattern: str, path: Optional[str] = None,
             file_glob: Optional[str] = None, max_matches: int = 100) -> str:
    search_path = str(Path(repo_path) / path) if path else repo_path
    try:
        cmd = ["rg", "--line-number", "--no-heading", f"-m{max_matches}"]
        if file_glob:
            cmd.extend(["-g", file_glob])
        cmd.extend([pattern, search_path])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return r.stdout[:12000]
    except FileNotFoundError:
        cmd = ["grep", "-rn", pattern, search_path]
        if file_glob:
            cmd = ["grep", "-rn", "--include", file_glob, pattern, search_path]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return r.stdout[:12000]
        except Exception:
            return ""
    except Exception:
        return ""


def run_semgrep(repo_path: str, pattern: str, language: Optional[str] = None,
                rules: Optional[str] = None) -> str:
    try:
        cmd = ["semgrep", "--json", "--no-git-ignore"]
        if rules:
            cmd.extend(["--config", rules])
        elif pattern:
            cmd.extend(["--pattern", pattern])
            if language:
                cmd.extend(["--lang", language])
        cmd.append(repo_path)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode not in (0, 1):
            return f"semgrep error: {r.stderr[:500]}"
        try:
            data = json.loads(r.stdout)
            findings = data.get("results", [])
            if not findings:
                return "No semgrep findings"
            out = []
            for f in findings[:50]:
                loc = f"{f['path']}:{f['start']['line']}"
                msg = f.get("extra", {}).get("message", "")
                code = f.get("extra", {}).get("lines", "")
                out.append(f"{loc}: {msg}\n  {code.strip()}")
            return "\n".join(out)
        except json.JSONDecodeError:
            return r.stdout[:5000]
    except FileNotFoundError:
        return "semgrep not installed — skipping"
    except Exception as ex:
        return f"semgrep error: {ex}"


_SHELL_WHITELIST = {
    "find", "tree", "git", "wc", "head", "tail", "sort", "uniq", "cut", "awk",
    "jq", "yq", "file", "strings", "xxd", "hexdump", "base64", "diff", "stat",
    "md5sum", "sha256sum", "sha1sum", "openssl", "xargs", "tr", "sed",
}

_GIT_SAFE_SUBCOMMANDS = {
    "log", "blame", "diff", "show", "grep", "shortlog", "ls-files",
    "ls-tree", "rev-parse", "status", "describe", "cat-file",
    "check-ignore", "count-objects",
}

_FIND_BLOCKED_FLAGS = {"-exec", "-execdir", "-delete", "-ok", "-okdir"}

_SAFE_ENV = {"GIT_TERMINAL_PROMPT": "0"}
_ENV_PASSTHROUGH = {"PATH", "HOME", "LANG", "LC_ALL", "TZ"}


def run_shell(repo_path: str, command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError as ex:
        return f"Parse error: {ex}"
    if not parts:
        return "Empty command"
    if any(p in ("|", "||", "&&", ";", "`") for p in parts):
        return "Shell operators (|, &&, ;) not allowed in commands"
    binary = Path(parts[0]).name
    if binary not in _SHELL_WHITELIST:
        return (f"Command '{binary}' not in whitelist. "
                f"Allowed: {', '.join(sorted(_SHELL_WHITELIST))}")
    if binary == "git":
        sub = parts[1] if len(parts) > 1 else ""
        if sub.startswith("-"):
            sub = ""
        if sub not in _GIT_SAFE_SUBCOMMANDS:
            return (f"git subcommand '{sub or '(none)'}' not allowed. "
                    f"Allowed: {', '.join(sorted(_GIT_SAFE_SUBCOMMANDS))}")
    if binary == "find":
        blocked = [a for a in parts[1:] if a in _FIND_BLOCKED_FLAGS]
        if blocked:
            return f"find flag(s) {blocked} not allowed (can execute processes or delete files)"
    if binary == "sed":
        return "sed is blocked; use read_file with line ranges or parse_file_structure"
    if binary == "awk":
        return "awk is blocked; use sqz_grep, find_all_usages, or parse_file_structure"
    _XARGS_SAFE = {
        "grep", "rg", "wc", "head", "tail", "file",
        "stat", "sha256sum", "md5sum", "sha1sum",
    }
    if binary == "xargs":
        sub_tokens = [p for p in parts[1:] if not p.startswith("-")]
        if sub_tokens:
            xsub = Path(sub_tokens[0]).name
            if xsub not in _XARGS_SAFE:
                return (
                    f"xargs with '{xsub}' not allowed. "
                    f"Safe: {', '.join(sorted(_XARGS_SAFE))}"
                )
    resolved = shutil.which(binary)
    if resolved is None:
        return f"Command '{binary}' not found in PATH"
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
    env.update(_SAFE_ENV)
    try:
        r = subprocess.run(
            [resolved] + parts[1:],
            shell=False,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        out = r.stdout + r.stderr
        return out[:15000] or "(no output)"
    except subprocess.TimeoutExpired:
        return "Command timed out (30s)"
    except Exception as ex:
        return f"Error: {ex}"


def list_dir(repo_path: str, rel_path: str = "", max_entries: int = 80) -> str:
    repo = Path(repo_path).resolve()
    target = (repo / rel_path).resolve() if rel_path else repo
    try:
        target.relative_to(repo)
    except ValueError:
        return "Access denied"
    if not target.exists():
        return f"Path not found: {rel_path}"
    skip = {"node_modules", ".git", "obj", "bin", "__pycache__", "dist", "build",
            ".vs", "vendor", "target", "generated"}
    lines = []
    try:
        for item in sorted(target.iterdir()):
            if item.name in skip:
                continue
            suffix = "/" if item.is_dir() else ""
            rel = str(item.relative_to(repo))
            size = "" if item.is_dir() else f"  ({item.stat().st_size:,}B)"
            lines.append(f"{rel}{suffix}{size}")
            if len(lines) >= max_entries:
                lines.append("... (truncated)")
                break
    except PermissionError:
        return f"Permission denied: {rel_path}"
    return "\n".join(lines) or "(empty)"
