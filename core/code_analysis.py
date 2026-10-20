from __future__ import annotations
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

try:
    from tree_sitter_language_pack import get_parser
    _HAS_TREE_SITTER = True
except ImportError:
    _HAS_TREE_SITTER = False

_EXT_TO_LANG = {
    ".py": "python",
    ".cs": "csharp",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".php": "php",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
}

_GRAMMAR_DOWNLOAD_TIMEOUT = 20
_MAX_FALLBACK_LINE = 400
_unavailable_grammars: set[str] = set()
_grammar_lock = threading.Lock()

_FUNCTION_NODES = {
    "function_definition", "method_declaration", "function_declaration",
    "method_definition", "constructor_declaration", "function_item",
    "method", "singleton_method", "local_function_statement",
}
_CLASS_NODES = {
    "class_declaration", "class_definition", "interface_declaration",
    "interface_definition", "struct_item", "enum_item", "trait_item", "impl_item",
    "class", "module", "class_specifier", "struct_specifier", "type_spec",
    "struct_declaration", "record_declaration", "enum_declaration",
    "object_declaration", "protocol_declaration", "trait_declaration",
}
_NAME_NODES = {
    "identifier", "field_identifier", "type_identifier", "qualified_identifier",
    "destructor_name", "operator_name", "simple_identifier", "name", "constant",
    "property_identifier", "scoped_identifier",
}
_PARAM_NODES = {
    "parameter_list", "formal_parameters", "function_value_parameters",
    "method_parameters", "parameters",
}
_DECORATOR_SIBLINGS = {"decorator", "attribute", "attribute_item", "attribute_list"}
_DECORATOR_CHILDREN = {"attribute_list", "decorator", "attributes"}
_ANNOTATION_NODES = {"annotation", "marker_annotation", "attribute"}


def _lang_for_file(file_path: str) -> Optional[str]:
    return _EXT_TO_LANG.get(Path(file_path).suffix.lower())


def _get_ts_parser(lang: str):
    if not _HAS_TREE_SITTER or lang in _unavailable_grammars:
        return None
    try:
        import tree_sitter_language_pack as pack
        with _grammar_lock:
            downloaded = set(pack.downloaded_languages() or [])
            if lang not in downloaded and hasattr(pack, "download"):
                pool = ThreadPoolExecutor(max_workers=1)
                future = pool.submit(pack.download, [lang])
                try:
                    future.result(timeout=_GRAMMAR_DOWNLOAD_TIMEOUT)
                except Exception:
                    _unavailable_grammars.add(lang)
                    return None
                finally:
                    pool.shutdown(wait=False)
        return get_parser(lang)
    except Exception:
        _unavailable_grammars.add(lang)
        return None


def parse_file_structure(repo_path: str, file_path: str) -> str:
    repo = Path(repo_path).resolve()
    full = (repo / file_path).resolve()
    try:
        full.relative_to(repo)
    except ValueError:
        return json.dumps({"file": file_path, "symbols": [], "error": "Access denied: path outside repository"})
    if not full.is_file():
        return json.dumps({"file": file_path, "symbols": [], "error": f"File not found: {file_path}"})

    lang = _lang_for_file(file_path)
    parser = _get_ts_parser(lang) if lang else None
    if parser is None:
        data = json.loads(_fallback_structure(full.read_text(errors="replace"), file_path))
        reason = ("no tree-sitter grammar for this file type" if not lang
                  else f"tree-sitter grammar for {lang} unavailable")
        data["_quality"] = {"used_ast": False, "fallback_reason": reason}
        return json.dumps(data, indent=2)

    try:
        source = full.read_bytes()
        tree = parser.parse(source)
        data = json.loads(_extract_structure(tree, source, lang, file_path))
    except Exception:
        data = json.loads(_fallback_structure(full.read_text(errors="replace"), file_path))
        data["_quality"] = {"used_ast": False, "fallback_reason": "tree-sitter parse error"}
        return json.dumps(data, indent=2)
    if not data["symbols"]:
        fallback = json.loads(_fallback_structure(source.decode(errors="replace"), file_path))
        if fallback["symbols"]:
            fallback["_quality"] = {"used_ast": False,
                                    "fallback_reason": f"no symbols extracted from the {lang} AST"}
            return json.dumps(fallback, indent=2)
    data["_quality"] = {"used_ast": True}
    return json.dumps(data, indent=2)


def _node_text(node: Any, limit: int = 200) -> str:
    text = node.text.decode(errors="replace") if node.text else ""
    return " ".join(text.split())[:limit]


def _declarator_name(node: Any) -> Optional[Any]:
    current = node
    for _ in range(8):
        if current is None:
            return None
        if current.type in _NAME_NODES:
            return current
        nxt = current.child_by_field_name("declarator") or current.child_by_field_name("name")
        if nxt is None:
            nxt = next((c for c in current.named_children if c.type in _NAME_NODES), None)
        current = nxt
    return None


def _symbol_name(node: Any) -> str:
    name_node = node.child_by_field_name("name")
    if name_node is None and node.type == "impl_item":
        name_node = node.child_by_field_name("type")
    if name_node is None:
        name_node = _declarator_name(node.child_by_field_name("declarator"))
    if name_node is None:
        name_node = next((c for c in node.named_children if c.type in _NAME_NODES), None)
    return _node_text(name_node, 120) if name_node is not None else "?"


def _params_node(node: Any) -> Optional[Any]:
    found = node.child_by_field_name("parameters") or node.child_by_field_name("formal_parameters")
    if found is not None:
        return found
    declarator = node.child_by_field_name("declarator")
    for _ in range(8):
        if declarator is None:
            break
        found = declarator.child_by_field_name("parameters")
        if found is not None:
            return found
        declarator = declarator.child_by_field_name("declarator")
    return next((c for c in node.named_children if c.type in _PARAM_NODES), None)


def _decorators(node: Any) -> list[str]:
    found: list[str] = []
    prev = node.prev_named_sibling
    while prev is not None and prev.type in _DECORATOR_SIBLINGS:
        found.insert(0, _node_text(prev, 160))
        prev = prev.prev_named_sibling
    for child in node.named_children:
        if child.type in _DECORATOR_CHILDREN:
            found.append(_node_text(child, 160))
        elif child.type == "modifiers":
            found.extend(_node_text(m, 160) for m in child.named_children
                         if m.type in _ANNOTATION_NODES)
    return found


def _extract_structure(tree: Any, source: bytes, lang: str, file_path: str) -> str:
    results: list[dict] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if not node.is_named:
            continue
        if node.type in _FUNCTION_NODES:
            name = _symbol_name(node)
            params_node = _params_node(node)
            params = _node_text(params_node, 300) if params_node is not None else ""
            results.append({
                "kind": "function",
                "name": name,
                "signature": f"{name}{params}",
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "decorators": _decorators(node),
            })
        elif node.type in _CLASS_NODES and not (
                node.type == "module" and node.child_by_field_name("name") is None):
            bases_node = node.child_by_field_name("bases") or node.child_by_field_name("superclasses") \
                or node.child_by_field_name("superclass")
            results.append({
                "kind": "class",
                "name": _symbol_name(node),
                "bases": _node_text(bases_node, 200) if bases_node is not None else "",
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "decorators": _decorators(node),
            })
        stack.extend(reversed(node.named_children))
    return json.dumps({"file": file_path, "symbols": results}, indent=2)


_NOT_FUNCTION_NAMES = {
    "if", "for", "foreach", "while", "switch", "catch", "return", "new", "else", "using",
    "lock", "sizeof", "typeof", "nameof", "when", "throw", "await", "yield", "function",
    "elif", "with", "assert", "print", "delete", "case", "do", "try", "fixed", "checked",
}
_FALLBACK_PATTERNS = [
    (re.compile(r"^\s*(?:(?:public|private|protected|internal|static|abstract|sealed|final|partial|export|default)\s+)*"
                r"(?:class|interface|record|struct|enum|trait|module|object)\s+(\w+)"), "class"),
    (re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("), "function"),
    (re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\("), "function"),
    (re.compile(r"^\s*func\s+(?:\(\s*\w+\s+\*?[\w.]+\s*\)\s+)?(\w+)\s*[\[(]"), "function"),
    (re.compile(r"^\s*(?:pub(?:\([\w ]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)"), "function"),
    (re.compile(r"^\s*(?:(?:public|private|protected|internal|static|abstract|final|override|open|suspend)\s+)*fun\s+(?:<[^>]*>\s*)?(?:\w+\.)?(\w+)\s*\("), "function"),
    (re.compile(r"^\s*(?:(?:public|private|protected|static|abstract|final)\s+)*function\s+&?\s*(\w+)\s*\("), "function"),
    (re.compile(r"^[ \t]*(?:[\w<>\[\],.?*&:]+[ \t]+)+(\w+)[ \t]*\([^;]*$"), "function"),
]


def _fallback_structure(source: str, file_path: str) -> str:
    results = []
    for i, line in enumerate(source.splitlines(), 1):
        if len(line) > _MAX_FALLBACK_LINE or not line.strip():
            continue
        stripped = line.lstrip()
        first = stripped.split(None, 1)[0] if stripped else ""
        if first in _NOT_FUNCTION_NAMES or first.startswith(("//", "#", "*", "/*")):
            continue
        for pattern, kind in _FALLBACK_PATTERNS:
            m = pattern.match(line)
            if m and m.group(1) not in _NOT_FUNCTION_NAMES:
                results.append({"kind": kind, "name": m.group(1), "line_start": i})
                break
    return json.dumps({"file": file_path, "symbols": results}, indent=2)


def find_all_usages(repo_path: str, symbol_name: str,
                    file_glob: Optional[str] = None, max_matches: int = 100) -> str:
    try:
        max_matches = max(1, int(max_matches))
    except (TypeError, ValueError):
        max_matches = 100
    safe = re.escape(symbol_name)
    combined = rf'(?:\b{safe}\b|\.{safe}\b|>{safe}\b)'
    try:
        cmd = ["rg", "--line-number", "--no-heading", "-m", str(max_matches + 1)]
        if file_glob:
            cmd.extend(["-g", file_glob])
        cmd.extend(["-e", combined, "--", repo_path])
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=20, stdin=subprocess.DEVNULL)
        raw_lines = [l for l in r.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        raw_lines = []
        per_pattern = max(1, max_matches // 3)
        for pat in [rf'\b{safe}\b', rf'\.{safe}\b', rf'>{safe}\b']:
            partial = _rg_grep(repo_path, pat, None, file_glob, per_pattern)
            raw_lines.extend(l for l in partial.splitlines() if l.strip())
    except subprocess.TimeoutExpired as ex:
        partial = ex.stdout.decode(errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        raw_lines = [l for l in partial.splitlines() if l.strip()]
        raw_lines.append("[TRUNCATED]")
    seen: set[str] = set()
    deduped: list[str] = []
    for line in raw_lines:
        if line == "[TRUNCATED]":
            continue
        parts = line.split(':', 2)
        key = ':'.join(parts[:2]) if len(parts) >= 2 else line
        if key not in seen:
            seen.add(key)
            deduped.append(line)
    truncated = len(deduped) > max_matches or "[TRUNCATED]" in raw_lines
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
        cmd.extend(["-e", pattern, "--", search_path])
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=20, stdin=subprocess.DEVNULL)
        return r.stdout[:12000]
    except FileNotFoundError:
        cmd = ["grep", "-rn", f"-m{max_matches}"]
        if file_glob:
            cmd.extend(["--include", file_glob])
        cmd.extend(["-e", pattern, "--", search_path])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                               timeout=20, stdin=subprocess.DEVNULL)
            return r.stdout[:12000]
        except Exception:
            return ""
    except Exception:
        return ""


_SEMGREP_REGISTRY = re.compile(r"^(p|r|s)/[\w.\-/]+$")


def run_semgrep(repo_path: str, pattern: str, language: Optional[str] = None,
                rules: Optional[str] = None) -> str:
    repo = Path(repo_path).resolve()
    cmd = ["semgrep", "--json", "--no-git-ignore", "--metrics=off", "--disable-version-check"]
    if rules:
        rules = str(rules).strip()
        if _SEMGREP_REGISTRY.match(rules):
            cmd.extend(["--config", rules])
        else:
            rule_path = (repo / rules).resolve()
            try:
                rule_path.relative_to(repo)
            except ValueError:
                return "semgrep rules must be a registry id (p/..., r/..., s/...) or a rule file inside the repository"
            if not rule_path.is_file():
                return f"semgrep rule file not found: {rules}"
            cmd.extend(["--config", str(rule_path)])
    elif pattern:
        if not language:
            return "semgrep: a pattern needs a language (e.g. language=\"python\")"
        cmd.extend(["--pattern", pattern, "--lang", str(language)])
    else:
        return "semgrep: pass a pattern with a language, or rules"
    cmd.append(str(repo))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=60, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return "semgrep not installed — skipping"
    except subprocess.TimeoutExpired:
        return "semgrep timed out (60s); narrow the pattern or rules"
    except Exception as ex:
        return f"semgrep error: {ex}"
    if r.returncode not in (0, 1):
        return f"semgrep error: {r.stderr[:500]}"
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return r.stdout[:5000]
    findings = data.get("results", [])
    if not findings:
        return "No semgrep findings"
    out = []
    for f in findings[:50]:
        path = str(f.get("path", "?"))
        try:
            path = Path(path).resolve().relative_to(repo).as_posix()
        except (ValueError, OSError):
            pass
        loc = f"{path}:{f.get('start', {}).get('line', '?')}"
        msg = f.get("extra", {}).get("message", "")
        code = f.get("extra", {}).get("lines", "")
        out.append(f"{loc}: {msg}\n  {code.strip()}")
    return "\n".join(out)


SHELL_ALLOWED_BINARIES = (
    "git", "find", "tree", "wc", "head", "tail", "file", "stat",
    "sha256sum", "sha1sum", "md5sum", "jq", "diff", "strings", "cut",
)
_SHELL_WHITELIST = set(SHELL_ALLOWED_BINARIES)

GIT_ALLOWED_SUBCOMMANDS = (
    "log", "show", "blame", "diff", "ls-files", "ls-tree", "rev-parse",
    "status", "shortlog", "describe", "grep",
)
_GIT_SAFE_SUBCOMMANDS = set(GIT_ALLOWED_SUBCOMMANDS)
_GIT_DENIED_OPTIONS = (
    "--output", "--open-files-in-pager", "-O", "--ext-diff", "--textconv",
    "--no-index", "--exec", "--upload-pack", "--receive-pack", "--git-dir",
    "--work-tree", "--paginate", "-p--",
)
_GIT_HARDENING = [
    "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=",
    "-c", "log.showSignature=false", "-c", "core.hooksPath=/dev/null", "--no-pager",
]
_GIT_NO_EXTERNAL = {"log", "show", "diff"}

_FIND_ALLOWED = {
    "-name", "-iname", "-path", "-ipath", "-wholename", "-type", "-maxdepth", "-mindepth",
    "-newer", "-mtime", "-mmin", "-size", "-empty", "-not", "!", "-o", "-a", "-or", "-and",
    "(", ")", "-print", "-regex", "-iregex", "-prune", "-xtype",
}
_TREE_ALLOWED = {"-a", "-d", "-f", "-L", "-I", "-P", "-i", "-F", "--noreport", "--dirsfirst", "--charset"}
_FOLLOW_OPTIONS = {"-f", "-F", "--follow", "--retry"}

_SAFE_ENV = {
    "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_PAGER": "cat", "PAGER": "cat", "GIT_OPTIONAL_LOCKS": "0",
}
_ENV_PASSTHROUGH = {"PATH", "HOME", "LANG", "LC_ALL", "TZ"}


def _shell_path_candidates(arg: str) -> list[str]:
    if arg in ("-", "--") or not arg:
        return []
    if arg.startswith("--"):
        return [arg.split("=", 1)[1]] if "=" in arg else []
    if arg.startswith("-"):
        return [arg[2:]] if len(arg) > 2 else []
    return [arg]


def _shell_inside_repo(repo: Path, candidate: str) -> bool:
    if not candidate:
        return True
    path = Path(candidate) if os.path.isabs(candidate) else repo / candidate
    try:
        path.resolve().relative_to(repo)
        return True
    except (ValueError, OSError):
        return False


def _check_shell_command(repo: Path, binary: str, args: list[str]) -> Optional[str]:
    if binary == "git":
        sub = args[0] if args else ""
        if sub not in _GIT_SAFE_SUBCOMMANDS:
            return (f"git subcommand '{sub or '(none)'}' not allowed. "
                    f"Allowed: {', '.join(GIT_ALLOWED_SUBCOMMANDS)}")
        for a in args[1:]:
            if any(a == d or a.startswith(d + "=") or (d.startswith("--") and a.startswith(d))
                   for d in _GIT_DENIED_OPTIONS):
                return f"git option {a!r} is not allowed (writes files, runs programs or reads outside the repository)"
    elif binary == "find":
        for a in args:
            if a.startswith("-") or a in ("!", "(", ")"):
                if a not in _FIND_ALLOWED:
                    return f"find option {a!r} is not allowed; allowed: {', '.join(sorted(_FIND_ALLOWED))}"
    elif binary == "tree":
        for a in args:
            if a.startswith("-") and a.split("=", 1)[0] not in _TREE_ALLOWED:
                return f"tree option {a!r} is not allowed"
    elif binary in ("head", "tail"):
        for a in args:
            if a in _FOLLOW_OPTIONS or a.startswith("--follow"):
                return f"{binary} {a} is not allowed (it never terminates)"
    for a in args:
        for candidate in _shell_path_candidates(a):
            if not _shell_inside_repo(repo, candidate):
                return f"argument {a!r} refers to a path outside the repository"
    return None


def run_shell(repo_path: str, command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError as ex:
        return f"Parse error: {ex}"
    if not parts:
        return "Empty command"
    if any(p in ("|", "||", "&&", ";", "&", "`", ">", ">>", "<", "<<") for p in parts) \
            or any(ch in command for ch in ("`", "$(", "\n")):
        return "Shell operators (pipes, redirection, command substitution, ;, &&) are not allowed"
    if "/" in parts[0]:
        return "Give the command name only, without a path"
    binary = parts[0]
    if binary not in _SHELL_WHITELIST:
        return (f"Command '{binary}' not allowed. "
                f"Allowed: {', '.join(SHELL_ALLOWED_BINARIES)}")
    repo = Path(repo_path).resolve()
    args = parts[1:]
    problem = _check_shell_command(repo, binary, args)
    if problem:
        return problem
    resolved = shutil.which(binary)
    if resolved is None:
        return f"Command '{binary}' not found in PATH"
    argv = [resolved] + args
    if binary == "git":
        sub = args[0]
        extra = ["--no-ext-diff", "--no-textconv"] if sub in _GIT_NO_EXTERNAL else []
        argv = [resolved] + _GIT_HARDENING + [sub] + extra + args[1:]
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
    env.update(_SAFE_ENV)
    try:
        r = subprocess.run(
            argv,
            shell=False,
            cwd=str(repo),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            env=env,
            stdin=subprocess.DEVNULL,
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
    if target.is_file():
        return f"Not a directory: {rel_path}"
    skip = {"node_modules", ".git", "obj", "bin", "__pycache__", "dist", "build",
            ".vs", "vendor", "target", "generated"}
    try:
        max_entries = max(1, int(max_entries))
    except (TypeError, ValueError):
        max_entries = 80
    lines = []
    try:
        for item in sorted(target.iterdir()):
            if item.name in skip:
                continue
            is_dir = item.is_dir()
            suffix = "/" if is_dir else ""
            rel = str(item.relative_to(repo))
            if is_dir:
                size = ""
            else:
                try:
                    size = f"  ({item.stat().st_size:,}B)"
                except OSError:
                    size = "  (broken link)"
            lines.append(f"{rel}{suffix}{size}")
            if len(lines) >= max_entries:
                lines.append("... (truncated)")
                break
    except PermissionError:
        return f"Permission denied: {rel_path}"
    return "\n".join(lines) or "(empty)"
