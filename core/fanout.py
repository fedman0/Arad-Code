from __future__ import annotations
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .models import EntryPoint
from .peer_analysis import _is_generic, _normalize_path

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_ANY_WORDS = ("ANY", "ALL", "USE")
_VERB = r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY|ALL|USE)"
_VERB_PREFIX = re.compile(rf"^\s*(?:{_VERB}(?:\s*[|,/&+]\s*{_VERB})*\s+)+", re.I)
_ROUTE_QN = re.compile(r"__route__([A-Z]+)__(.*)$")
_OPTIONAL = re.compile(r"^(.*?)\[(/.+?)\](.*)$")
_NON_ROUTE_KINDS = ("consumer", "job", "command", "hook", "callback")
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "e2e", "cypress",
                        "__mocks__", "testing"})
_TEST_FILE = re.compile(r"(?:^test_|[._-](?:test|spec)s?\.[a-z0-9]+$)")
GRAPH_ROUTES_QUERY = ("MATCH (s)-[:CALLS|HANDLES]->(r:Route) "
                      "RETURN DISTINCT r.qualified_name AS qn, s.file_path AS src, s.is_test AS test")


def _label(text: str) -> str:
    text = (text or "").split(" | ", 1)[0]
    text = re.sub(r"\([^)]*\)", " ", text)
    return " ".join(text.split()).strip(" .,;:").lower()


@dataclass(frozen=True)
class Target:
    kind: str
    method: str
    path: str
    handler: str = ""
    file_path: str = ""
    line: int = 0
    source: str = "p1"

    @property
    def name(self) -> str:
        if self.kind == "route":
            return f"{self.method} {self.path}"
        return f"{self.kind} {self.path}"

    @property
    def key(self) -> tuple[str, str, str]:
        if self.kind == "route":
            return (self.kind, self.method, _normalize_path(self.path))
        return (self.kind, "", _label(self.path))


def is_test_path(path: str) -> bool:
    parts = [p for p in re.split(r"[\\/]+", (path or "").lower()) if p]
    if not parts:
        return False
    if any(p in _TEST_DIRS for p in parts[:-1]):
        return True
    return bool(_TEST_FILE.search(parts[-1]))


def route_methods(raw: Optional[str], path: str = "") -> list[str]:
    found = [t.upper() for t in re.findall(r"[A-Za-z]+", raw or "") if t.upper() in HTTP_METHODS]
    prefix = _VERB_PREFIX.match(path or "")
    if prefix:
        found += [t.upper() for t in re.findall(r"[A-Za-z]+", prefix.group(0))
                  if t.upper() in HTTP_METHODS]
    return list(dict.fromkeys(found)) or ["ANY"]


def normalize_method(raw: Optional[str], path: str = "") -> str:
    return route_methods(raw, path)[0]


def _expand_optional(token: str) -> list[str]:
    m = _OPTIONAL.match(token)
    if not m:
        return [token]
    return [m.group(1) + m.group(3), m.group(1) + m.group(2) + m.group(3)]


def route_paths(text: Optional[str]) -> list[str]:
    body = _VERB_PREFIX.sub("", (text or "").strip())
    body = re.sub(r"\([^)]*\)", " ", body.split(" | ", 1)[0])
    out: list[str] = []
    for i, token in enumerate(t for t in re.split(r"[,\s]+", body) if t):
        token = token.strip("\"'`").rstrip(",;.")
        if token == "*":
            token = "/*"
        if not token or "://" in token:
            continue
        if not token.startswith("/"):
            if i or "/" not in token:
                continue
            token = "/" + token
        for path in _expand_optional(token):
            path = path.replace("//", "/") or "/"
            if path not in out:
                out.append(path)
    return out


def normalize_route_path(path: Optional[str]) -> str:
    paths = route_paths(path)
    return paths[0] if paths else ""


def _from_entry_point(ep: EntryPoint) -> list[Target]:
    if ep.kind == "route":
        return [Target("route", method, path, ep.handler_qn or "", ep.file_path or "",
                       int(ep.line or 0), "p1")
                for path in route_paths(ep.path)
                for method in route_methods(ep.method, ep.path)]
    path = " ".join((ep.path or "").split())
    if not _label(path):
        return []
    return [Target(ep.kind, "", path, ep.handler_qn or "", ep.file_path or "", int(ep.line or 0), "p1")]


def _is_true(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("true", "1")


def parse_graph_routes(result: Any) -> list[tuple[str, str, str]]:
    rows: list = []
    if isinstance(result, dict):
        rows = result.get("rows") or []
    out: list[tuple[str, str, str]] = []
    for row in rows:
        if not isinstance(row, (list, tuple)) or not row:
            continue
        m = _ROUTE_QN.search(str(row[0]))
        if not m:
            continue
        src = str(row[1]) if len(row) > 1 and row[1] else ""
        if (len(row) > 2 and _is_true(row[2])) or is_test_path(src):
            continue
        method = m.group(1).upper()
        method = method if method in HTTP_METHODS else "ANY"
        path = normalize_route_path(m.group(2))
        if path:
            out.append((method, path, src))
    return out


def _richness(t: Target) -> tuple[int, int, int]:
    return (1 if t.line else 0, 1 if t.file_path else 0, len(t.handler))


def inventory(entry_points: Iterable[EntryPoint],
              graph_routes: Iterable[tuple[str, str, str]] = ()) -> list[Target]:
    best: dict[tuple[str, str, str], Target] = {}
    for ep in entry_points:
        for t in _from_entry_point(ep):
            old = best.get(t.key)
            if old is None or _richness(t) > _richness(old):
                best[t.key] = t
    graph = [Target("route", method, path, "", src, 0, "graph") for method, path, src in graph_routes]
    weight = Counter(src for _, src in {(t.key, t.file_path) for t in graph} if src)
    for t in sorted(graph, key=lambda g: (-weight[g.file_path], g.file_path)):
        best.setdefault(t.key, t)
    richest: dict[str, tuple[int, int, int]] = {}
    for k, t in best.items():
        if k[0] == "route" and k[1] != "ANY":
            richest[k[2]] = max(richest.get(k[2], (-1, -1, -1)), _richness(t))
    targets = [t for k, t in best.items()
               if not (k[0] == "route" and k[1] == "ANY" and k[2] in richest
                       and richest[k[2]] > _richness(t))]
    return sorted(targets, key=lambda t: (t.kind, _normalize_path(t.path) if t.kind == "route" else t.path, t.method))


def cluster(t: Target) -> str:
    if t.kind != "route":
        return t.kind
    literal = [s for s in _normalize_path(t.path).strip("/").split("/") if s and s != "*"]
    meaningful = [s for s in literal if not _is_generic(s)]
    seg = meaningful[0] if meaningful else (literal[0] if literal else "")
    return f"route:/{seg}"


def make_batches(targets: list[Target], size: int) -> list[list[Target]]:
    size = max(1, int(size))
    groups: dict[str, list[Target]] = {}
    for t in targets:
        groups.setdefault(cluster(t), []).append(t)
    out: list[list[Target]] = []
    current: list[Target] = []
    for key in sorted(groups):
        members = groups[key]
        for i in range(0, len(members), size):
            chunk = members[i:i + size]
            if len(chunk) == size:
                out.append(chunk)
                continue
            if current and len(current) + len(chunk) > size:
                out.append(current)
                current = []
            current.extend(chunk)
    if current:
        out.append(current)
    return out


def assignment(chunk: list[Target], index: int, total: int) -> str:
    lines = [f"# Assigned entry points (batch {index} of {total})",
             "Review every entry point below. For each one, add a coverage item with kind "
             "\"entry_point\" and name exactly as written before the first \" | \", and status "
             "reported, no_issue_found, ruled_out, not_applicable or needs_follow_up (say why in blocker).",
             ""]
    for t in chunk:
        if t.handler and t.file_path:
            where = f"handler {t.handler} ({t.file_path}" + (f":{t.line})" if t.line else ")")
        elif t.file_path:
            where = f"registered in {t.file_path}; resolve the handler first"
        else:
            where = "handler not resolved; find where it is registered first"
        lines.append(f"- {t.name} | {where} | from {t.source}")
    return "\n".join(lines)


def coverage_key(name: str) -> tuple[str, str, str]:
    text = " ".join((name or "").split())
    for kind in _NON_ROUTE_KINDS:
        if text.lower().startswith(kind + " "):
            return (kind, "", _label(text[len(kind) + 1:]))
    path = normalize_route_path(text)
    return ("route", normalize_method(text.split(" ", 1)[0] if " " in text else "", text),
            _normalize_path(path) if path else "")


def target_from_name(name: str) -> Optional[Target]:
    kind, method, label = coverage_key(name)
    if kind == "route":
        path = normalize_route_path(name)
        return Target("route", method, path, source="an earlier run") if path else None
    text = " ".join((name or "").split())[len(kind) + 1:]
    return Target(kind, "", text, source="an earlier run") if label else None


def _label_matches(target: str, seen: str) -> bool:
    if not target or not seen:
        return False
    if target == seen or seen.startswith(target + " "):
        return True
    return len(seen) >= 6 and target.startswith(seen + " ")


def uncovered(chunk: list[Target], names: Iterable[str]) -> list[Target]:
    names = list(names)
    seen = {coverage_key(n) for n in names}
    any_paths = {k[2] for k in seen if k[0] == "route" and k[1] == "ANY" and k[2]}
    labels = {_label(n) for n in names} | {k[2] for k in seen if k[0] != "route"}
    out = []
    for t in chunk:
        if t.key in seen:
            continue
        if t.kind == "route" and t.key[2] in any_paths:
            continue
        if t.kind != "route" and any(_label_matches(t.key[2], s) for s in labels):
            continue
        out.append(t)
    return out
