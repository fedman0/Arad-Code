from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .models import EntryPoint
from .peer_analysis import _is_generic, _normalize_path

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_ANY_WORDS = ("ANY", "ALL", "USE")
_VERB_PREFIX = re.compile(r"^\s*(?:(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY|ALL|USE)\s+)+", re.I)
_ROUTE_QN = re.compile(r"__route__([A-Z]+)__(.*)$")
GRAPH_ROUTES_QUERY = ("MATCH (s)-[:CALLS|HANDLES]->(r:Route) "
                      "RETURN DISTINCT r.qualified_name AS qn, s.file_path AS src")


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
        return (self.kind, "", " ".join(self.path.split()).lower())


def normalize_method(raw: Optional[str], path: str = "") -> str:
    for token in re.findall(r"[A-Za-z]+", raw or ""):
        if token.upper() in HTTP_METHODS:
            return token.upper()
    m = re.match(r"\s*([A-Za-z]+)\s+/", path or "")
    if m and m.group(1).upper() in HTTP_METHODS:
        return m.group(1).upper()
    return "ANY"


def normalize_route_path(path: Optional[str]) -> str:
    text = _VERB_PREFIX.sub("", (path or "").strip())
    first = text.split()[0] if text.split() else ""
    if first and not first.startswith("/"):
        first = "/" + first
    return first


def _from_entry_point(ep: EntryPoint) -> Optional[Target]:
    if ep.kind == "route":
        path = normalize_route_path(ep.path)
        if not path:
            return None
        return Target("route", normalize_method(ep.method, ep.path), path, ep.handler_qn or "",
                      ep.file_path or "", int(ep.line or 0), "p1")
    path = " ".join((ep.path or "").split())
    if not path:
        return None
    return Target(ep.kind, "", path, ep.handler_qn or "", ep.file_path or "", int(ep.line or 0), "p1")


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
        method = m.group(1).upper()
        method = method if method in HTTP_METHODS else "ANY"
        path = normalize_route_path(m.group(2))
        if path:
            src = str(row[1]) if len(row) > 1 and row[1] else ""
            out.append((method, path, src))
    return out


def _richness(t: Target) -> tuple[int, int, int]:
    return (1 if t.line else 0, 1 if t.file_path else 0, len(t.handler))


def inventory(entry_points: Iterable[EntryPoint],
              graph_routes: Iterable[tuple[str, str, str]] = ()) -> list[Target]:
    best: dict[tuple[str, str, str], Target] = {}
    for ep in entry_points:
        t = _from_entry_point(ep)
        if t is None:
            continue
        old = best.get(t.key)
        if old is None or _richness(t) > _richness(old):
            best[t.key] = t
    for method, path, src in graph_routes:
        t = Target("route", method, path, "", src, 0, "graph")
        best.setdefault(t.key, t)
    specific = {k[2] for k in best if k[0] == "route" and k[1] != "ANY"}
    targets = [t for k, t in best.items() if not (k[0] == "route" and k[1] == "ANY" and k[2] in specific)]
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


def batch_key(skill: str, tag: str, chunk: list[Target]) -> str:
    digest = hashlib.sha1("\n".join(t.name for t in chunk).encode()).hexdigest()[:8]
    return f"{skill}#{tag}-{digest}"


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
    for kind in ("consumer", "job", "command", "hook", "callback"):
        if text.lower().startswith(kind + " "):
            return (kind, "", text[len(kind) + 1:].lower())
    return ("route", normalize_method(text.split(" ", 1)[0] if " " in text else "", text),
            _normalize_path(normalize_route_path(text)))


def uncovered(chunk: list[Target], names: Iterable[str]) -> list[Target]:
    seen = {coverage_key(n) for n in names}
    any_paths = {k[2] for k in seen if k[0] == "route" and k[1] == "ANY"}
    out = []
    for t in chunk:
        if t.key in seen:
            continue
        if t.kind == "route" and t.key[2] in any_paths:
            continue
        out.append(t)
    return out
