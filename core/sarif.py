"""SARIF 2.1.0 export for SAST findings.

Produces GitHub code-scanning compatible SARIF from Hypothesis + Evidence objects.
Only hypotheses with status in {evidence_supported, reproduced, human_confirmed} are included.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from .models import Evidence, Hypothesis

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "hesabo-ai"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_INT_TO_SEVERITY = {
    (9, 10): "critical",
    (7, 8): "high",
    (4, 6): "medium",
    (1, 3): "low",
    (0, 0): "info",
}

_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}

_CWE_TO_STRIDE: dict[str, tuple[str, ...]] = {
    "287": ("S",), "290": ("S",), "306": ("S", "E"), "352": ("T", "S"),
    "384": ("S",), "613": ("S",), "798": ("S", "I"),
    "20": ("T",), "22": ("T", "I"), "73": ("T", "I"), "78": ("T", "E"),
    "79": ("T", "I"), "89": ("T",), "94": ("T", "E"), "434": ("T",),
    "502": ("T", "E"), "611": ("I", "T"), "639": ("E",), "915": ("E", "T"),
    "918": ("T", "I"), "1336": ("T", "E"),
    "117": ("R",), "223": ("R",), "778": ("R",),
    "200": ("I",), "201": ("I",), "209": ("I",), "256": ("I",),
    "311": ("I",), "319": ("I",), "327": ("I",), "522": ("I",), "532": ("I",),
    "400": ("D",), "770": ("D",), "1333": ("D",),
    "269": ("E",), "284": ("E",), "285": ("E",), "639": ("E",),
    "732": ("E",), "862": ("E",), "863": ("E",),
}
_DEFAULT_STRIDE: tuple[str, ...] = ("T", "I")

EXPORT_STATUSES = frozenset({"evidence_supported", "reproduced", "human_confirmed"})
_EMIT_STATUSES = EXPORT_STATUSES


def _int_severity(val: int) -> str:
    for (lo, hi), label in _INT_TO_SEVERITY.items():
        if lo <= val <= hi:
            return label
    return "info"


def _normalise_cwe(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    digits = "".join(c for c in str(raw) if c.isdigit())
    return f"CWE-{digits}" if digits else None


def _stride_for(cwe: Optional[str]) -> tuple[str, ...]:
    if not cwe:
        return _DEFAULT_STRIDE
    digits = "".join(c for c in cwe if c.isdigit())
    return _CWE_TO_STRIDE.get(digits, _DEFAULT_STRIDE)


def _slugify(text: str) -> str:
    chars = [c.lower() if c.isalnum() else "-" for c in text]
    slug = "-".join(p for p in "".join(chars).split("-") if p)
    return slug[:80] or "finding"


def _rule_id(h: Hypothesis) -> str:
    cwe = _normalise_cwe(h.cwe)
    if cwe:
        return cwe
    # the slug is truncated to 80 chars, so two long invariants sharing a prefix
    # collapsed into one rule and inherited the first one's severity and level
    slug = _slugify(h.violated_invariant)
    digest = hashlib.sha256(h.violated_invariant.encode()).hexdigest()[:8]
    return f"{slug}-{digest}"


def _security_severity(h: Hypothesis) -> str:
    return _SEVERITY_TO_SCORE.get(_int_severity(h.severity), "1.0")


def _fingerprint(rule_id: str, file_uri: str, snippet: str) -> str:
    norm = " ".join(snippet.split())
    composite = f"{rule_id}|{file_uri}|{norm}"
    return hashlib.sha256(composite.encode()).hexdigest()[:32]


def repository_uri_from_remote(remote: str) -> str:
    remote = (remote or "").strip()
    if not remote:
        return ""
    port = None
    if "://" in remote:
        try:
            parts = urlsplit(remote)
            host = parts.hostname or ""
            if parts.scheme.lower() in ("http", "https"):
                port = parts.port
        except ValueError:
            return ""
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https", "ssh", "git", "git+ssh", "ssh+git"):
            return ""
        scheme = "http" if scheme == "http" else "https"
        path = parts.path
    else:
        m = re.match(r"^(?:[^@/]+@)?([^/:]+):(.+)$", remote)
        if not m or len(m.group(1)) < 2:
            return ""
        scheme, host, path = "https", m.group(1), m.group(2)
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4].rstrip("/")
    if not host or not path:
        return ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port else host
    return f"{scheme}://{netloc}/{quote(path, safe='/')}"


def _relative_to_root(raw: str, repo_root: Optional[str]) -> str:
    if not raw or not repo_root:
        return raw
    candidate = Path(raw)
    if not candidate.is_absolute():
        return raw
    root = Path(repo_root)
    for base, target in ((root, candidate), (root.resolve(), candidate.resolve())):
        try:
            return target.relative_to(base).as_posix()
        except ValueError:
            continue
    return raw


def _safe_uri(raw: str) -> Optional[str]:
    if not raw:
        return None
    uri = raw.replace("\\", "/")
    while uri.startswith("./"):
        uri = uri[2:]
    while "//" in uri:
        uri = uri.replace("//", "/")
    if not uri or uri.startswith("/") or ".." in uri.split("/"):
        return None
    return uri


def _build_rule(rule_id: str, h: Hypothesis) -> dict[str, Any]:
    cwe = _normalise_cwe(h.cwe)
    severity = _int_severity(h.severity)
    tags: list[str] = ["security"]
    if cwe:
        tags.append(cwe)
    for leg in _stride_for(cwe):
        tags.append(f"stride:{leg}")

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _slugify(h.violated_invariant).replace("-", "_"),
        "shortDescription": {"text": h.violated_invariant[:200]},
        "fullDescription": {"text": h.observable_impact[:1000]},
        "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(severity, "note")},
        "properties": {
            "security-severity": _security_severity(h),
            "tags": tags,
        },
    }
    if cwe:
        digits = "".join(c for c in cwe if c.isdigit())
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{digits}.html"
    return rule


def _build_locations(
    evidence_for_hyp: list[Evidence],
    repo_root: Optional[str] = None,
) -> tuple[list[dict[str, Any]], list[tuple[Evidence, str]]]:
    """Return locations alongside the evidence each one came from.

    The fingerprint has to hash the snippet belonging to the location it
    describes; pairing locations[0] with evidence[0] silently mismatched
    whenever an earlier evidence item had an unusable path.
    """
    locations: list[dict[str, Any]] = []
    used: list[tuple[Evidence, str]] = []
    for ev in evidence_for_hyp:
        uri = _safe_uri(_relative_to_root(ev.file_path, repo_root))
        if not uri:
            continue
        start = max(1, ev.line_start)
        locations.append({
            "physicalLocation": {
                "artifactLocation": {"uri": quote(uri, safe="/"), "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": start,
                    "endLine": max(start, ev.line_end),
                },
            },
        })
        used.append((ev, uri))
    return locations, used


def _synthetic_location() -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": "SECURITY.md", "uriBaseId": "%SRCROOT%"},
        },
    }


def build_sarif(
    hypotheses: list[Hypothesis],
    evidence_items: list[Evidence],
    *,
    commit_sha: str = "",
    repo_url: str = "",
    tool_version: Optional[str] = None,
    repo_root: Optional[str] = None,
) -> dict[str, Any]:
    evidence_by_hyp: dict[str, list[Evidence]] = {}
    for ev in evidence_items:
        evidence_by_hyp.setdefault(ev.hypothesis_id, []).append(ev)

    emitted = [h for h in hypotheses if h.status in EXPORT_STATUSES]
    rule_source: dict[str, Hypothesis] = {}
    for h in emitted:
        rule_id = _rule_id(h)
        current = rule_source.get(rule_id)
        if current is None or h.severity > current.severity:
            rule_source[rule_id] = h
    rule_index_by_id = {rule_id: i for i, rule_id in enumerate(rule_source)}
    rules = [_build_rule(rule_id, h) for rule_id, h in rule_source.items()]
    results: list[dict[str, Any]] = []
    fp_groups: dict[str, list[tuple[int, str, dict[str, Any]]]] = {}

    for h in emitted:
        rule_id = _rule_id(h)

        ev_list = evidence_by_hyp.get(h.id, [])
        locations, located_evidence = _build_locations(ev_list, repo_root)
        is_synthetic = not locations
        if is_synthetic:
            locations = [_synthetic_location()]

        severity = _int_severity(h.severity)
        message_text = (
            f"{h.violated_invariant}\n\n"
            f"Actor: {h.actor} | Entry: {h.entry_point} | "
            f"Impact: {h.observable_impact}"
        )

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index_by_id[rule_id],
            "level": _SEVERITY_TO_LEVEL.get(severity, "note"),
            "message": {"text": message_text},
            "locations": locations,
            "properties": {
                "security-severity": _security_severity(h),
                "hesabo": {
                    "hypothesis_id": h.id,
                    "status": h.status,
                    "severity": h.severity,
                    "confidence": h.confidence,
                    "reachability": h.reachability,
                    "input_control": h.input_control,
                    "skill_source": h.skill_source,
                },
            },
        }
        if is_synthetic:
            result["properties"]["synthetic_location"] = True

        if not is_synthetic:
            first_ev, uri = located_evidence[0]
            fp = _fingerprint(rule_id, uri, first_ev.snippet)
            line = locations[0]["physicalLocation"]["region"]["startLine"]
        else:
            # a finding with no usable location still needs a stable identity,
            # or code scanning reopens it as a new alert on every run
            fp = _fingerprint(rule_id, "", f"{h.entry_point}|{h.violated_invariant}")
            line = 0
        result["partialFingerprints"] = {"primaryLocationLineHash": fp}
        fp_groups.setdefault(fp, []).append((line, h.id, result))

        results.append(result)

    for fp, group in fp_groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda item: (item[0], item[1]))
        for occurrence, (_, _, result) in enumerate(group[1:], start=2):
            result["partialFingerprints"]["primaryLocationLineHash"] = f"{fp}:{occurrence}"

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "rules": rules,
    }
    if tool_version:
        driver["version"] = tool_version

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }

    if repo_url:
        vcs: dict[str, Any] = {"repositoryUri": repo_url}
        if commit_sha:
            vcs["revisionId"] = commit_sha
        run["versionControlProvenance"] = [vcs]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif(
    output_dir: Path,
    hypotheses: list[Hypothesis],
    evidence_items: list[Evidence],
    *,
    commit_sha: str = "",
    repo_url: str = "",
    tool_version: Optional[str] = None,
    filename: str = "findings.sarif",
    repo_root: Optional[str] = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / filename
    doc = build_sarif(
        hypotheses, evidence_items,
        commit_sha=commit_sha, repo_url=repo_url, tool_version=tool_version,
        repo_root=repo_root,
    )
    tmp = out.with_name(f"{out.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        tmp.replace(out)
    finally:
        tmp.unlink(missing_ok=True)
    return out
