"""SARIF 2.1.0 export for SAST findings.

Produces GitHub code-scanning compatible SARIF from Hypothesis + Evidence objects.
Only hypotheses with status in {evidence_supported, reproduced} are included.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

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
    (5, 6): "medium",
    (3, 4): "low",
    (0, 2): "info",
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

_EMIT_STATUSES = {"evidence_supported", "reproduced"}


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
    return _slugify(h.violated_invariant)


def _security_severity(h: Hypothesis) -> str:
    return _SEVERITY_TO_SCORE.get(_int_severity(h.severity), "1.0")


def _fingerprint(rule_id: str, file_uri: str, line: int) -> str:
    composite = f"{rule_id}|{file_uri}|{line}"
    return hashlib.sha256(composite.encode()).hexdigest()


def _safe_uri(raw: str) -> Optional[str]:
    if not raw or ".." in raw or raw.startswith("/"):
        return None
    return raw.replace("\\", "/")


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


def _build_locations(evidence_for_hyp: list[Evidence]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for ev in evidence_for_hyp:
        uri = _safe_uri(ev.file_path)
        if not uri:
            continue
        locations.append({
            "physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": max(1, ev.line_start),
                    "endLine": max(1, ev.line_end),
                },
            },
        })
    return locations


def _synthetic_location() -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": "SECURITY.md"},
        },
    }


def build_sarif(
    hypotheses: list[Hypothesis],
    evidence_items: list[Evidence],
    *,
    commit_sha: str = "",
    repo_url: str = "",
    tool_version: Optional[str] = None,
) -> dict[str, Any]:
    evidence_by_hyp: dict[str, list[Evidence]] = {}
    for ev in evidence_items:
        evidence_by_hyp.setdefault(ev.hypothesis_id, []).append(ev)

    rules_by_id: dict[str, dict[str, Any]] = {}
    rule_index_by_id: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for h in hypotheses:
        if h.status not in _EMIT_STATUSES:
            continue

        rule_id = _rule_id(h)
        if rule_id not in rules_by_id:
            rule_index_by_id[rule_id] = len(rules_by_id)
            rules_by_id[rule_id] = _build_rule(rule_id, h)

        ev_list = evidence_by_hyp.get(h.id, [])
        locations = _build_locations(ev_list)
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

        if locations and not is_synthetic:
            loc = locations[0]
            region = loc.get("physicalLocation", {}).get("region", {})
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            fp = _fingerprint(rule_id, uri, region.get("startLine", 0))
            result["partialFingerprints"] = {"primaryLocationLineHash": fp}

        results.append(result)

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "rules": list(rules_by_id.values()),
    }
    if tool_version:
        driver["version"] = tool_version

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }

    if commit_sha or repo_url:
        vcs: dict[str, Any] = {}
        if repo_url:
            vcs["repositoryUri"] = repo_url
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
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / filename
    doc = build_sarif(
        hypotheses, evidence_items,
        commit_sha=commit_sha, repo_url=repo_url, tool_version=tool_version,
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
