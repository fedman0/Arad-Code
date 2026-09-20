from __future__ import annotations
import json
from typing import Optional

DEEP_RESEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "cves": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "description": {"type": "string"},
                    "file_pattern": {"type": "string"},
                    "grep_pattern": {"type": "string"},
                    "root_cause": {"type": "string"},
                },
                "required": ["id", "description"],
                "additionalProperties": False,
            },
        },
        "attack_surfaces": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "area": {"type": "string"},
                    "description": {"type": "string"},
                    "why_unexplored": {"type": "string"},
                    "grep_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "target_files": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["area", "description"],
                "additionalProperties": False,
            },
        },
        "recent_features": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "feature": {"type": "string"},
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "reason_less_audited": {"type": "string"},
                },
                "required": ["feature"],
                "additionalProperties": False,
            },
        },
        "grep_patterns": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "bug_class": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["pattern", "bug_class"],
                "additionalProperties": False,
            },
        },
        "priority_files": {
            "type": "array",
            "items": {"type": "string"},
        },
        "research_directions": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["summary", "cves", "attack_surfaces", "grep_patterns"],
    "additionalProperties": False,
}


DEEP_RESEARCH_SYSTEM = """You are a world-class security researcher specializing in vulnerability research.

Your job is deep research: comprehensive analysis of a target to find novel vulnerabilities, understand the attack surface, and identify patterns from past CVEs that might have variants in this codebase.

Be exhaustive and specific. Return grep patterns that will actually work. Name real file paths. Your output goes directly to hunters who need concrete leads, not vague directions.

For CVEs: include the exact CWE, the file:line that was vulnerable, and a grep pattern that would find similar code.

For attack surfaces: think creatively. What code paths are rarely tested? What assumptions might be wrong? What interacts with untrusted input in unexpected ways?

For grep patterns: make them specific enough to be useful (not too broad) and focused on the bug class. Include both the obvious pattern and the subtle variant.
"""


def _build_prompt(question: str, repo_path: str, context: str) -> str:
    parts = [
        f"Deep research request: {question}",
        f"Repository: {repo_path}" if repo_path else "",
        f"Additional context: {context}" if context else "",
        "",
        "Produce:",
        "1. Known bug classes and vulnerability patterns for this target — from your training data.",
        "   IMPORTANT: do NOT fabricate specific CVE IDs or file:line references you are not certain of.",
        "   If you know a real CVE number confidently, include it; otherwise describe the bug class only.",
        "2. Unexplored attack surfaces and novel research directions",
        "3. Recently added features (less audited, higher bug density)",
        "4. Specific grep patterns for finding bug-class variants in source",
        "5. Priority files most likely to contain vulnerabilities",
        "",
        "Use every available tool. Read actual source files. Trace call chains.",
        "Do not guess — find evidence in the code.",
    ]
    return "\n".join(p for p in parts if p is not None)


async def deep_research(
    question: str,
    *,
    runner,
    repo_path: str = "",
    context: str = "",
) -> dict:
    prompt = _build_prompt(question, repo_path, context)

    result = await runner.run_prompt(
        prompt=prompt,
        repo_path=repo_path,
        extra_context=context,
        schema=DEEP_RESEARCH_SCHEMA,
        system_override=DEEP_RESEARCH_SYSTEM,
    )

    return result if isinstance(result, dict) else {"summary": str(result), "cves": [], "attack_surfaces": [], "grep_patterns": []}


def format_research_output(result: dict) -> str:
    lines = []

    if result.get("summary"):
        lines.append(f"## Summary\n{result['summary']}\n")

    cves = result.get("cves") or []
    if cves:
        lines.append(f"## Known CVEs ({len(cves)})")
        for cve in cves:
            lines.append(f"  [{cve.get('id', '?')}] {cve.get('description', '')}")
            if cve.get("grep_pattern"):
                lines.append(f"    grep: {cve['grep_pattern']}")
            if cve.get("file_pattern"):
                lines.append(f"    file: {cve['file_pattern']}")
        lines.append("")

    surfaces = result.get("attack_surfaces") or []
    if surfaces:
        lines.append(f"## Attack Surfaces ({len(surfaces)})")
        for s in surfaces:
            lines.append(f"  [{s.get('area', '?')}] {s.get('description', '')}")
            patterns = s.get("grep_patterns") or []
            for p in patterns[:3]:
                lines.append(f"    grep: {p}")
        lines.append("")

    patterns = result.get("grep_patterns") or []
    if patterns:
        lines.append(f"## Grep Patterns ({len(patterns)})")
        for p in patterns:
            lines.append(f"  [{p.get('bug_class', '?')}] {p.get('pattern', '')}")
            if p.get("rationale"):
                lines.append(f"    {p['rationale']}")
        lines.append("")

    priority = result.get("priority_files") or []
    if priority:
        lines.append(f"## Priority Files")
        for f in priority[:10]:
            lines.append(f"  {f}")

    return "\n".join(lines)
