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

    if isinstance(result, dict):
        return result
    summary = str(result).strip() if result is not None else ""
    return {"summary": summary or "No result was returned.", "cves": [],
            "attack_surfaces": [], "grep_patterns": []}


def _items(value) -> list:
    return value if isinstance(value, list) else []


def _field(item, key: str, default: str = "") -> str:
    if isinstance(item, dict):
        value = item.get(key)
        return default if value in (None, "") else str(value)
    return str(item) if key in ("description", "pattern", "feature") else default


def format_research_output(result: dict) -> str:
    from rich.markup import escape

    if not isinstance(result, dict):
        result = {"summary": str(result)}
    lines = []

    if result.get("summary"):
        lines.append(f"[bold]Summary[/bold]\n{escape(str(result['summary']))}\n")

    cves = _items(result.get("cves"))
    if cves:
        lines.append(f"[bold]Known CVEs[/bold] ({len(cves)})")
        for cve in cves:
            lines.append(f"  [cyan]{escape('[' + _field(cve, 'id', '?') + ']')}[/cyan] "
                         f"{escape(_field(cve, 'description'))}")
            if _field(cve, "grep_pattern"):
                lines.append(f"    [dim]grep:[/dim] {escape(_field(cve, 'grep_pattern'))}")
            if _field(cve, "file_pattern"):
                lines.append(f"    [dim]file:[/dim] {escape(_field(cve, 'file_pattern'))}")
        lines.append("")

    surfaces = _items(result.get("attack_surfaces"))
    if surfaces:
        lines.append(f"[bold]Attack Surfaces[/bold] ({len(surfaces)})")
        for surface in surfaces:
            lines.append(f"  [cyan]{escape('[' + _field(surface, 'area', '?') + ']')}[/cyan] "
                         f"{escape(_field(surface, 'description'))}")
            patterns = _items(surface.get("grep_patterns")) if isinstance(surface, dict) else []
            for pattern in patterns[:3]:
                lines.append(f"    [dim]grep:[/dim] {escape(str(pattern))}")
        lines.append("")

    features = _items(result.get("recent_features"))
    if features:
        lines.append(f"[bold]Recent Features[/bold] ({len(features)})")
        for feature in features:
            files = _items(feature.get("files")) if isinstance(feature, dict) else []
            suffix = f"  [dim]{escape(', '.join(str(f) for f in files[:3]))}[/dim]" if files else ""
            lines.append(f"  {escape(_field(feature, 'feature'))}{suffix}")
        lines.append("")

    patterns = _items(result.get("grep_patterns"))
    if patterns:
        lines.append(f"[bold]Grep Patterns[/bold] ({len(patterns)})")
        for pattern in patterns:
            lines.append(f"  [cyan]{escape('[' + _field(pattern, 'bug_class', '?') + ']')}[/cyan] "
                         f"{escape(_field(pattern, 'pattern'))}")
            if _field(pattern, "rationale"):
                lines.append(f"    [dim]{escape(_field(pattern, 'rationale'))}[/dim]")
        lines.append("")

    priority = _items(result.get("priority_files"))
    if priority:
        lines.append("[bold]Priority Files[/bold]")
        for f in priority[:10]:
            lines.append(f"  {escape(str(f))}")
        lines.append("")

    directions = _items(result.get("research_directions"))
    if directions:
        lines.append("[bold]Research Directions[/bold]")
        for d in directions[:10]:
            lines.append(f"  • {escape(str(d))}")

    return "\n".join(lines).rstrip() or "[dim]No research output.[/dim]"
