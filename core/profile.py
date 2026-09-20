from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Optional

import yaml

PROFILE_FILENAME = ".llmsast.yaml"

_EXPOSURES = {"internet", "authenticated", "internal", "admin_only", "unreachable"}


@dataclass
class Sanitizer:
    qn: str
    neutralizes: list[str] = field(default_factory=list)
    complete: bool = False


@dataclass
class Suppression:
    rule: str
    path: str
    reason: str
    expires: date

    def is_expired(self, today: Optional[date] = None) -> bool:
        return (today or date.today()) > self.expires

    def matches(self, rule: str, file_path: str) -> bool:
        if self.rule != "*" and self.rule.lower() not in (rule or "").lower():
            return False
        return fnmatch.fnmatch(file_path or "", self.path)


@dataclass
class ProjectProfile:
    sanitizers: list[Sanitizer] = field(default_factory=list)
    auth_decorators: list[str] = field(default_factory=list)
    auth_middleware: list[str] = field(default_factory=list)
    trusted_sources: list[str] = field(default_factory=list)
    exposure_overrides: dict[str, str] = field(default_factory=dict)
    suppressions: list[Suppression] = field(default_factory=list)
    rejected_suppressions: list[str] = field(default_factory=list)
    expired_suppressions: list[Suppression] = field(default_factory=list)
    source_path: Optional[Path] = None

    def is_empty(self) -> bool:
        return not (self.sanitizers or self.auth_decorators or self.auth_middleware
                    or self.trusted_sources or self.exposure_overrides or self.suppressions)

    def auth_markers(self) -> list[str]:
        return self.auth_decorators + self.auth_middleware

    def exposure_for(self, entry_path: str) -> Optional[str]:
        for pattern, exposure in self.exposure_overrides.items():
            if fnmatch.fnmatch(entry_path or "", pattern):
                return exposure
        return None

    def suppression_for(self, rule: str, file_path: str) -> Optional[Suppression]:
        for s in self.suppressions:
            if s.matches(rule, file_path):
                return s
        return None

    def sanitizer_for(self, cwe: str) -> list[Sanitizer]:
        return [s for s in self.sanitizers if cwe and cwe.upper() in
                [n.upper() for n in s.neutralizes]]

    def to_prompt(self) -> str:
        """Render the profile for injection into the skill prompt.

        Injected rather than applied as a post-filter so the model stops
        generating the finding instead of generating it and having it dropped.
        """
        if self.is_empty():
            return ""
        parts = ["# Project Profile (.llmsast.yaml — organizational knowledge, treat as authoritative)"]

        if self.auth_decorators or self.auth_middleware:
            lines = []
            if self.auth_decorators:
                lines.append(f"  decorators: {', '.join(self.auth_decorators)}")
            if self.auth_middleware:
                lines.append(f"  middleware: {', '.join(self.auth_middleware)}")
            parts.append(
                "These markers ARE valid authorization. An entry point carrying one is "
                "authenticated — do not report it as missing auth:\n" + "\n".join(lines)
            )

        if self.sanitizers:
            lines = []
            for s in self.sanitizers:
                completeness = "complete" if s.complete else "partial (still verify context)"
                lines.append(f"  {s.qn} neutralizes {', '.join(s.neutralizes)} — {completeness}")
            parts.append(
                "These functions are verified sanitizers. Data passing through a complete "
                "sanitizer is NOT tainted for the listed CWEs:\n" + "\n".join(lines)
            )

        if self.trusted_sources:
            parts.append(
                "These input sources are trusted by organizational policy — do not treat "
                "them as attacker-controlled:\n" +
                "\n".join(f"  {t}" for t in self.trusted_sources)
            )

        if self.exposure_overrides:
            parts.append(
                "Exposure overrides — use these values instead of inferring exposure:\n" +
                "\n".join(f"  {p} -> {e}" for p, e in self.exposure_overrides.items())
            )

        if self.suppressions:
            lines = [f"  {s.rule} in {s.path} — {s.reason} (expires {s.expires.isoformat()})"
                     for s in self.suppressions]
            parts.append(
                "Known-accepted risks. Do not raise these as findings:\n" + "\n".join(lines)
            )

        if self.expired_suppressions:
            lines = [f"  {s.rule} in {s.path} (expired {s.expires.isoformat()})"
                     for s in self.expired_suppressions]
            parts.append(
                "These suppressions EXPIRED and are no longer in effect — analyze these "
                "paths normally:\n" + "\n".join(lines)
            )

        return "\n\n".join(parts)


def _parse_expires(raw) -> Optional[date]:
    if isinstance(raw, date):
        return raw
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, str):
        try:
            return datetime.strptime(raw.strip(), "%Y-%m-%d").date()
        except ValueError:
            return None
    return None


def load_profile(repo_path: str | Path, today: Optional[date] = None) -> ProjectProfile:
    """Load .llmsast.yaml from a target repo root. Absent file yields an empty profile."""
    path = Path(repo_path) / PROFILE_FILENAME
    if not path.exists():
        return ProjectProfile()
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return ProjectProfile(source_path=path)
    if not isinstance(data, dict):
        return ProjectProfile(source_path=path)

    profile = ProjectProfile(source_path=path)

    for raw in data.get("sanitizers") or []:
        if isinstance(raw, dict) and raw.get("qn"):
            profile.sanitizers.append(Sanitizer(
                qn=str(raw["qn"]),
                neutralizes=[str(n) for n in (raw.get("neutralizes") or [])],
                complete=bool(raw.get("complete", False)),
            ))

    markers = data.get("auth_markers") or {}
    if isinstance(markers, dict):
        profile.auth_decorators = [str(d) for d in (markers.get("decorators") or [])]
        profile.auth_middleware = [str(m) for m in (markers.get("middleware") or [])]

    profile.trusted_sources = [str(t) for t in (data.get("trusted_sources") or [])]

    overrides = data.get("exposure_overrides") or {}
    if isinstance(overrides, dict):
        for pattern, exposure in overrides.items():
            if str(exposure) in _EXPOSURES:
                profile.exposure_overrides[str(pattern)] = str(exposure)

    today = today or date.today()
    for raw in data.get("suppress") or []:
        if not isinstance(raw, dict):
            continue
        rule = str(raw.get("rule") or "").strip()
        path_glob = str(raw.get("path") or "").strip()
        reason = str(raw.get("reason") or "").strip()
        expires = _parse_expires(raw.get("expires"))
        label = f"{rule or '?'} in {path_glob or '?'}"
        # reason and expiry are mandatory: without them a suppression list silently
        # rots into a place where real vulnerabilities hide
        if not rule or not path_glob:
            profile.rejected_suppressions.append(f"{label}: missing rule or path")
            continue
        if not reason:
            profile.rejected_suppressions.append(f"{label}: missing required 'reason'")
            continue
        if expires is None:
            profile.rejected_suppressions.append(f"{label}: missing or malformed 'expires' (need YYYY-MM-DD)")
            continue
        suppression = Suppression(rule=rule, path=path_glob, reason=reason, expires=expires)
        if suppression.is_expired(today):
            profile.expired_suppressions.append(suppression)
        else:
            profile.suppressions.append(suppression)

    return profile
