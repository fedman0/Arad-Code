from __future__ import annotations
import fnmatch
import re
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

    def matches(self, cwe: str, rule_text: str, file_path: str) -> bool:
        # a path-scoped suppression needs a real path; matching "" against "*"
        # would silently suppress every hypothesis that has no evidence yet
        if not file_path or not fnmatch.fnmatch(file_path, self.path):
            return False
        rule = self.rule.lower().strip()
        if rule == "*":
            return True
        if rule.startswith("cwe-"):
            return (cwe or "").lower().strip() == rule
        # token match, so "sql-injection" needs both words present rather than
        # matching any prose containing the substring
        wanted = {t for t in re.split(r"[^a-z0-9]+", rule) if t}
        present = {t for t in re.split(r"[^a-z0-9]+", (rule_text or "").lower()) if t}
        cwe_token = (cwe or "").lower().replace("-", "")
        if cwe_token:
            present.add(cwe_token)
        return bool(wanted) and wanted <= present


@dataclass
class ProjectProfile:
    trusted: bool = False
    ignored_repo_profile: Optional[Path] = None
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
        # expired/rejected entries must count: a profile whose suppressions have
        # all expired would otherwise drop the "these no longer apply" notice,
        # which is exactly when the anti-rot warning matters
        return not (self.sanitizers or self.auth_decorators or self.auth_middleware
                    or self.trusted_sources or self.exposure_overrides
                    or self.suppressions or self.expired_suppressions
                    or self.rejected_suppressions)

    def auth_markers(self) -> list[str]:
        return self.auth_decorators + self.auth_middleware

    def exposure_for(self, entry_path: str) -> Optional[str]:
        # entry_point is formatted "GET /admin/users -> handler.qn", so an
        # anchored pattern like "/admin/*" never matched and the feature was dead
        route = _route_of(entry_path)
        for pattern, exposure in self.exposure_overrides.items():
            if _route_matches(pattern, route):
                return exposure
        return None

    def suppression_for(self, cwe: str, rule_text: str,
                        file_path: str) -> Optional[Suppression]:
        for s in self.suppressions:
            if s.matches(cwe, rule_text, file_path):
                return s
        return None

    def sanitizer_for(self, cwe: str) -> list[Sanitizer]:
        return [s for s in self.sanitizers if cwe and cwe.upper() in
                [n.upper() for n in s.neutralizes]]

    @staticmethod
    def _safe(text: str, limit: int = 200) -> str:
        """Flatten a profile value before it is interpolated into the prompt.

        Values are written by whoever owns the repo, not necessarily the
        operator, and a multi-line `reason` could otherwise open its own
        `# Skill Contract` section and issue instructions to the model.
        """
        flat = " ".join(str(text or "").split())
        flat = flat.replace("#", "").replace("`", "'")
        return flat[:limit]

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
                lines.append("  decorators: " + ", ".join(self._safe(d, 80) for d in self.auth_decorators))
            if self.auth_middleware:
                lines.append("  middleware: " + ", ".join(self._safe(m, 80) for m in self.auth_middleware))
            parts.append(
                "These markers ARE valid authorization. An entry point carrying one is "
                "authenticated — do not report it as missing auth:\n" + "\n".join(lines)
            )

        if self.sanitizers:
            lines = []
            for s in self.sanitizers:
                completeness = "complete" if s.complete else "partial (still verify context)"
                lines.append(f"  {self._safe(s.qn, 120)} neutralizes "
                             + ", ".join(self._safe(n, 20) for n in s.neutralizes)
                             + f" — {completeness}")
            parts.append(
                "These functions are verified sanitizers. Data passing through a complete "
                "sanitizer is NOT tainted for the listed CWEs:\n" + "\n".join(lines)
            )

        if self.trusted_sources:
            parts.append(
                "These input sources are trusted by organizational policy — do not treat "
                "them as attacker-controlled:\n" +
                "\n".join(f"  {self._safe(t)}" for t in self.trusted_sources)
            )

        if self.exposure_overrides:
            parts.append(
                "Exposure overrides — use these values instead of inferring exposure:\n" +
                "\n".join(f"  {self._safe(p, 120)} -> {e}"
                          for p, e in self.exposure_overrides.items())
            )

        if self.suppressions:
            lines = [f"  {self._safe(s.rule, 60)} in {self._safe(s.path, 80)} — "
                     f"{self._safe(s.reason)} (expires {s.expires.isoformat()})"
                     for s in self.suppressions]
            parts.append(
                "Known-accepted risks. Do not raise these as findings:\n" + "\n".join(lines)
            )

        if self.expired_suppressions:
            lines = [f"  {self._safe(s.rule, 60)} in {self._safe(s.path, 80)} "
                     f"(expired {s.expires.isoformat()})"
                     for s in self.expired_suppressions]
            parts.append(
                "These suppressions EXPIRED and are no longer in effect — analyze these "
                "paths normally:\n" + "\n".join(lines)
            )

        return "\n\n".join(parts)


def _jsonable(value):
    """YAML parses bare dates into date objects, which json cannot serialize."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()[:10]
    return value


def _route_of(entry: str) -> str:
    head = (entry or "").split("->", 1)[0].strip()
    tokens = head.split()
    if len(tokens) >= 2 and tokens[0].isalpha() and tokens[0].isupper():
        return tokens[1]
    return tokens[0] if tokens else ""


def _route_matches(pattern: str, route: str) -> bool:
    pattern = pattern.strip()
    if not pattern or not route:
        return False
    if any(ch in pattern for ch in "*?["):
        candidates = [pattern]
    else:
        candidates = [pattern, pattern.rstrip("/") + "/*"]
    starts = [route]
    if not pattern.startswith(("/", "*")):
        starts += [route[i + 1:] for i, ch in enumerate(route) if ch == "/"]
    return any(fnmatch.fnmatchcase(s, c) for s in starts for c in candidates)


def _str_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v is not None]
    if isinstance(value, dict):
        return []
    return [str(value)]


def _parse_expires(raw) -> Optional[date]:
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, date):
        return raw
    if isinstance(raw, str):
        try:
            return datetime.strptime(raw.strip(), "%Y-%m-%d").date()
        except ValueError:
            return None
    return None


def load_profile(repo_path: str | Path, today: Optional[date] = None, *,
                 external_path: Optional[str | Path] = None,
                 trust_repo_profile: bool = False,
                 use_cache: bool = False) -> ProjectProfile:
    """Load a project profile.

    A profile can suppress findings and declare inputs trusted, so a profile
    committed inside the target repository is attacker-controlled on any codebase
    you did not write: a malicious PR adding `trusted_sources: ["all HTTP request
    bodies"]` would blind the scan. An in-repo profile is therefore ignored unless
    explicitly trusted; prefer `external_path`, which the target cannot modify.
    """
    repo_file = Path(repo_path) / PROFILE_FILENAME

    if external_path:
        path = Path(external_path).expanduser()
        if not path.exists():
            return ProjectProfile()
    elif trust_repo_profile:
        path = repo_file
        if not path.exists():
            return ProjectProfile()
    else:
        return ProjectProfile(
            ignored_repo_profile=repo_file if repo_file.exists() else None)

    data = None
    if use_cache:
        from .cache import read_profile_cache
        data = read_profile_cache(str(repo_path), path)
    if data is None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError, ValueError):
            return ProjectProfile(source_path=path, trusted=True)
        if use_cache and isinstance(data, dict):
            from .cache import write_profile_cache
            write_profile_cache(str(repo_path), path, _jsonable(data))
    if not isinstance(data, dict):
        return ProjectProfile(source_path=path, trusted=True)

    profile = ProjectProfile(source_path=path, trusted=True)

    sanitizers = data.get("sanitizers") or []
    for raw in sanitizers if isinstance(sanitizers, list) else []:
        if isinstance(raw, dict) and raw.get("qn"):
            profile.sanitizers.append(Sanitizer(
                qn=str(raw["qn"]),
                neutralizes=_str_list(raw.get("neutralizes")),
                complete=bool(raw.get("complete", False)),
            ))

    markers = data.get("auth_markers") or {}
    if isinstance(markers, dict):
        profile.auth_decorators = _str_list(markers.get("decorators"))
        profile.auth_middleware = _str_list(markers.get("middleware"))

    profile.trusted_sources = _str_list(data.get("trusted_sources"))

    overrides = data.get("exposure_overrides") or {}
    if isinstance(overrides, dict):
        for pattern, exposure in overrides.items():
            if str(exposure) in _EXPOSURES:
                profile.exposure_overrides[str(pattern)] = str(exposure)

    today = today or date.today()
    suppress = data.get("suppress") or []
    if isinstance(suppress, dict):
        suppress = [suppress]
    for raw in suppress if isinstance(suppress, list) else []:
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
        if rule == "*" and path_glob in ("**", "*"):
            profile.rejected_suppressions.append(
                f"{label}: refuses to suppress every rule in every file; "
                "scope the rule or the path"
            )
            continue
        suppression = Suppression(rule=rule, path=path_glob, reason=reason, expires=expires)
        if suppression.is_expired(today):
            profile.expired_suppressions.append(suppression)
        else:
            profile.suppressions.append(suppression)

    return profile
