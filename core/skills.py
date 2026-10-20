from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

MAINTENANCE_PHASE = "p0"
DEFAULT_ORDER = 100


class SkillFormatError(ValueError):
    pass


@dataclass(frozen=True)
class SkillInfo:
    name: str
    phase: str
    path: Path
    order: int = DEFAULT_ORDER
    parallel: bool = False
    requires: tuple[str, ...] = ()


def split_frontmatter(text: str, source: str = "skill") -> tuple[dict, str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return {}, text
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            try:
                meta = yaml.safe_load("".join(lines[1:i])) or {}
            except yaml.YAMLError as e:
                raise SkillFormatError(f"{source}: invalid frontmatter: {e}") from None
            if not isinstance(meta, dict):
                raise SkillFormatError(f"{source}: frontmatter must be a mapping")
            return meta, "".join(lines[i + 1:]).lstrip("\n")
    raise SkillFormatError(f"{source}: frontmatter is missing its closing ---")


def _as_order(value, source: str) -> int:
    if value is None:
        return DEFAULT_ORDER
    if isinstance(value, bool):
        raise SkillFormatError(f"{source}: order must be a number")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SkillFormatError(f"{source}: order must be a number") from None


def _as_flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _as_names(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v).strip().lower() for v in value if str(v).strip())
    text = str(value).strip().lower()
    return (text,) if text else ()


class SkillCatalog:
    def __init__(self, root: Path):
        self.root = Path(root)

    def phases(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return [d.name for d in sorted(self.root.iterdir()) if d.is_dir()]

    def _info(self, phase: str, path: Path) -> SkillInfo:
        meta, _ = split_frontmatter(path.read_text(encoding="utf-8"), str(path))
        return SkillInfo(
            name=path.stem,
            phase=phase,
            path=path,
            order=_as_order(meta.get("order"), str(path)),
            parallel=_as_flag(meta.get("parallel", False)),
            requires=_as_names(meta.get("requires")),
        )

    def phase_skills(self, phase: str) -> list[SkillInfo]:
        phase_dir = self.root / phase
        if not phase_dir.is_dir():
            raise FileNotFoundError(f"Phase dir not found: {phase_dir}")
        infos = [self._info(phase, f) for f in phase_dir.glob("*.md")]
        return sorted(infos, key=lambda s: (s.order, s.name))

    def find(self, name: str) -> Optional[SkillInfo]:
        for phase in self.phases():
            path = self.root / phase / f"{name}.md"
            if path.exists():
                return self._info(phase, path)
        return None

    def body(self, name: str) -> str:
        info = self.find(name)
        if info is None:
            raise FileNotFoundError(f"Skill '{name}' not found in {self.root}")
        return split_frontmatter(info.path.read_text(encoding="utf-8"), str(info.path))[1]
