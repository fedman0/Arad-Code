from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional


def cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    path = Path(base) / "pentest"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _slug(repo_path: str) -> str:
    name = Path(repo_path).name or "repo"
    digest = hashlib.sha256(str(repo_path).encode()).hexdigest()[:10]
    return f"{name}-{digest}"


# --------------------------------------------------------------------------
# profile cache
# --------------------------------------------------------------------------

def _profile_cache_file(repo_path: str) -> Path:
    return cache_root() / "profiles" / f"{_slug(repo_path)}.json"


def read_profile_cache(repo_path: str, source: Optional[Path]) -> Optional[dict]:
    """Return the cached profile payload if the source file is unchanged."""
    path = _profile_cache_file(repo_path)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("mtime") != _source_mtime(source):
        return None
    return payload.get("data")


def write_profile_cache(repo_path: str, source: Optional[Path], data: dict) -> None:
    path = _profile_cache_file(repo_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(
            {"mtime": _source_mtime(source), "cached_at": time.time(), "data": data}))
    except OSError:
        pass


def _source_mtime(source: Optional[Path]) -> Optional[float]:
    if source is None:
        return None
    try:
        return source.stat().st_mtime
    except OSError:
        return None


# --------------------------------------------------------------------------
# scan resume state
# --------------------------------------------------------------------------

def _state_file(repo_path: str) -> Path:
    return cache_root() / "runs" / f"{_slug(repo_path)}.json"


def load_run_state(repo_path: str) -> dict:
    path = _state_file(repo_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_run_state(repo_path: str, state: dict) -> None:
    path = _state_file(repo_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(state, indent=2))
    except OSError:
        pass


def clear_run_state(repo_path: str) -> None:
    try:
        _state_file(repo_path).unlink()
    except OSError:
        pass


def mark_skill_done(repo_path: str, commit: str, skill_name: str) -> None:
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        state = {"commit": commit, "completed": []}
    completed = state.setdefault("completed", [])
    if skill_name not in completed:
        completed.append(skill_name)
    state["updated_at"] = time.time()
    save_run_state(repo_path, state)


def completed_skills(repo_path: str, commit: str) -> set[str]:
    """Skills already finished at this commit; a different commit invalidates all."""
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        return set()
    return set(state.get("completed", []))
