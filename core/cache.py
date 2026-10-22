from __future__ import annotations
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional


def cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    path = Path(base) / "pentest"
    path.mkdir(parents=True, exist_ok=True)
    # suppression reasons carry business context, so keep the cache private
    try:
        path.chmod(0o700)
    except OSError:
        pass
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
    if payload.get("source") != _source_key(source):
        return None
    if payload.get("mtime") != _source_mtime(source):
        return None
    return payload.get("data")


def write_profile_cache(repo_path: str, source: Optional[Path], data: dict) -> None:
    path = _profile_cache_file(repo_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _atomic_write(path, json.dumps(
            {"source": _source_key(source), "mtime": _source_mtime(source),
             "cached_at": time.time(), "data": data}))
    except OSError:
        pass


def _source_key(source: Optional[Path]) -> Optional[str]:
    if source is None:
        return None
    try:
        return str(Path(source).expanduser().resolve())
    except (OSError, RuntimeError):
        return str(source)


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
        _atomic_write(path, json.dumps(state, indent=2))
    except OSError:
        pass


def clear_run_state(repo_path: str) -> None:
    try:
        _state_file(repo_path).unlink()
    except OSError:
        pass


def _working_tree_hash(repo_path: str) -> str:
    """Hash of uncommitted changes so a dirty tree invalidates the cache.

    Uses `git diff HEAD` (actual content) rather than `git status --porcelain`
    (only filenames) so that editing a file twice produces different hashes.
    Falls back to porcelain output if diff fails (e.g. empty repo with no HEAD).
    """
    try:
        diff = subprocess.run(
            ["git", "-C", repo_path, "diff", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if diff.returncode == 0:
            porcelain = subprocess.run(
                ["git", "-C", repo_path, "status", "--porcelain"],
                capture_output=True, text=True, timeout=5,
            )
            combined = diff.stdout + porcelain.stdout
            return hashlib.sha256(combined.encode()).hexdigest()[:12]
        porcelain = subprocess.run(
            ["git", "-C", repo_path, "status", "--porcelain"],
            capture_output=True, text=True, timeout=5,
        )
        if porcelain.returncode != 0:
            return ""
        return hashlib.sha256(porcelain.stdout.encode()).hexdigest()[:12]
    except Exception:
        return ""


def mark_skill_done(repo_path: str, commit: str, skill_name: str) -> None:
    if not commit:
        return
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        state = {"commit": commit, "completed": []}
    completed = state.setdefault("completed", [])
    if skill_name not in completed:
        completed.append(skill_name)
    state["updated_at"] = time.time()
    save_run_state(repo_path, state)


def completed_skills(repo_path: str, commit: str) -> set[str]:
    """Skills already finished at this commit; a different commit invalidates all.

    An empty commit means the target is not a git repo — nothing is resumable.
    Use --restart to force a full re-scan regardless of commit.
    """
    if not commit:
        return set()
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        return set()
    return set(state.get("completed", []))


def _state_for(repo_path: str, commit: str) -> dict:
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        state = {"commit": commit, "completed": []}
    return state


def forget_skills(repo_path: str, commit: str, names) -> None:
    names = set(names)
    state = load_run_state(repo_path)
    if not commit or state.get("commit") != commit:
        clear_run_state(repo_path)
        return
    state["completed"] = [s for s in state.get("completed", []) if s.split("#", 1)[0] not in names]
    fanout = {k: v for k, v in (state.get("fanout") or {}).items() if k not in names}
    if fanout:
        state["fanout"] = fanout
    else:
        state.pop("fanout", None)
    state["updated_at"] = time.time()
    save_run_state(repo_path, state)


def fanout_progress(repo_path: str, commit: str, skill_name: str) -> dict:
    if not commit:
        return {}
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        return {}
    entry = (state.get("fanout") or {}).get(skill_name)
    return entry if isinstance(entry, dict) else {}


def record_fanout(repo_path: str, commit: str, skill_name: str, retry: bool,
                  reviewed, undecided) -> None:
    if not commit:
        return
    state = _state_for(repo_path, commit)
    entry = state.setdefault("fanout", {}).setdefault(skill_name, {})
    for field, names in (("retried" if retry else "reviewed", reviewed),
                         ("failed" if retry else "undecided", undecided)):
        items = entry.setdefault(field, [])
        items.extend(n for n in names if n not in items)
    state["updated_at"] = time.time()
    save_run_state(repo_path, state)


def started_skills(repo_path: str, commit: str) -> set[str]:
    if not commit:
        return set()
    state = load_run_state(repo_path)
    if state.get("commit") != commit:
        return set()
    names = {s.split("#", 1)[0] for s in state.get("completed", [])}
    return names | set((state.get("fanout") or {}).keys())
