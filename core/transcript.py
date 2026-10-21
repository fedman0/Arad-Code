from __future__ import annotations
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

from .cache import _slug
from .models import utc_now_iso


def new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:80] or "run"


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass


class Transcript:
    def __init__(self, path: Path, meta: dict):
        self.path = path
        self._messages: Optional[list] = None
        self._written = 0
        self._ok = True
        try:
            _private_dir(path.parent)
        except OSError:
            self._ok = False
        self._write({"type": "start", **meta})

    def _write(self, event: dict) -> None:
        if not self._ok:
            return
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps({"t": utc_now_iso(), **event}, ensure_ascii=False, default=str))
                f.write("\n")
        except OSError:
            self._ok = False

    def bind(self, messages: list) -> None:
        self._messages = messages
        self._written = 0

    def sync(self, messages: Optional[list] = None) -> None:
        if messages is not None and messages is not self._messages:
            self.bind(messages)
        if self._messages is None:
            return
        for m in self._messages[self._written:]:
            self._write({"type": "message", "message": m})
        self._written = len(self._messages)

    def event(self, kind: str, **info) -> None:
        self.sync()
        self._write({"type": kind, **info})

    def close(self, **info) -> None:
        self.sync()
        self._write({"type": "end", **info})


class NullTranscript:
    path = None

    def bind(self, messages: list) -> None:
        pass

    def sync(self, messages: Optional[list] = None) -> None:
        pass

    def event(self, kind: str, **info) -> None:
        pass

    def close(self, **info) -> None:
        pass


def open_transcript(root: Optional[Path], run_id: str, repo_path: str, scope: str, meta: dict):
    if root is None:
        return NullTranscript()
    folder = root / _slug(repo_path or "no-repo") / run_id
    name = f"{time.strftime('%H%M%S')}-{secrets.token_hex(2)}-{_safe_name(scope)}.jsonl"
    try:
        _private_dir(root)
    except OSError:
        return NullTranscript()
    return Transcript(folder / name, {"run_id": run_id, "repo_path": repo_path, "scope": scope, **meta})
