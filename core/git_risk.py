from __future__ import annotations
import re
import subprocess
from collections import defaultdict
from pathlib import Path

_SECURITY_COMMIT = re.compile(
    r"\b(cve-\d{4}-\d+|security|vulnerab\w*|exploit\w*|injection|xss|csrf|ssrf|rce|"
    r"auth(?:z|entication|orization)?\s+bypass|sanitiz\w*|escap\w*|overflow|traversal)\b",
    re.IGNORECASE,
)


def _git(repo_path: str, *args: str, timeout: int = 30) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return out.stdout if out.returncode == 0 else ""
    except (subprocess.SubprocessError, OSError):
        return ""


def file_risk_scores(repo_path: str, max_commits: int = 2000) -> dict[str, float]:
    """Weight files by how much security history they carry.

    This is a budgeting signal only — it decides where to spend analysis effort,
    never whether something is a finding. Past security patches in a file predict
    future ones; so does heavy churn.
    """
    log = _git(repo_path, "log", f"-n{max_commits}", "--name-only",
               "--pretty=format:%x00%s", "--no-merges")
    if not log:
        return {}

    churn: dict[str, int] = defaultdict(int)
    security_touches: dict[str, int] = defaultdict(int)

    for block in log.split("\x00"):
        if not block.strip():
            continue
        lines = block.splitlines()
        subject = lines[0] if lines else ""
        is_security = bool(_SECURITY_COMMIT.search(subject))
        for path in lines[1:]:
            path = path.strip()
            if not path:
                continue
            churn[path] += 1
            if is_security:
                security_touches[path] += 1

    if not churn:
        return {}

    max_churn = max(churn.values())
    scores: dict[str, float] = {}
    for path, count in churn.items():
        churn_score = count / max_churn
        sec_score = min(security_touches.get(path, 0) / 3.0, 1.0)
        scores[path] = round(0.35 * churn_score + 0.65 * sec_score, 4)
    return scores


def risk_for_file(scores: dict[str, float], file_path: str) -> float:
    if not scores or not file_path:
        return 0.0
    if file_path in scores:
        return scores[file_path]
    suffix = Path(file_path).as_posix()
    for path, score in scores.items():
        if path.endswith("/" + suffix) or suffix.endswith("/" + path):
            return score
    return 0.0
