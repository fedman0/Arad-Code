import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.code_analysis import _rg_grep, find_all_usages
from core.tool_exec import ToolExecutor


def repo(tmp_path):
    d = tmp_path / "app"
    for rel, text in {"routes/login.ts": "export const login = () => db.query(q)\n",
                      "routes/admin/users.ts": "login()\n",
                      "lib/util.ts": "const q = login\n",
                      ".github/workflows/ci.yml": "run: login\n"}.items():
        f = d / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    return str(d)


def files(out):
    return sorted({line.split(":", 1)[0] for line in out.splitlines() if ":" in line})


def test_path_globs_match_from_the_repository_root(tmp_path):
    rp = repo(tmp_path)
    t = ToolExecutor()
    assert files(t._grep(rp, "login", file_glob="routes/*.ts")) == ["routes/login.ts"]
    assert files(t._grep(rp, "login", file_glob="routes/**")) == ["routes/admin/users.ts", "routes/login.ts"]
    assert files(t._grep(rp, "login", file_glob="*.ts")) == ["lib/util.ts", "routes/admin/users.ts", "routes/login.ts"]


def test_output_paths_are_relative_to_the_repository(tmp_path):
    rp = repo(tmp_path)
    t = ToolExecutor()
    out = t._grep(rp, "login")
    assert ".github/workflows/ci.yml" in files(out)
    assert not any(line.startswith(("/", "./")) for line in out.splitlines())
    assert files(t._grep(rp, "login", path="routes")) == ["routes/admin/users.ts", "routes/login.ts"]
    assert t._grep(rp, "login", path="../") == "Access denied: path outside repository"


def test_find_all_usages_and_the_helper_take_path_globs_too(tmp_path):
    rp = repo(tmp_path)
    assert files(find_all_usages(rp, "login", "routes/*.ts")) == ["routes/login.ts"]
    assert files(_rg_grep(rp, "login", "lib")) == ["lib/util.ts"]
    assert not any(line.startswith(("/", "./")) for line in find_all_usages(rp, "login").splitlines())
