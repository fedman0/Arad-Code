import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.code_analysis import run_shell
from core.tool_specs import TOOLS


def repo(tmp_path):
    d = tmp_path / "r"
    d.mkdir()
    (d / "a.txt").write_text("hello\n")
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    return str(d)


def test_refused_commands_point_at_the_tool_that_does_the_job(tmp_path):
    rp = repo(tmp_path)
    assert "list_dir" in run_shell(rp, "ls -la")
    assert "read_file" in run_shell(rp, "cat a.txt")
    assert "read_file" in run_shell(rp, "sed -n 1,5p a.txt")
    assert "grep tool" in run_shell(rp, "grep hello a.txt")
    assert "grep tool" in run_shell(rp, "rg hello")
    assert "read-only" in run_shell(rp, "python3 setup.py")


def test_operators_are_explained_as_one_command_per_call(tmp_path):
    rp = repo(tmp_path)
    out = run_shell(rp, "head a.txt | wc -l")
    assert "not allowed" in out and "one command per call" in out and "grep tool" in out
    assert "hello" in run_shell(rp, "head -1 a.txt")


def test_the_shell_tool_description_names_the_alternatives():
    spec = next(t for t in TOOLS if t["function"]["name"] == "shell")
    text = spec["function"]["description"]
    for word in ("list_dir", "read_file", "no pipes", "ls", "cat", "sed"):
        assert word in text
