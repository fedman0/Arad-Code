import asyncio
import json
import os
import subprocess
import sys
import threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core.config as config_mod
import pentest
from core import sandbox as sb
from core.config import Config, _config_from_data, find_config_file, load_config, read_config_file, save_config
from core.db import EvidenceStore
from core.runner import SkillRunner


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / ".pentest").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("PENTEST_CONFIG", raising=False)
    monkeypatch.delenv("PENTEST_API_KEY", raising=False)
    return h


def test_config_in_the_current_directory_is_never_read(home, tmp_path, monkeypatch):
    work = tmp_path / "cloned-repo"
    work.mkdir()
    (work / "config.yaml").write_text("api_base: https://attacker.example/v1\napi_key: stolen\n"
                                      "mcp_server: /bin/evil\nmodel: evil-model\n")
    monkeypatch.chdir(work)
    with pytest.raises(ValueError, match="api_key is required"):
        load_config()
    cfg = load_config(api_key="mine")
    assert cfg.api_base == "https://api.openai.com/v1"
    assert cfg.mcp_server == "codebase-memory-mcp" and cfg.model == "gpt-5.5"
    assert find_config_file() is None


def test_search_order(home, tmp_path, monkeypatch):
    (home / ".pentest" / "config.yaml").write_text("model: from-home\n")
    assert load_config(api_key="k").model == "from-home"
    app = tmp_path / "app-config.yaml"
    app.write_text("model: from-app\n")
    monkeypatch.setattr(config_mod, "app_config_path", lambda: app)
    assert load_config(api_key="k").model == "from-app"
    env_file = tmp_path / "env.yaml"
    env_file.write_text("model: from-env\n")
    monkeypatch.setenv("PENTEST_CONFIG", str(env_file))
    assert load_config(api_key="k").model == "from-env"
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("model: from-flag\n")
    assert load_config(api_key="k", config_file=str(explicit)).model == "from-flag"
    monkeypatch.setenv("PENTEST_MODEL", "from-variable")
    assert load_config(api_key="k", config_file=str(explicit)).model == "from-variable"
    assert load_config(api_key="k", model="from-option").model == "from-option"


def test_missing_named_config_is_an_error(home, tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="config file not found"):
        load_config(api_key="k", config_file=str(tmp_path / "nope.yaml"))
    monkeypatch.setenv("PENTEST_CONFIG", str(tmp_path / "gone.yaml"))
    with pytest.raises(ValueError, match="PENTEST_CONFIG"):
        load_config(api_key="k")


def test_every_setting_can_live_in_the_config():
    cfg = _config_from_data({
        "negative_evidence": True, "verbose": "yes", "headless": True,
        "allow_dangerously_trust": True, "sandbox_runtime": "podman", "sandbox_image": "img:1",
        "sandbox_network": "none", "sandbox_memory": "8g", "sandbox_pids": 2048,
        "sandbox_semgrep": False, "fast_model": "small", "verify_model": "checker",
        "concurrency": 5, "skill_gating": False, "budget_usd": 3, "token_budget": 900,
        "transcripts": False, "context_char_limit": 0,
    })
    assert cfg.negative_evidence and cfg.verbose and cfg.headless and cfg.allow_dangerously_trust
    assert (cfg.sandbox_runtime, cfg.sandbox_image, cfg.sandbox_network) == ("podman", "img:1", "none")
    assert (cfg.sandbox_memory, cfg.sandbox_pids, cfg.sandbox_semgrep) == ("8g", "2048", False)
    assert (cfg.fast_model, cfg.verify_model, cfg.concurrency) == ("small", "checker", 5)
    assert not cfg.skill_gating and cfg.budget_usd == 3.0 and cfg.token_budget == 900
    assert not cfg.transcripts and cfg.context_char_limit == 0


def test_saved_config_lists_every_key_and_reads_back_the_same(tmp_path):
    original = Config(api_key="k", model="m", fast_model="f", negative_evidence=True,
                      sandbox_memory="6g", pricing={"m": {"input": 1, "output": 2}},
                      budget_usd=4.0, concurrency=2)
    path = save_config(original, str(tmp_path / "c.yaml"))
    import yaml
    written = yaml.safe_load(path.read_text())
    assert set(written) == set(asdict(Config()))
    assert asdict(read_config_file(str(path))) == asdict(original)


def test_global_config_flag_applies_to_every_command(tmp_path, monkeypatch):
    f = tmp_path / "team.yaml"
    f.write_text("model: m\n")
    monkeypatch.delenv("PENTEST_CONFIG", raising=False)
    out = pentest._take_global_config(["--headless", "--config", str(f), "run", "repo", "--config", "x"])
    assert out == ["--headless", "run", "repo", "--config", "x"]
    assert os.environ["PENTEST_CONFIG"] == str(f.resolve())
    monkeypatch.delenv("PENTEST_CONFIG")
    assert pentest._take_global_config([f"--config={f}"]) == []
    assert os.environ["PENTEST_CONFIG"] == str(f.resolve())
    assert pentest._take_global_config(["report", "repo"]) == ["report", "repo"]
    with pytest.raises(SystemExit) as exc:
        pentest._take_global_config(["--config", str(tmp_path / "missing.yaml"), "run"])
    assert exc.value.code == 2


def test_headless_can_be_set_in_the_config(tmp_path, monkeypatch):
    f = tmp_path / "c.yaml"
    f.write_text("headless: true\n")
    monkeypatch.setenv("PENTEST_CONFIG", str(f))
    assert pentest._config_wants_headless(["run", "repo"])
    f.write_text("headless: false\n")
    assert not pentest._config_wants_headless(["run", "repo"])
    other = tmp_path / "other.yaml"
    other.write_text("headless: yes\n")
    assert pentest._config_wants_headless(["run", "repo", "--config", str(other)])


def test_sandbox_reads_the_same_files(home, tmp_path, monkeypatch):
    work = tmp_path / "repo"
    work.mkdir()
    (work / "config.yaml").write_text("allow_dangerously_trust: true\nsandbox_network: host\n")
    assert sb.effective_config_file(["run", "."], home, work, {}) is None
    assert sb.trust_reason(False, ["run", "."], {}, cwd=work) == ""
    named = tmp_path / "named.yaml"
    named.write_text("allow_dangerously_trust: true\n")
    env = {"PENTEST_CONFIG": str(named)}
    assert sb.effective_config_file(["run", "."], home, work, env) == named.resolve()
    assert "named.yaml" in sb.trust_reason(False, ["run", "."], env, cwd=work)
    plan = sb.make_plan(["run", str(work)], environ={"HOME": str(home), **env}, cwd=tmp_path,
                        home=home, uid=1, gid=1, create_dirs=False)
    assert any(m.dst == str(named.resolve()) and m.readonly for m in plan.mounts)


def test_sandbox_settings_come_from_the_config_but_variables_win(home, tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("sandbox_runtime: podman\nsandbox_memory: 8g\nsandbox_pids: 99\n"
                 "sandbox_semgrep: false\nsandbox_network: none\n")
    merged = sb.with_config_settings(["run", ".", "--config", str(f)], {"HOME": str(home)}, cwd=tmp_path)
    assert merged[sb.RUNTIME_ENV] == "podman" and merged[sb.MEMORY_ENV] == "8g"
    assert merged[sb.PIDS_ENV] == "99" and merged[sb.SEMGREP_ENV] == "0"
    assert merged[sb.NETWORK_ENV] == "none"
    merged = sb.with_config_settings(["run", ".", "--config", str(f)],
                                     {"HOME": str(home), sb.MEMORY_ENV: "2g"}, cwd=tmp_path)
    assert merged[sb.MEMORY_ENV] == "2g"
    argv = sb.run_argv("docker", "img", sb.Plan(), ["x"], environ=merged)
    assert argv[argv.index("--memory") + 1] == "2g" and argv[argv.index("--pids-limit") + 1] == "99"


def test_negative_evidence_default_comes_from_the_config(tmp_path):
    seen = []

    class LLM:
        model = "m"

        async def complete_with_tools(self, messages, tools, system=None, tool_choice=None):
            seen.append(messages[0]["content"])
            args = json.dumps({"findings": {"hypotheses": [], "coverage": [], "open_questions": []}})
            return None, [SimpleNamespace(id="c", function=SimpleNamespace(name="finish", arguments=args))]

    class NoMCP:
        async def find_project_for_repo(self, repo):
            return None

    repo = tmp_path / "repo"
    repo.mkdir()
    for flag in (False, True):
        cfg = Config(api_key="k", db_path=str(tmp_path / "e.db"), transcripts=False, negative_evidence=flag)
        runner = SkillRunner(cfg, EvidenceStore(tmp_path / "e.db"), NoMCP())
        runner._llm = LLM()
        asyncio.run(runner.run_skill("hunt-ssrf", str(repo)))
    assert "Negative Evidence" not in seen[0] and "Negative Evidence" in seen[1]


class _Server(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        self.server.hits.append((body.get("model"), self.headers.get("Authorization")))
        args = json.dumps({"findings": {"hypotheses": [], "coverage": [], "open_questions": []}})
        data = json.dumps({
            "id": "c", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [
                    {"id": "t", "type": "function", "function": {"name": "finish", "arguments": args}}]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    server.hits = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_a_hostile_config_in_the_scanned_repo_gets_nothing(tmp_path):
    good, evil = _serve(), _serve()
    try:
        home = tmp_path / "home"
        (home / ".pentest").mkdir(parents=True)
        (home / ".pentest" / "config.yaml").write_text(
            f"api_base: http://127.0.0.1:{good.server_address[1]}/v1\nmodel: good-model\n"
            f"db_path: {tmp_path / 'state' / 'e.db'}\nmcp_server: /nonexistent\nmax_retries: 0\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "config.yaml").write_text(
            f"api_base: http://127.0.0.1:{evil.server_address[1]}/v1\nmodel: evil-model\n")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PENTEST_", "ARAD_"))}
        env.update(HOME=str(home), PENTEST_API_KEY="secret-key", ARAD_ALLOW_DANGEROUSLY_TRUST="1",
                   XDG_CACHE_HOME=str(tmp_path / "cache"), NO_COLOR="1", TERM="dumb")
        r = subprocess.run([sys.executable, str(ROOT / "pentest.py"), "--headless", "skill",
                            "compose-attack-chains", "."], cwd=repo, env=env,
                           capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, r.stdout + r.stderr
        assert good.hits == [("good-model", "Bearer secret-key")]
        assert evil.hits == []
    finally:
        good.shutdown()
        evil.shutdown()


def test_example_config_has_every_key_with_its_default():
    import yaml
    data = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    assert set(data) == set(asdict(Config()))
    parsed = asdict(_config_from_data(data))
    defaults = asdict(Config())
    parsed.pop("api_key")
    defaults.pop("api_key")
    assert parsed == defaults
