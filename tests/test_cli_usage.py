import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append(body)
        reply = {
            "id": "c1", "object": "chat.completion", "created": 0, "model": body.get("model", "m"),
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [{
                    "id": "t1", "type": "function", "function": {
                        "name": "finish",
                        "arguments": json.dumps({"findings": {"hypotheses": [], "coverage": [],
                                                              "open_questions": []}})}}]}}],
            "usage": {"prompt_tokens": 2000, "completion_tokens": 100, "total_tokens": 2100},
        }
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture()
def fake_api():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture()
def env(tmp_path, fake_api):
    home = tmp_path / "home"
    home.mkdir()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"model: test-model\n"
        f"api_base: http://127.0.0.1:{fake_api.server_address[1]}/v1\n"
        f"api_key: k\n"
        f"db_path: {tmp_path / 'state' / 'e.db'}\n"
        f"mcp_server: /nonexistent/codebase-memory-mcp\n"
        f"max_retries: 0\n"
        f"pricing:\n  test-model:\n    input: 1.0\n    output: 4.0\n"
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "i"],
                   cwd=repo, check=True)
    e = {k: v for k, v in os.environ.items() if not k.startswith("PENTEST_")}
    e.update(HOME=str(home), XDG_CACHE_HOME=str(tmp_path / "cache"), COLUMNS="200",
             NO_COLOR="1", TERM="dumb")
    return {"cfg": str(cfg), "repo": str(repo), "env": e, "tmp": tmp_path}


def cli(env, *args):
    return subprocess.run([sys.executable, str(ROOT / "pentest.py"), "--headless", *args],
                          capture_output=True, text=True, env=env["env"], cwd=env["tmp"], timeout=300)


def test_skill_prints_usage_and_saves_it(env, fake_api):
    r = cli(env, "skill", "compose-attack-chains", env["repo"], "--config", env["cfg"])
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Model usage" in r.stdout and "test-model" in r.stdout
    assert "$0.00" in r.stdout and "2.0k" in r.stdout
    assert "Conversations saved in" in r.stdout
    assert fake_api.requests and fake_api.requests[0]["model"] == "test-model"
    listing = cli(env, "usage", env["repo"], "--config", env["cfg"])
    assert listing.returncode == 0, listing.stderr
    assert "test-model" in listing.stdout and "2.1k" in listing.stdout
    run_id = listing.stdout.split("\n")
    detail_line = next(line for line in run_id if "test-model" in line)
    rid = detail_line.split()[0]
    detail = cli(env, "usage", env["repo"], "--run", rid, "--config", env["cfg"])
    assert detail.returncode == 0 and "compose-attack-chains" in detail.stdout
    files = list((env["tmp"] / "state" / "transcripts").rglob("*.jsonl"))
    assert len(files) == 1


def test_no_transcripts_flag(env):
    r = cli(env, "skill", "compose-attack-chains", env["repo"], "--config", env["cfg"],
            "--no-transcripts")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Conversations saved in" not in r.stdout
    assert not (env["tmp"] / "state" / "transcripts").exists()


def test_dollar_budget_needs_prices(env):
    r = cli(env, "skill", "compose-attack-chains", env["repo"], "--config", env["cfg"],
            "--model", "unpriced-model", "--budget", "1")
    assert r.returncode != 0
    assert "needs prices for unpriced-model" in (r.stdout + r.stderr)


def test_token_budget_stops_a_run_with_exit_code_3(env, fake_api):
    r = cli(env, "run", env["repo"], "--phase", "p1", "--config", env["cfg"], "--token-budget", "4000")
    assert r.returncode == 3, r.stdout + r.stderr
    assert "token budget reached" in r.stdout and "--resume" in r.stdout
    assert len(fake_api.requests) == 2
