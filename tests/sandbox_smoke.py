from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import sandbox as sb

MARKER = "ARAD_SMOKE_MARKER_7f3a"
SECRET = "host-only-secret-9d1c"
FAILS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  <- {detail}"))
    if not ok:
        FAILS.append(name)


class FakeLLM(BaseHTTPRequestHandler):
    requests: list[dict] = []
    auth: list[str] = []
    secret_path = ""

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        FakeLLM.requests.append(body)
        FakeLLM.auth.append(self.headers.get("Authorization", ""))
        turn = len(FakeLLM.requests)
        if turn == 1:
            calls = [
                {"id": "call_0", "type": "function",
                 "function": {"name": "search_graph",
                              "arguments": json.dumps({"name_pattern": "read_token"})}},
                {"id": "call_1", "type": "function",
                 "function": {"name": "grep", "arguments": json.dumps({"pattern": MARKER})}},
                {"id": "call_2", "type": "function",
                 "function": {"name": "read_file",
                              "arguments": json.dumps({"file_path": FakeLLM.secret_path})}},
            ]
        else:
            findings = {"findings": {"hypotheses": [], "evidence": [], "coverage": [],
                                     "open_questions": []}}
            calls = [{"id": f"call_f{turn}", "type": "function",
                      "function": {"name": "finish", "arguments": json.dumps(findings)}}]
        payload = {
            "id": f"chatcmpl-{turn}", "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model", "fake"),
            "choices": [{"index": 0, "finish_reason": "tool_calls",
                         "message": {"role": "assistant", "content": None, "tool_calls": calls}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=smoke@example.com", "-c", "user.name=smoke",
                    *args], cwd=repo, check=True, capture_output=True)


def tool_results(body: dict) -> dict:
    return {m.get("tool_call_id"): str(m.get("content")) for m in body.get("messages", [])
            if m.get("role") == "tool"}


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="arad-smoke-")).resolve()
    home = base / "home"
    home.mkdir()
    outside = base / "outside"
    outside.mkdir()
    secret_file = outside / "secret.txt"
    secret_file.write_text(SECRET + "\n")
    repo = base / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text(
        f"API_TOKEN = '{MARKER}'\n\n\ndef read_token():\n    return API_TOKEN\n")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "init")
    FakeLLM.secret_path = str(secret_file)

    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("PENTEST_", "ARAD_")) and k != "XDG_CACHE_HOME"}
    env.update({
        "HOME": str(home),
        "PENTEST_API_BASE": f"http://127.0.0.1:{port}/v1",
        "PENTEST_API_KEY": "smoke-key",
        "PENTEST_MODEL": "fake-model",
    })
    if os.environ.get(sb.IMAGE_ENV):
        env[sb.IMAGE_ENV] = os.environ[sb.IMAGE_ENV]
    cli = [sys.executable, str(ROOT / "arad.py"), "--headless"]

    if not env.get(sb.IMAGE_ENV):
        r = subprocess.run([*cli, "sandbox", "build"], env=env, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=3600, cwd=base)
        print(r.stdout[-2000:], r.stderr[-2000:], sep="\n")
        check("sandbox image builds", r.returncode == 0, str(r.returncode))

    r = subprocess.run([*cli, "init", str(repo)], env=env, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=900, cwd=base)
    print(r.stdout[-2000:], r.stderr[-2000:], sep="\n")
    check("init exits 0 inside the sandbox", r.returncode == 0, str(r.returncode))
    check("codebase-memory-mcp indexes inside the sandbox",
          "Indexed via codebase-memory-mcp" in r.stdout, r.stdout[-300:])
    check("the indexed project is found again by its path",
          "Code graph project:" in r.stdout, r.stdout[-300:])

    r = subprocess.run([*cli, "skill", "hunt-secrets-detection", str(repo)], env=env,
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=900,
                       cwd=base)
    print(r.stdout[-2000:], r.stderr[-2000:], sep="\n")
    check("skill exits 0 inside the sandbox", r.returncode == 0, str(r.returncode))
    check("no unsandboxed warning", "without the sandbox" not in r.stderr, r.stderr[-300:])
    check("model endpoint reached from the sandbox", len(FakeLLM.requests) >= 2,
          str(len(FakeLLM.requests)))
    check("api key forwarded by name", bool(FakeLLM.auth) and FakeLLM.auth[0] == "Bearer smoke-key",
          str(FakeLLM.auth[:1]))
    results = tool_results(FakeLLM.requests[1]) if len(FakeLLM.requests) >= 2 else {}
    check("graph tools answer inside the sandbox", "read_token" in results.get("call_0", ""),
          results.get("call_0", "")[:300])
    check("ripgrep works on the mounted repo", MARKER in results.get("call_1", ""),
          results.get("call_1", "")[:300])
    check("host file outside the repo is not readable",
          SECRET not in results.get("call_2", SECRET), results.get("call_2", "")[:300])
    db = home / ".pentest" / "evidence.db"
    check("evidence database written to the host", db.is_file(), str(db))
    transcripts = list((home / ".pentest" / "transcripts").rglob("*.jsonl"))
    check("conversation transcript written to the host", len(transcripts) == 1, str(transcripts))
    check("usage table printed after the sandboxed run", "Model usage" in r.stdout, r.stdout[-300:])
    if db.is_file() and hasattr(os, "getuid"):
        check("database owned by the host user", db.stat().st_uid == os.getuid(),
              str(db.stat().st_uid))

    runtime = sb.require_runtime(env)
    image = sb.image_tag(env)
    old_cwd = os.getcwd()
    os.chdir(base)
    try:
        plan = sb.make_plan(["run", str(repo)], environ=env, cwd=base, home=home)
    finally:
        os.chdir(old_cwd)
    probe = (
        f"cat {secret_file} >/dev/null 2>&1 && echo outside-readable || echo outside-hidden; "
        f"touch {repo}/x 2>/dev/null && echo repo-writable || echo repo-readonly; "
        "touch /usr/x 2>/dev/null && echo root-writable || echo root-readonly; "
        f"touch {home}/.pentest/probe && echo state-writable || echo state-readonly; "
        "grep CapEff /proc/self/status; id -u; "
        "test -n \"$PENTEST_API_KEY\" && echo key-present || echo key-missing; "
        "for t in rg git codebase-memory-mcp semgrep; do command -v $t; done"
    )
    argv = sb.run_argv(runtime, image, plan, ["sh", "-c", probe], environ=env)
    check("secret value never on the docker command line", "smoke-key" not in " ".join(argv))
    p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=300,
                       stdin=subprocess.DEVNULL)
    out = p.stdout
    print(out, p.stderr[-1000:], sep="\n")
    check("probe container ran", p.returncode == 0, p.stderr[-300:])
    check("host path outside the mounts is hidden", "outside-hidden" in out, out)
    check("repository is read-only", "repo-readonly" in out, out)
    check("root filesystem is read-only", "root-readonly" in out, out)
    check("state directory is writable", "state-writable" in out, out)
    check("all capabilities dropped", "CapEff:\t0000000000000000" in out, out)
    if hasattr(os, "getuid"):
        check("runs as the host uid", f"\n{os.getuid()}\n" in f"\n{out}", out)
    check("api key available inside", "key-present" in out, out)
    for tool in ("rg", "git", "codebase-memory-mcp", "semgrep"):
        check(f"{tool} installed in the image", f"/{tool}\n" in out, out)

    server.shutdown()
    print("\nALL PASS" if not FAILS else f"\n{len(FAILS)} FAILURES: {FAILS}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
