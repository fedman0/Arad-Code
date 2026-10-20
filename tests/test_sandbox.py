import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import sandbox as sb

TUI_CMDS = {"run", "workflow", "skill", "deep-research"}


def _cli():
    import pentest
    return pentest.cli


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    repo = work / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("print('x')\n")
    monkeypatch.chdir(work)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    for name in list(os.environ):
        if name.startswith(("PENTEST_", "ARAD_")):
            monkeypatch.delenv(name, raising=False)
    environ = {"HOME": str(home), "PATH": "/usr/bin"}
    return {"home": home, "work": work, "repo": repo, "environ": environ}


def plan_for(args, env, tui=False, **kw):
    return sb.make_plan(args, cli=_cli(), tui=tui, environ=env["environ"], cwd=env["work"],
                        home=env["home"], uid=1234, gid=5678, **kw)


def mounts_by_dst(plan):
    return {m.dst: m for m in plan.mounts}


def test_trust_flag_removed_anywhere():
    args, flag = sb.split_trust_flag(["run", ".", "--allow-dangerously-trust", "-v"])
    assert flag and args == ["run", ".", "-v"]
    args, flag = sb.split_trust_flag(["--allow-dangerously-trust", "report", "."])
    assert flag and args == ["report", "."]
    args, flag = sb.split_trust_flag(["report", "."])
    assert not flag and args == ["report", "."]


@pytest.mark.parametrize("args,headless,expected", [
    (["run", "."], False, True),
    (["run", "."], True, True),
    (["skill", "hunt-xss", "."], True, True),
    (["verify", "abc", "."], False, True),
    (["init", "."], False, True),
    ([], False, True),
    (["workflow", "wf.py"], False, True),
    ([], True, False),
    (["report", "."], False, False),
    (["sarif", "."], False, False),
    (["triage", "."], False, False),
    (["list-skills"], False, False),
    (["config-init"], False, False),
    (["doctor", "."], False, False),
    (["sandbox", "build"], False, False),
    (["run", "--help"], False, False),
    (["--help"], False, False),
])
def test_which_commands_are_sandboxed(args, headless, expected):
    assert sb.wants_sandbox(args, headless, TUI_CMDS) is expected


def test_trust_from_env(env):
    assert sb.trust_reason(False, ["run", "."], {sb.TRUST_ENV: "1"}) == sb.TRUST_ENV
    assert sb.trust_reason(False, ["run", "."], {sb.TRUST_ENV: "true"}) == sb.TRUST_ENV
    assert sb.trust_reason(False, ["run", "."], {sb.TRUST_ENV: "0"}) == ""
    assert sb.trust_reason(True, ["run", "."], {}) == sb.TRUST_FLAG


def test_trust_from_user_config_only(env):
    (env["work"] / "config.yaml").write_text("allow_dangerously_trust: true\n")
    (env["repo"] / "config.yaml").write_text("allow_dangerously_trust: true\n")
    assert sb.trust_reason(False, ["run", "."], {}) == ""
    user = env["home"] / ".pentest" / "config.yaml"
    user.parent.mkdir()
    user.write_text("allow_dangerously_trust: false\n")
    assert sb.trust_reason(False, ["run", "."], {}) == ""
    user.write_text("allow_dangerously_trust: true\n")
    assert "config.yaml" in sb.trust_reason(False, ["run", "."], {})


def test_repo_config_cannot_disable_sandbox(env, monkeypatch):
    (env["repo"] / "config.yaml").write_text("allow_dangerously_trust: true\n")
    monkeypatch.chdir(env["repo"])
    called = []
    with pytest.raises(SystemExit):
        sb.gate(["run", "."], cli=_cli(), tui_cmds=TUI_CMDS, environ=dict(env["environ"]),
                warn=lambda s: pytest.fail(s), runner=lambda *a, **k: called.append(a) or 0)
    assert called
    with pytest.raises(SystemExit):
        sb.gate([], cli=_cli(), tui_cmds=TUI_CMDS, environ=dict(env["environ"]),
                warn=lambda s: pytest.fail(s), runner=lambda *a, **k: called.append(a) or 0)
    assert len(called) == 2


def test_trust_from_explicit_config(env):
    cfg = env["work"] / "mine.yaml"
    cfg.write_text("allow_dangerously_trust: yes\n")
    assert sb.trust_reason(False, ["run", ".", "--config", str(cfg)], {})
    assert sb.trust_reason(False, ["run", ".", f"--config={cfg}"], {})


def test_gate_inside_runs_directly():
    environ = {sb.INSIDE_ENV: "1"}
    called = []
    out = sb.gate(["--allow-dangerously-trust", "run", "."], tui_cmds=TUI_CMDS, environ=environ,
                  runner=lambda *a, **k: called.append(1) or 0)
    assert out == ["run", "."] and not called


def test_gate_trusted_warns_and_exports(env):
    environ = dict(env["environ"])
    warnings = []
    out = sb.gate(["run", ".", "--allow-dangerously-trust"], tui_cmds=TUI_CMDS, environ=environ,
                  warn=warnings.append, runner=lambda *a, **k: pytest.fail("must not sandbox"))
    assert out == ["run", "."]
    assert environ[sb.TRUST_ENV] == "1"
    assert len(warnings) == 1 and "without the sandbox" in warnings[0]


def test_gate_host_commands_untouched(env):
    out = sb.gate(["report", "."], tui_cmds=TUI_CMDS, environ=dict(env["environ"]),
                  warn=lambda s: pytest.fail(s), runner=lambda *a, **k: pytest.fail("no"))
    assert out == ["report", "."]


def test_gate_sandboxes_and_exits_with_child_code(env):
    seen = {}

    def runner(args, **kw):
        seen["args"] = args
        seen["tui"] = kw["tui"]
        return 7

    with pytest.raises(SystemExit) as exc:
        sb.gate(["--headless", "run", "repo"], tui_cmds=TUI_CMDS, environ=dict(env["environ"]),
                runner=runner)
    assert exc.value.code == 7
    assert seen == {"args": ["--headless", "run", "repo"], "tui": False}


def test_gate_reports_missing_runtime(env, monkeypatch):
    monkeypatch.setattr(sb, "detect_runtime", lambda environ=None, which=None: None)
    monkeypatch.setattr(sb, "image_tag", lambda environ=None: "x")
    warnings = []
    with pytest.raises(SystemExit) as exc:
        sb.gate(["run", "repo"], cli=_cli(), tui_cmds=TUI_CMDS, environ=dict(env["environ"]),
                warn=warnings.append)
    assert exc.value.code == 2
    assert "no container runtime" in warnings[-1] and sb.TRUST_FLAG in warnings[-1]


def test_gate_reports_daemon_down(env, monkeypatch):
    monkeypatch.setattr(sb, "detect_runtime", lambda environ=None, which=None: "/usr/bin/docker")
    monkeypatch.setattr(sb, "daemon_error", lambda rt: "Cannot connect to the Docker daemon")
    warnings = []
    with pytest.raises(SystemExit):
        sb.gate(["run", "repo"], cli=_cli(), tui_cmds=TUI_CMDS, environ=dict(env["environ"]),
                warn=warnings.append)
    assert "daemon is not reachable" in warnings[-1] and "Cannot connect" in warnings[-1]


def test_plan_mounts_repo_readonly_and_state_rw(env):
    plan = plan_for(["run", "repo"], env)
    m = mounts_by_dst(plan)
    repo = str(env["repo"].resolve())
    assert m[repo].readonly and m[repo].src == repo
    db_dir = str((env["home"] / ".pentest").resolve())
    cache = str((env["home"] / ".cache" / "pentest").resolve())
    assert not m[db_dir].readonly
    assert not m[cache].readonly
    ts = str((env["home"] / ".cache" / "tree-sitter-language-pack").resolve())
    assert not m[ts].readonly and m[ts].src.startswith(cache + "/sandbox/")
    assert plan.workdir == str(env["work"].resolve())
    assert plan.env_values["HOME"] == str(env["home"].resolve())
    assert plan.env_values[sb.INSIDE_ENV] == "1"
    assert plan.env_values["CBM_CACHE_DIR"].startswith(cache + "/sandbox/")
    assert plan.user == "1234:5678"
    assert str(env["work"].resolve()) not in m
    assert str(env["home"].resolve()) not in m


def test_plan_expands_tilde_with_its_own_home(env, tmp_path):
    other = tmp_path / "other-home"
    other.mkdir()
    environ = dict(env["environ"], HOME=str(other))
    plan = sb.make_plan(["run", "repo"], cli=_cli(), environ=environ, cwd=env["work"],
                        home=other, uid=1, gid=1)
    m = mounts_by_dst(plan)
    assert str((other / ".pentest").resolve()) in m
    assert str((env["home"] / ".pentest").resolve()) not in m


def test_plan_mounts_app_code_readonly(env):
    plan = plan_for(["run", "repo"], env)
    root = sb.app_root()
    m = mounts_by_dst(plan)
    for entry in ("core", "pentest.py", "arad.py", "skills"):
        assert m[str(root / entry)].readonly


def test_plan_refuses_home_and_root(env):
    with pytest.raises(sb.SandboxError):
        plan_for(["run", str(env["home"])], env)
    with pytest.raises(sb.SandboxError):
        plan_for(["run", "/"], env)


def test_plan_tui_mounts_cwd_unless_home(env, monkeypatch):
    plan = plan_for([], env, tui=True)
    assert mounts_by_dst(plan)[str(env["work"].resolve())].readonly
    monkeypatch.chdir(env["home"])
    plan = sb.make_plan([], cli=_cli(), tui=True, environ=env["environ"], cwd=env["home"],
                        home=env["home"], uid=1, gid=1)
    assert str(env["home"].resolve()) not in mounts_by_dst(plan)
    assert any("not shared" in n for n in plan.notes)


def test_plan_config_file_readonly_and_used(env):
    cfg = env["work"] / "conf.yaml"
    db = env["work"] / "state" / "ev.db"
    cfg.write_text(f"db_path: {db}\n")
    plan = plan_for(["run", "repo", "--config", str(cfg)], env)
    m = mounts_by_dst(plan)
    assert m[str(cfg.resolve())].readonly
    assert not m[str(db.parent.resolve())].readonly


def test_repo_config_cannot_choose_mounts(env, monkeypatch):
    evil = env["home"] / ".ssh"
    evil.mkdir()
    (env["repo"] / "config.yaml").write_text(
        f"db_path: {evil}/x.db\nskills_dir: {evil}\nprofile_path: {evil}\n"
        "api_base: http://127.0.0.1:9/v1\n")
    monkeypatch.chdir(env["repo"])
    plan = sb.make_plan(["run", "."], cli=_cli(), environ=env["environ"], cwd=env["repo"],
                        home=env["home"], uid=1, gid=1)
    assert not any(m.src.startswith(str(evil.resolve())) for m in plan.mounts)
    assert plan.network is None


def test_db_inside_repo_is_refused(env):
    cfg = env["work"] / "conf.yaml"
    cfg.write_text(f"db_path: {env['repo']}/state/ev.db\n")
    with pytest.raises(sb.SandboxError):
        plan_for(["run", "repo", "--config", str(cfg)], env)
    env["environ"]["XDG_CACHE_HOME"] = str(env["repo"] / "cache")
    with pytest.raises(sb.SandboxError):
        plan_for(["run", "repo"], env)
    assert sorted(p.name for p in env["repo"].iterdir()) == ["app.py"]


def test_loopback_api_uses_host_network(env):
    env["environ"]["PENTEST_API_BASE"] = "http://127.0.0.1:11434/v1"
    assert plan_for(["run", "repo"], env).network == "host"
    env["environ"]["PENTEST_API_BASE"] = "https://api.openai.com/v1"
    assert plan_for(["run", "repo"], env).network is None
    plan = plan_for(["run", "repo", "--api-base", "http://localhost:8000/v1"], env)
    assert plan.network == "host"
    env["environ"][sb.NETWORK_ENV] = "none"
    assert plan_for(["run", "repo"], env).network == "none"


def test_loopback_proxy_uses_host_network(env):
    env["environ"]["HTTPS_PROXY"] = "http://proxy.corp:3128"
    assert plan_for(["run", "repo"], env).network is None
    env["environ"]["HTTPS_PROXY"] = "http://127.0.0.1:10800"
    plan = plan_for(["run", "repo"], env)
    assert plan.network == "host" and any("proxy" in n for n in plan.notes)
    del env["environ"]["HTTPS_PROXY"]
    env["environ"]["no_proxy"] = "localhost,127.0.0.1"
    assert plan_for(["run", "repo"], env).network is None


def test_proxy_matches_the_host_shell(env):
    env["environ"]["HTTPS_PROXY"] = "http://user:pw@proxy.corp:3128"
    plan = plan_for(["run", "repo"], env)
    argv = sb.run_argv("/usr/bin/docker", "img:1", plan, ["x"], environ={})
    assert "user:pw" not in " ".join(argv)
    assert argv[argv.index("HTTPS_PROXY") - 1] == "--env"
    assert "HTTP_PROXY=" in argv and "http_proxy=" in argv and "NO_PROXY=" in argv
    assert "HTTPS_PROXY=" not in argv
    build = sb.proxy_build_args({"HTTPS_PROXY": "http://proxy.corp:3128"})
    assert "HTTPS_PROXY" in build and "HTTP_PROXY=" in build and "https_proxy=" in build


def test_secrets_are_passed_by_name_only(env):
    env["environ"]["PENTEST_API_KEY"] = "sk-supersecret-value"
    env["environ"]["AWS_SECRET_ACCESS_KEY"] = "aws-secret"
    env["environ"]["TERM"] = "xterm-256color"
    env["environ"][sb.TRUST_ENV] = "0"
    plan = plan_for(["run", "repo"], env)
    argv = sb.run_argv("/usr/bin/docker", "img:1", plan, ["python", "x"], environ={})
    joined = " ".join(argv)
    assert "sk-supersecret-value" not in joined
    assert "aws-secret" not in joined and "AWS_SECRET_ACCESS_KEY" not in joined
    i = argv.index("PENTEST_API_KEY")
    assert argv[i - 1] == "--env"
    assert "TERM" in argv
    assert sb.TRUST_ENV not in plan.env_names


def test_run_argv_hardening(env):
    plan = plan_for(["run", "repo"], env)
    argv = sb.run_argv("/usr/bin/docker", "img:1", plan, ["python", "-I", "x.py", "run"],
                       tty=False, environ={})
    assert argv[:3] == ["/usr/bin/docker", "run", "--rm"]
    assert "--init" in argv and "-i" in argv and "-t" not in argv
    assert "--read-only" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--pids-limit") + 1] == sb.DEFAULT_PIDS
    assert argv[argv.index("--memory") + 1] == sb.DEFAULT_MEMORY
    assert argv[argv.index("--tmpfs") + 1].startswith("/tmp:")
    assert argv[argv.index("--user") + 1] == "1234:5678"
    assert "--userns=keep-id" not in argv
    assert argv[argv.index("img:1") + 1:] == ["python", "-I", "x.py", "run"]
    specs = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    repo = str(env["repo"].resolve())
    assert f"type=bind,src={repo},dst={repo},readonly" in specs
    assert all(s.startswith("type=bind,") for s in specs)


def test_run_argv_tty_podman_and_limits(env):
    plan = plan_for([], env, tui=True)
    argv = sb.run_argv("/usr/bin/podman", "img:1", plan, ["python"], tty=True,
                       environ={sb.MEMORY_ENV: "8g", sb.PIDS_ENV: "64"})
    assert "-t" in argv and "--userns=keep-id" in argv
    assert argv[argv.index("--memory") + 1] == "8g"
    assert argv[argv.index("--pids-limit") + 1] == "64"


def test_mount_spec_quotes_commas():
    spec = sb.Mount("/a,b", "/a,b", False).spec()
    assert spec == 'type=bind,"src=/a,b","dst=/a,b"'


def test_inner_command_uses_same_entry():
    root = sb.app_root()
    assert sb.inner_command(["--headless", "run", "."]) == [
        "python", "-I", "-B", str(root / "arad.py"), "--headless", "run", "."]


def test_image_tag_tracks_version_and_inputs(monkeypatch):
    tag = sb.image_tag({})
    assert tag.startswith(f"{sb.IMAGE_NAME}:{sb.app_version()}-")
    assert sb.image_tag({sb.IMAGE_ENV: "registry/arad:1"}) == "registry/arad:1"


def test_detect_runtime_prefers_docker():
    found = {"docker": "/usr/bin/docker", "podman": "/usr/bin/podman"}
    assert sb.detect_runtime({}, which=found.get) == "/usr/bin/docker"
    assert sb.detect_runtime({}, which={"podman": "/usr/bin/podman"}.get) == "/usr/bin/podman"
    assert sb.detect_runtime({}, which={}.get) is None
    assert sb.detect_runtime({sb.RUNTIME_ENV: "podman"}, which=found.get) == "/usr/bin/podman"


def test_click_paths_parse_real_commands(env):
    cli = _cli()
    assert sb.click_path_values(cli, ["skill", "hunt-xss", "repo"]) == [("repo_path", "repo")]
    assert sb.click_path_values(cli, ["verify", "abc123", "repo", "--config", "c.yaml"]) == [
        ("repo_path", "repo"), ("config_file", "c.yaml")]
    assert sb.click_path_values(cli, ["run", "missing-dir"]) == []
    assert sb.click_path_values(cli, ["workflow", "x"]) is None


def test_main_strips_flag_for_host_commands(env, monkeypatch, capsys):
    import pentest
    seen = {}
    monkeypatch.setattr(pentest, "_run_headless", lambda args, tui_available=True: seen.setdefault("args", args))
    pentest.main(["--allow-dangerously-trust", "list-skills"])
    assert seen["args"] == ["list-skills"]


def test_custom_transcripts_dir_is_mounted_read_write(env):
    cfg = env["home"] / "custom.yaml"
    out = env["home"] / "logs" / "arad"
    cfg.write_text(f"transcripts_dir: {out}\n")
    plan = plan_for(["run", "repo", "--config", str(cfg)], env, create_dirs=False)
    m = mounts_by_dst(plan)
    assert str(out.resolve()) in m and not m[str(out.resolve())].readonly


def test_default_transcripts_need_no_extra_mount(env):
    plan = plan_for(["run", "repo"], env, create_dirs=False)
    assert not any(dst.endswith("/transcripts") for dst in mounts_by_dst(plan))


def test_transcripts_inside_the_repo_are_refused(env):
    (env["repo"] / "logs").mkdir()
    cfg = env["home"] / "c.yaml"
    cfg.write_text(f"transcripts_dir: {env['repo'] / 'logs'}\n")
    with pytest.raises(sb.SandboxError, match="transcripts_dir"):
        plan_for(["run", "repo", "--config", str(cfg)], env, create_dirs=False)


def test_dockerfile_is_found_in_an_installed_package(tmp_path, monkeypatch):
    root = tmp_path / "site-packages"
    (root / "arad_sandbox").mkdir(parents=True)
    (root / "arad_sandbox" / "Dockerfile").write_text("FROM scratch\n")
    monkeypatch.setattr(sb, "app_root", lambda: root)
    assert sb.dockerfile_path() == root / "arad_sandbox" / "Dockerfile"
