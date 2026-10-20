from __future__ import annotations
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, MutableMapping, Optional, Sequence
from urllib.parse import urlsplit

TRUST_FLAG = "--allow-dangerously-trust"
TRUST_ENV = "ARAD_ALLOW_DANGEROUSLY_TRUST"
TRUST_KEY = "allow_dangerously_trust"
INSIDE_ENV = "ARAD_IN_SANDBOX"
IMAGE_ENV = "ARAD_SANDBOX_IMAGE"
RUNTIME_ENV = "ARAD_SANDBOX_RUNTIME"
NETWORK_ENV = "ARAD_SANDBOX_NETWORK"
MEMORY_ENV = "ARAD_SANDBOX_MEMORY"
PIDS_ENV = "ARAD_SANDBOX_PIDS"
SEMGREP_ENV = "ARAD_SANDBOX_SEMGREP"
CONFIG_SETTINGS = (
    (RUNTIME_ENV, "sandbox_runtime"),
    (IMAGE_ENV, "sandbox_image"),
    (NETWORK_ENV, "sandbox_network"),
    (MEMORY_ENV, "sandbox_memory"),
    (PIDS_ENV, "sandbox_pids"),
    (SEMGREP_ENV, "sandbox_semgrep"),
)
IMAGE_NAME = "arad-code-sandbox"
DEFAULT_MEMORY = "4g"
DEFAULT_PIDS = "1024"
SANDBOXED_COMMANDS = frozenset({"run", "skill", "verify", "init", "workflow", "deep-research"})
PASS_ENV_PREFIXES = ("PENTEST_", "ARAD_")
PASS_ENV_NAMES = (
    "TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "COLUMNS", "LINES",
    "NO_COLOR", "FORCE_COLOR",
)
PROXY_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "FTP_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy",
)
NEVER_PASS = frozenset({INSIDE_ENV, TRUST_ENV, "XDG_CACHE_HOME", "HOME", "CBM_CACHE_DIR"})
USER_CONFIG = "~/.pentest/config.yaml"
CONFIG_ENV = "PENTEST_CONFIG"
APP_ENTRIES = ("core", "pentest.py", "arad.py", "skills", "arad_skills")
_TRUE = frozenset({"1", "true", "yes", "on"})


class SandboxError(Exception):
    pass


@dataclass(frozen=True)
class Mount:
    src: str
    dst: str
    readonly: bool = True

    def spec(self) -> str:
        parts = ["type=bind", _mount_field("src", self.src), _mount_field("dst", self.dst)]
        if self.readonly:
            parts.append("readonly")
        return ",".join(parts)


@dataclass
class Plan:
    mounts: list[Mount] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)
    env_values: dict[str, str] = field(default_factory=dict)
    workdir: str = "/"
    network: Optional[str] = None
    user: Optional[str] = None
    notes: list[str] = field(default_factory=list)


def _mount_field(key: str, value: str) -> str:
    text = f"{key}={value}"
    if "," in value or '"' in value:
        return '"' + text.replace('"', '""') + '"'
    return text


def app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def dockerfile_path() -> Path:
    for folder in ("sandbox", "arad_sandbox"):
        candidate = app_root() / folder / "Dockerfile"
        if candidate.is_file():
            return candidate
    return app_root() / "sandbox" / "Dockerfile"


def is_truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in _TRUE
    return False


def split_trust_flag(args: Sequence[str]) -> tuple[list[str], bool]:
    kept = [a for a in args if a != TRUST_FLAG]
    return kept, len(kept) != len(args)


def first_command(args: Sequence[str]) -> str:
    return next((a for a in args if not a.startswith("-")), "")


def option_value(args: Sequence[str], name: str) -> Optional[str]:
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None


def launches_tui(args: Sequence[str], headless: bool, tui_cmds) -> bool:
    if headless:
        return False
    return not args or first_command(args) in tui_cmds


def wants_sandbox(args: Sequence[str], headless: bool, tui_cmds) -> bool:
    if "--help" in args:
        return False
    if launches_tui(args, headless, tui_cmds):
        return True
    return first_command(args) in SANDBOXED_COMMANDS


def _read_yaml(path: Path) -> dict:
    import yaml
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def home_of(environ: Mapping[str, str]) -> Path:
    return Path(environ.get("HOME") or Path.home())


def expand(raw: str, home: Path, cwd: Optional[Path] = None) -> Path:
    if raw == "~":
        p = home
    elif raw.startswith("~/"):
        p = home / raw[2:]
    else:
        p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (cwd or Path.cwd()) / p
    return p


def trust_reason(flag: bool, args: Sequence[str], environ: Mapping[str, str],
                 cwd: Optional[Path] = None) -> str:
    if flag:
        return TRUST_FLAG
    if is_truthy(environ.get(TRUST_ENV, "")):
        return TRUST_ENV
    path = effective_config_file(args, home_of(environ), cwd or Path.cwd(), environ)
    if path is not None and path.is_file() and is_truthy(_read_yaml(path).get(TRUST_KEY)):
        return f"{TRUST_KEY} in {path}"
    return ""


def effective_config_file(args: Sequence[str], home: Path, cwd: Path,
                          environ: Optional[Mapping[str, str]] = None) -> Optional[Path]:
    from . import config as _config
    environ = os.environ if environ is None else environ
    explicit = option_value(args, "--config") or environ.get(CONFIG_ENV, "")
    if explicit:
        p = expand(explicit, home, cwd)
        return p.resolve() if p.exists() else None
    for p in (_config.app_config_path(), expand(USER_CONFIG, home, cwd)):
        if p.exists():
            return p.resolve()
    return None


def with_config_settings(args: Sequence[str], environ: Mapping[str, str],
                         cwd: Optional[Path] = None) -> dict:
    merged = dict(environ)
    path = effective_config_file(args, home_of(environ), cwd or Path.cwd(), environ)
    data = _read_yaml(path) if path is not None else {}
    for env_name, key in CONFIG_SETTINGS:
        value = data.get(key)
        if merged.get(env_name) or value is None or value == "":
            continue
        merged[env_name] = ("1" if is_truthy(value) else "0") if isinstance(value, bool) else str(value)
    return merged


def effective_config(args: Sequence[str], environ: Mapping[str, str], home: Path, cwd: Path,
                     api_base: Optional[str] = None):
    from .config import _config_from_data
    path = effective_config_file(args, home, cwd, environ)
    data = _read_yaml(path) if path else {}
    try:
        return _config_from_data(data, api_base=api_base, env=dict(environ)), path
    except ValueError as e:
        raise SandboxError(str(e)) from None


def is_loopback_url(url: str) -> bool:
    try:
        host = (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def loopback_proxy(environ: Mapping[str, str]) -> str:
    for name in PROXY_NAMES:
        value = environ.get(name, "")
        if value and not name.lower().startswith("no_") and is_loopback_url(value):
            return value
    return ""


def proxy_build_args(environ: Mapping[str, str]) -> list[str]:
    out: list[str] = []
    for name in PROXY_NAMES:
        out += ["--build-arg", name if environ.get(name) else f"{name}="]
    return out


def app_version() -> str:
    try:
        from .version import VERSION
        return str(VERSION)
    except ImportError:
        pass
    try:
        text = (app_root() / "core" / "tui.py").read_text(encoding="utf-8")
    except OSError:
        return "dev"
    m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    return m.group(1) if m else "dev"


def requirements_text() -> str:
    req = app_root() / "requirements.txt"
    if req.is_file():
        return req.read_text(encoding="utf-8")
    try:
        from importlib.metadata import PackageNotFoundError, requires
    except ImportError:
        requires = None
    if requires is not None:
        for name in ("arad-code", "arad_code"):
            try:
                reqs = requires(name) or []
            except PackageNotFoundError:
                continue
            lines = [r for r in reqs if "extra ==" not in r]
            if lines:
                return "\n".join(lines) + "\n"
    raise SandboxError("cannot find the project requirements to build the sandbox image "
                       f"(looked for {req} and the installed package metadata)")


def image_tag(environ: Optional[Mapping[str, str]] = None) -> str:
    environ = os.environ if environ is None else environ
    custom = environ.get(IMAGE_ENV, "").strip()
    if custom:
        return custom
    df = dockerfile_path()
    try:
        df_bytes = df.read_bytes()
    except OSError:
        raise SandboxError(f"sandbox Dockerfile not found at {df}") from None
    digest = hashlib.sha256(df_bytes + b"\0" + requirements_text().encode()).hexdigest()[:12]
    return f"{IMAGE_NAME}:{app_version()}-{digest}"


def detect_runtime(environ: Optional[Mapping[str, str]] = None,
                   which: Callable[[str], Optional[str]] = shutil.which) -> Optional[str]:
    environ = os.environ if environ is None else environ
    forced = environ.get(RUNTIME_ENV, "").strip()
    if forced:
        return which(forced) or None
    return which("docker") or which("podman")


def runtime_is_podman(runtime: str) -> bool:
    return Path(runtime).name.startswith("podman")


def daemon_error(runtime: str) -> str:
    try:
        r = subprocess.run([runtime, "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "timed out talking to the daemon"
    except OSError as e:
        return str(e)
    if r.returncode == 0:
        return ""
    lines = [ln.strip() for ln in (r.stderr or r.stdout or "").splitlines() if ln.strip()]
    return lines[-1] if lines else f"exit status {r.returncode}"


def image_exists(runtime: str, tag: str) -> bool:
    try:
        r = subprocess.run([runtime, "image", "inspect", tag], capture_output=True,
                           timeout=60, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def build_image(runtime: str, tag: str, semgrep: bool = True,
                log: Callable[[str], None] = lambda s: print(s, file=sys.stderr)) -> None:
    df = dockerfile_path()
    if not df.is_file():
        raise SandboxError(f"sandbox Dockerfile not found at {df}")
    reqs = requirements_text()
    with tempfile.TemporaryDirectory(prefix="arad-sandbox-") as ctx:
        shutil.copyfile(df, Path(ctx) / "Dockerfile")
        (Path(ctx) / "requirements.txt").write_text(reqs, encoding="utf-8")
        argv = [runtime, "build", "-t", tag, "--build-arg", f"WITH_SEMGREP={1 if semgrep else 0}"]
        argv += proxy_build_args(os.environ)
        if loopback_proxy(os.environ):
            argv += ["--network", "host"]
        argv += ["-f", str(Path(ctx) / "Dockerfile"), ctx]
        log(f"Building the sandbox image {tag}. The first build takes a few minutes.")
        try:
            r = subprocess.run(argv, stdin=subprocess.DEVNULL)
        except OSError as e:
            raise SandboxError(f"could not run {runtime}: {e}") from None
    if r.returncode != 0:
        raise SandboxError(f"building the sandbox image failed (exit status {r.returncode})")


def _is_unsafe_root(path: Path, home: Path) -> bool:
    if path == Path(path.anchor):
        return True
    try:
        home.relative_to(path)
        return True
    except ValueError:
        return False


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def click_path_values(cli, args: Sequence[str]) -> Optional[list[tuple[str, str]]]:
    if cli is None:
        return None
    import click
    name = first_command(args)
    if not name:
        return []
    cmd = getattr(cli, "commands", {}).get(name)
    if cmd is None:
        return None
    sub = list(args[list(args).index(name) + 1:])
    try:
        ctx = cmd.make_context(name, sub, resilient_parsing=True)
    except (click.ClickException, click.exceptions.Exit, click.exceptions.Abort):
        return []
    out: list[tuple[str, str]] = []
    for param in cmd.params:
        if isinstance(param.type, click.Path):
            value = ctx.params.get(param.name)
            if value:
                out.append((param.name, str(value)))
    return out


def requested_paths(cli, args: Sequence[str], cwd: Path) -> list[Path]:
    values = click_path_values(cli, args)
    if values is None:
        name = first_command(args)
        tail = list(args[list(args).index(name) + 1:]) if name else list(args)
        candidates = [a for a in tail if not a.startswith("-")]
    else:
        candidates = [v for k, v in values if k != "config_file"]
    out: list[Path] = []
    for raw in candidates:
        p = Path(raw).expanduser()
        p = (p if p.is_absolute() else cwd / p)
        if p.exists():
            out.append(p.resolve())
    return out


def _add(mounts: list[Mount], mount: Mount) -> None:
    for i, m in enumerate(mounts):
        if m.dst == mount.dst:
            if m.readonly and not mount.readonly:
                mounts[i] = mount
            return
    mounts.append(mount)


def make_plan(args: Sequence[str], *, cli=None, tui: bool = False,
              environ: Optional[Mapping[str, str]] = None,
              cwd: Optional[Path] = None, home: Optional[Path] = None,
              root: Optional[Path] = None, uid: Optional[int] = None,
              gid: Optional[int] = None, create_dirs: bool = True) -> Plan:
    environ = dict(os.environ if environ is None else environ)
    cwd = (cwd or Path.cwd()).resolve()
    home = (home or Path(environ.get("HOME") or Path.home())).expanduser().resolve()
    root = (root or app_root()).resolve()
    plan = Plan(workdir=str(cwd))

    for path in requested_paths(cli, args, cwd):
        if _is_unsafe_root(path, home):
            raise SandboxError(f"refusing to expose {path} to the sandbox; "
                               "point arad at a project directory instead")
        _add(plan.mounts, Mount(str(path), str(path), True))

    if tui:
        if _is_unsafe_root(cwd, home):
            plan.notes.append(f"the current directory {cwd} is not shared with the sandbox; "
                              "start arad inside the project you want to scan")
        else:
            _add(plan.mounts, Mount(str(cwd), str(cwd), True))

    api_override = option_value(args, "--api-base")
    cfg, cfg_path = effective_config(args, environ, home, cwd, api_base=api_override)

    for entry in APP_ENTRIES:
        p = root / entry
        if p.exists():
            _add(plan.mounts, Mount(str(p), str(p), True))
    if cfg.skills_dir:
        sd = expand(cfg.skills_dir, home, cwd)
        if sd.exists():
            _add(plan.mounts, Mount(str(sd.resolve()), str(sd.resolve()), True))
    if cfg.profile_path:
        pp = expand(cfg.profile_path, home, cwd)
        if pp.exists():
            _add(plan.mounts, Mount(str(pp.resolve()), str(pp.resolve()), True))

    db_dir = expand(cfg.db_path, home, cwd).parent.resolve()
    xdg = expand(environ.get("XDG_CACHE_HOME") or str(home / ".cache"), home, cwd).resolve()
    cache_dir = xdg / "pentest"
    sandbox_cache = cache_dir / "sandbox"
    tslp_src = sandbox_cache / "tree-sitter-language-pack"
    cbm_dir = sandbox_cache / "codebase-memory-mcp"
    app_paths = {str(root / e) for e in APP_ENTRIES}
    for m in plan.mounts:
        if m.readonly and m.src not in app_paths and (
                _inside(db_dir, Path(m.src)) or _inside(cache_dir, Path(m.src))):
            raise SandboxError(f"the evidence database or cache ({db_dir}) is inside {m.src}; "
                               "move db_path or XDG_CACHE_HOME out of the scanned directory "
                               "to use the sandbox")
    if _is_unsafe_root(db_dir, home) or _is_unsafe_root(cache_dir, home):
        raise SandboxError(f"refusing to share {db_dir} read-write with the sandbox; "
                           "set db_path to a file inside a dedicated directory")
    transcripts = cfg.resolved_transcripts()
    if transcripts is not None:
        transcripts = expand(str(transcripts), home, cwd).resolve()
        if _inside(transcripts, db_dir) or _inside(transcripts, cache_dir):
            transcripts = None
    if transcripts is not None:
        for m in plan.mounts:
            if m.readonly and m.src not in app_paths and _inside(transcripts, Path(m.src)):
                raise SandboxError(f"transcripts_dir ({transcripts}) is inside {m.src}; move it "
                                   "out of the scanned directory to use the sandbox")
        if _is_unsafe_root(transcripts, home):
            raise SandboxError(f"refusing to share {transcripts} read-write with the sandbox; "
                               "set transcripts_dir to a dedicated directory")
    if create_dirs:
        for d in (db_dir, cache_dir, tslp_src, cbm_dir) + ((transcripts,) if transcripts else ()):
            d.mkdir(parents=True, exist_ok=True)
            try:
                d.chmod(0o700)
            except OSError:
                pass
    _add(plan.mounts, Mount(str(db_dir), str(db_dir), False))
    _add(plan.mounts, Mount(str(cache_dir), str(cache_dir), False))
    if transcripts is not None:
        _add(plan.mounts, Mount(str(transcripts), str(transcripts), False))
    _add(plan.mounts, Mount(str(tslp_src.resolve()), str(xdg / "tree-sitter-language-pack"), False))
    if cfg_path is not None:
        _add(plan.mounts, Mount(str(cfg_path), str(cfg_path), True))
        for i, m in enumerate(plan.mounts):
            if m.dst == str(cfg_path) and not m.readonly:
                plan.mounts[i] = Mount(m.src, m.dst, True)

    plan.env_values = {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(xdg),
        "CBM_CACHE_DIR": str(cbm_dir.resolve()),
        INSIDE_ENV: "1",
    }
    for name in PROXY_NAMES:
        if not environ.get(name):
            plan.env_values[name] = ""
    plan.env_names = sorted(
        name for name in environ
        if name not in NEVER_PASS and environ.get(name, "") != ""
        and (name in PASS_ENV_NAMES or name in PROXY_NAMES
             or name.startswith(PASS_ENV_PREFIXES))
    )

    forced_net = environ.get(NETWORK_ENV, "").strip()
    proxy = loopback_proxy(environ)
    if forced_net:
        plan.network = forced_net
    elif is_loopback_url(cfg.api_base):
        plan.network = "host"
        plan.notes.append(f"the model endpoint {cfg.api_base} is on this machine, so the "
                          "sandbox shares the host network")
    elif proxy:
        plan.network = "host"
        plan.notes.append("your proxy is on this machine, so the sandbox shares the host network")

    if uid is None and hasattr(os, "getuid"):
        uid, gid = os.getuid(), os.getgid()
    if uid is not None:
        plan.user = f"{uid}:{gid if gid is not None else uid}"
    return plan


def run_argv(runtime: str, image: str, plan: Plan, inner: Sequence[str], *,
             tty: bool = False, environ: Optional[Mapping[str, str]] = None) -> list[str]:
    environ = os.environ if environ is None else environ
    argv = [runtime, "run", "--rm", "--init", "-i"]
    if tty:
        argv.append("-t")
    argv += [
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g,mode=1777",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(environ.get(PIDS_ENV) or DEFAULT_PIDS),
        "--memory", str(environ.get(MEMORY_ENV) or DEFAULT_MEMORY),
    ]
    if runtime_is_podman(runtime):
        argv.append("--userns=keep-id")
    if plan.user:
        argv += ["--user", plan.user]
    if plan.network:
        argv += ["--network", plan.network]
    argv += ["--workdir", plan.workdir]
    for name, value in plan.env_values.items():
        argv += ["--env", f"{name}={value}"]
    for name in plan.env_names:
        argv += ["--env", name]
    for m in sorted(plan.mounts, key=lambda m: (m.dst.count("/"), m.dst)):
        argv += ["--mount", m.spec()]
    argv.append(image)
    argv += list(inner)
    return argv


def inner_command(args: Sequence[str], root: Optional[Path] = None) -> list[str]:
    root = root or app_root()
    return ["python", "-I", "-B", str(root / "arad.py"), *args]


def ensure_image(runtime: str, environ: Optional[Mapping[str, str]] = None,
                 log: Callable[[str], None] = lambda s: print(s, file=sys.stderr)) -> str:
    environ = os.environ if environ is None else environ
    tag = image_tag(environ)
    if image_exists(runtime, tag):
        return tag
    if environ.get(IMAGE_ENV, "").strip():
        raise SandboxError(f"sandbox image {tag} (from {IMAGE_ENV} or sandbox_image) "
                           "is not available locally")
    build_image(runtime, tag, semgrep=is_truthy(environ.get(SEMGREP_ENV, "1")), log=log)
    return tag


def require_runtime(environ: Optional[Mapping[str, str]] = None) -> str:
    runtime = detect_runtime(environ)
    if not runtime:
        raise SandboxError(
            "no container runtime found. Arad runs the model's tools inside a Docker or "
            "Podman container by default. Install Docker or Podman, or pass "
            f"{TRUST_FLAG} to run without the sandbox.")
    problem = daemon_error(runtime)
    if problem:
        name = Path(runtime).name
        raise SandboxError(
            f"{name} is installed but its daemon is not reachable ({problem}). Start {name}, "
            f"or pass {TRUST_FLAG} to run without the sandbox.")
    return runtime


def _wait(proc: subprocess.Popen) -> int:
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            continue


def run_sandboxed(args: Sequence[str], *, cli=None, tui: bool = False,
                  environ: Optional[Mapping[str, str]] = None,
                  log: Callable[[str], None] = lambda s: print(s, file=sys.stderr)) -> int:
    environ = os.environ if environ is None else environ
    rest = [a for a in args if a != "--headless"]
    environ = with_config_settings(rest, environ)
    plan = make_plan(rest, cli=cli, tui=tui, environ=environ)
    runtime = require_runtime(environ)
    image = ensure_image(runtime, environ, log=log)
    for note in plan.notes:
        log(f"sandbox: {note}")
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    argv = run_argv(runtime, image, plan, inner_command(args), tty=tty, environ=environ)
    try:
        proc = subprocess.Popen(argv)
    except OSError as e:
        raise SandboxError(f"could not start {runtime}: {e}") from None
    return _wait(proc)


def gate(args: Sequence[str], *, cli=None, tui_cmds=frozenset(),
         environ: Optional[MutableMapping[str, str]] = None,
         warn: Callable[[str], None] = lambda s: print(s, file=sys.stderr),
         runner: Callable[..., int] = run_sandboxed) -> list[str]:
    environ = os.environ if environ is None else environ
    args, flag = split_trust_flag(args)
    if environ.get(INSIDE_ENV) == "1":
        return args
    headless = "--headless" in args
    rest = [a for a in args if a != "--headless"]
    if not wants_sandbox(rest, headless, tui_cmds):
        return args
    reason = trust_reason(flag, rest, environ)
    if reason:
        environ[TRUST_ENV] = "1"
        warn(f"Running without the sandbox ({reason}): the model's tools run directly on "
             "this machine.")
        return args
    try:
        code = runner(args, cli=cli, tui=launches_tui(rest, headless, tui_cmds),
                      environ=environ, log=warn)
    except SandboxError as e:
        warn(f"Error: {e}")
        code = 2
    raise SystemExit(code)


def status(args: Sequence[str] = (), environ: Optional[Mapping[str, str]] = None) -> list[tuple[str, str]]:
    environ = with_config_settings(args, os.environ if environ is None else environ)
    rows: list[tuple[str, str]] = []
    reason = trust_reason(False, args, environ)
    rows.append(("mode", f"disabled by {reason}" if reason else "enabled"))
    runtime = detect_runtime(environ)
    rows.append(("runtime", runtime or "not found"))
    if runtime:
        problem = daemon_error(runtime)
        rows.append(("daemon", f"not reachable ({problem})" if problem else "running"))
    try:
        tag = image_tag(environ)
        rows.append(("image", tag))
        if runtime:
            rows.append(("image built", "yes" if image_exists(runtime, tag) else "no (built on first use)"))
    except SandboxError as e:
        rows.append(("image", f"unavailable: {e}"))
    return rows
