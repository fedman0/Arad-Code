from __future__ import annotations
import os
import yaml
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    model: str = "gpt-4o"
    api_base: str = "https://api.openai.com/v1"
    api_key: str = ""
    mcp_server: str = "codebase-memory-mcp"
    mcp_args: list[str] = field(default_factory=list)
    db_path: str = "~/.pentest/evidence.db"
    skills_dir: str = ""
    max_tokens: int = 8192
    temperature: float = 0.0
    reasoning_effort: str = ""
    profile_path: str = ""
    trust_repo_profile: bool = False
    mcp_allow: dict = field(default_factory=dict)

    def resolved_db(self) -> Path:
        return Path(self.db_path).expanduser()

    def resolved_skills(self) -> Path:
        if self.skills_dir:
            return Path(self.skills_dir).expanduser()
        return Path(__file__).parent.parent / "skills"


def _read_config_data(p: Path) -> dict:
    try:
        with open(p) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid YAML in config file {p}: {e}") from None
    except OSError as e:
        raise ValueError(f"cannot read config file {p}: {e.strerror or e}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"config file {p} must be a mapping of settings, "
                         f"not {type(data).__name__}")
    return data


def _opt(data: dict, key: str, default):
    value = data.get(key)
    return default if value is None else value


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, (int, float)):
        return value != 0
    return False


def _config_from_data(
    data: dict,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    env: Optional[dict] = None,
) -> Config:
    env = env or {}
    mcp_args = _opt(data, "mcp_args", [])
    if not isinstance(mcp_args, list):
        raise ValueError("mcp_args in the config file must be a list")
    mcp_allow = _opt(data, "mcp_allow", {})
    if not isinstance(mcp_allow, dict):
        raise ValueError("mcp_allow in the config file must be a mapping")
    return Config(
        model=model or env.get("PENTEST_MODEL") or _opt(data, "model", "gpt-4o"),
        api_base=api_base or env.get("PENTEST_API_BASE") or _opt(data, "api_base", "https://api.openai.com/v1"),
        api_key=api_key or env.get("PENTEST_API_KEY") or _opt(data, "api_key", ""),
        mcp_server=_opt(data, "mcp_server", "codebase-memory-mcp"),
        mcp_args=[str(a) for a in mcp_args],
        db_path=_opt(data, "db_path", "~/.pentest/evidence.db"),
        skills_dir=_opt(data, "skills_dir", ""),
        max_tokens=_opt(data, "max_tokens", 8192),
        temperature=_opt(data, "temperature", 0.0),
        reasoning_effort=env.get("PENTEST_REASONING_EFFORT") or _opt(data, "reasoning_effort", ""),
        profile_path=_opt(data, "profile_path", ""),
        trust_repo_profile=_as_bool(_opt(data, "trust_repo_profile", False)),
        mcp_allow=mcp_allow,
    )


def read_config_file(path: str = "~/.pentest/config.yaml") -> Config:
    p = Path(path).expanduser()
    data = _read_config_data(p) if p.exists() else {}
    return _config_from_data(data)


def load_config(
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    config_file: Optional[str] = None,
) -> Config:
    data: dict = {}

    if config_file is not None and not Path(config_file).expanduser().exists():
        raise ValueError(f"config file not found: {config_file}")

    candidates = [
        config_file,
        "./config.yaml",
        "~/.pentest/config.yaml",
    ]
    for path in candidates:
        if path is None:
            continue
        p = Path(path).expanduser()
        if p.exists():
            data = _read_config_data(p)
            break

    cfg = _config_from_data(data, api_base=api_base, api_key=api_key, model=model,
                            env=os.environ)

    if not cfg.api_key:
        raise ValueError("api_key is required (--api-key, PENTEST_API_KEY, or config.yaml)")

    return cfg


def save_config(cfg: Config, path: str = "~/.pentest/config.yaml"):
    import yaml
    p = Path(path).expanduser()
    if not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.parent.chmod(0o700)
        except OSError:
            pass
    data = asdict(cfg)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        yaml.dump(data, f, default_flow_style=False)
    return p
