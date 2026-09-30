from __future__ import annotations
import os
import yaml
from dataclasses import dataclass, field
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


def load_config(
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    config_file: Optional[str] = None,
) -> Config:
    data: dict = {}

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
            with open(p) as f:
                data = yaml.safe_load(f) or {}
            break

    cfg = Config(
        model=model or os.environ.get("PENTEST_MODEL") or data.get("model", "gpt-4o"),
        api_base=api_base or os.environ.get("PENTEST_API_BASE") or data.get("api_base", "https://api.openai.com/v1"),
        api_key=api_key or os.environ.get("PENTEST_API_KEY") or data.get("api_key", ""),
        mcp_server=data.get("mcp_server", "codebase-memory-mcp"),
        mcp_args=data.get("mcp_args", []),
        db_path=data.get("db_path", "~/.pentest/evidence.db"),
        skills_dir=data.get("skills_dir", ""),
        max_tokens=data.get("max_tokens", 8192),
        temperature=data.get("temperature", 0.0),
        reasoning_effort=os.environ.get("PENTEST_REASONING_EFFORT") or data.get("reasoning_effort", ""),
        profile_path=data.get("profile_path", ""),
        trust_repo_profile=bool(data.get("trust_repo_profile", False)),
        mcp_allow=data.get("mcp_allow", {}),
    )

    if not cfg.api_key:
        raise ValueError("api_key is required (--api-key, PENTEST_API_KEY, or config.yaml)")

    return cfg


def save_config(cfg: Config, path: str = "~/.pentest/config.yaml"):
    import yaml
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "model": cfg.model,
        "api_base": cfg.api_base,
        "api_key": cfg.api_key,
        "mcp_server": cfg.mcp_server,
        "mcp_args": cfg.mcp_args,
        "db_path": cfg.db_path,
        "skills_dir": cfg.skills_dir,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    with open(p, "w") as f:
        yaml.dump(data, f, default_flow_style=False)
    return p
