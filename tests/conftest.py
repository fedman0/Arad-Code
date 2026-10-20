import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_SESSION_DIR = Path(tempfile.mkdtemp(prefix="arad-tests-")).resolve()

for _name in ("home", "cache", "config", "data", "state"):
    (_SESSION_DIR / _name).mkdir()

os.environ["HOME"] = str(_SESSION_DIR / "home")
os.environ["XDG_CACHE_HOME"] = str(_SESSION_DIR / "cache")
os.environ["XDG_CONFIG_HOME"] = str(_SESSION_DIR / "config")
os.environ["XDG_DATA_HOME"] = str(_SESSION_DIR / "data")
os.environ["XDG_STATE_HOME"] = str(_SESSION_DIR / "state")

for _name in list(os.environ):
    if _name.startswith(("PENTEST_", "ARAD_")):
        os.environ.pop(_name, None)


@pytest.fixture(autouse=True)
def _no_app_config(monkeypatch):
    import core.config
    monkeypatch.setattr(core.config, "app_config_path", lambda: _SESSION_DIR / "no-app-config.yaml")


def pytest_unconfigure(config):
    shutil.rmtree(_SESSION_DIR, ignore_errors=True)
