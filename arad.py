#!/usr/bin/env python3
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main():
    if "--headless" in sys.argv:
        sys.argv = [a for a in sys.argv if a != "--headless"]
        sys.argv[0] = "pentest"
        import pentest
        pentest.cli.main(args=sys.argv[1:], standalone_mode=True)
    else:
        from core.tui import launch_tui
        launch_tui()


if __name__ == "__main__":
    main()
