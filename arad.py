#!/usr/bin/env python3
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main():
    sys.argv[0] = "pentest"
    import pentest
    pentest.main(sys.argv[1:])


if __name__ == "__main__":
    main()
