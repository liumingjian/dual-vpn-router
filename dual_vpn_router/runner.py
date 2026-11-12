"""Stable absolute-path entry point for privileged and hook subprocesses."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dual_vpn_router.cli import main

if __name__ == "__main__":
    main()
