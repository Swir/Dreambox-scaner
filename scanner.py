"""Backward-compatible launcher for Dreambox Scanner v6.

The application code now lives in ``src/dreambox_scanner``. Existing users can
keep running ``python scanner.py ...`` while new installations may use
``python main.py ...`` or the installed ``dreambox-scanner`` command.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dreambox_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
