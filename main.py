from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dreambox_scanner.cli import main as cli_main
from dreambox_scanner.gui import launch_gui


if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise SystemExit(launch_gui())
    raise SystemExit(cli_main())
