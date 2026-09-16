from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def default_log_path() -> Path:
    if os.name == "nt":
        root = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "DreamboxScanner" / "logs" / "dreambox-scanner.log"
    state_home = Path(os.getenv("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "dreambox-scanner" / "dreambox-scanner.log"


def configure_logging(path: str | Path | None = None, verbose: bool = False) -> Path:
    log_path = Path(path).expanduser() if path else default_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("dreambox_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    handler = RotatingFileHandler(
        log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(handler)
    return log_path
