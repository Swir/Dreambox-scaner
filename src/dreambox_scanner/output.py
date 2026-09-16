from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import ScanResult


def save_results(results: list[ScanResult], destination: str | Path, output_format: str) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = output_format.lower()

    if fmt == "json":
        path.write_text(
            json.dumps([item.to_dict() for item in results], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "ip",
                    "port",
                    "service",
                    "device",
                    "latency_ms",
                    "http_status",
                    "fingerprint",
                ],
            )
            writer.writeheader()
            for item in results:
                writer.writerow(item.to_dict())
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

    return path
