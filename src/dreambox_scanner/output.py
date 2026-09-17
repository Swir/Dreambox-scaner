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
    elif fmt in {"text", "txt"}:
        blocks: list[str] = []
        for item in results:
            latency = "-" if item.latency_ms is None else f"{item.latency_ms:.2f} ms"
            http_status = "-" if item.http_status is None else str(item.http_status)
            fingerprint = item.fingerprint or "-"
            blocks.append(
                "\n".join(
                    (
                        f"IP: {item.ip}",
                        f"Port: {item.port}",
                        f"Service: {item.service}",
                        f"Device: {item.device}",
                        f"Latency: {latency}",
                        f"HTTP: {http_status}",
                        f"Fingerprint: {fingerprint}",
                    )
                )
            )
        path.write_text("\n\n".join(blocks) + ("\n" if blocks else ""), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

    return path
