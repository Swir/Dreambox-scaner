from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .models import ScanResult

DEFAULT_TEMPLATE = """#EXTM3U
# Dreambox Scanner playlist template
# Device: {{IP}}
# Open ports: {{OPEN_PORTS}}
# Discovered services:
{{DISCOVERED_SERVICES}}
"""


def load_or_create_template(path: Path) -> str:
    path = Path(path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_TEMPLATE, encoding="utf-8")
    return path.read_text(encoding="utf-8")


def render_playlist(template: str, ip: str, results: Iterable[ScanResult]) -> str:
    items = list(results)
    open_ports = ",".join(str(item.port) for item in items)
    services = "\n".join(
        f"# {item.ip}:{item.port} | {item.service} | {item.device}"
        for item in items
    )
    rendered = template.replace("xxx.xxx.xxx.xxx", ip)
    rendered = rendered.replace("{{IP}}", ip)
    rendered = rendered.replace("{{OPEN_PORTS}}", open_ports)
    rendered = rendered.replace("{{DISCOVERED_SERVICES}}", services)
    return rendered


def generate_playlist(
    ip: str,
    results: Iterable[ScanResult],
    output_dir: Path | str = "HITS",
    template_path: Path | str = "playlist_template.m3u",
) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    template = load_or_create_template(Path(template_path))
    path = output / f"playlist_{ip.replace('.', '_')}.m3u"
    path.write_text(render_playlist(template, ip, results), encoding="utf-8")
    return path
