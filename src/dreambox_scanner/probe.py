from __future__ import annotations

import socket
import time
from dataclasses import dataclass

import requests
from requests.auth import HTTPBasicAuth

from .models import ScanResult

SERVICE_HINTS = {
    80: "HTTP / OpenWebif",
    443: "HTTPS / OpenWebif",
    8001: "Enigma2 stream",
    8002: "Enigma2 transcoding",
    8080: "Kodi / HTTP",
    8888: "NBox / HTTP",
    9981: "TVHeadend / HTTP",
    65001: "HDHomeRun discovery",
}

HTTP_PORTS = {80, 443, 8080, 8888, 9981}


@dataclass(slots=True, frozen=True)
class HttpFingerprint:
    device: str
    status: int | None
    fingerprint: str | None


def _identify(text: str, port: int) -> str:
    lowered = text.lower()
    if "vu+" in lowered or "vuplus" in lowered:
        return "Vu+ / Enigma2"
    if "dreambox" in lowered:
        return "Dreambox / Enigma2"
    if "openwebif" in lowered or "enigma2" in lowered:
        return "Enigma2 / OpenWebif"
    if "tvheadend" in lowered:
        return "TVHeadend"
    if "kodi" in lowered or "xbmc" in lowered:
        return "Kodi"
    if "hdhomerun" in lowered:
        return "HDHomeRun"
    if "nbox" in lowered:
        return "NBox"
    if port in (8001, 8002):
        return "Enigma2 stream candidate"
    return "Unknown"


def tcp_probe(ip: str, port: int, timeout_s: float) -> tuple[bool, float | None]:
    started = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            latency = round((time.perf_counter() - started) * 1000, 2)
            return True, latency
    except (TimeoutError, OSError):
        return False, None


def http_fingerprint(
    ip: str,
    port: int,
    timeout_s: float,
    username: str | None = None,
    password: str | None = None,
) -> HttpFingerprint:
    if port not in HTTP_PORTS:
        return HttpFingerprint(_identify("", port), None, None)

    scheme = "https" if port == 443 else "http"
    auth = HTTPBasicAuth(username, password or "") if username else None
    paths = ("/", "/web/about", "/jsonrpc", "/api/status")
    snippets: list[str] = []
    last_status: int | None = None

    with requests.Session() as session:
        session.headers.update({"User-Agent": "DreamboxScanner/6.0 (+authorized-LAN-diagnostics)"})
        for path in paths:
            try:
                response = session.get(
                    f"{scheme}://{ip}:{port}{path}",
                    timeout=timeout_s,
                    auth=auth,
                    verify=False,
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue
            last_status = response.status_code
            server = response.headers.get("Server", "")
            title_fragment = response.text[:4096]
            combined = f"{server}\n{title_fragment}"
            snippets.append(combined)
            device = _identify(combined, port)
            if device != "Unknown":
                fingerprint = server.strip() or device
                return HttpFingerprint(device, response.status_code, fingerprint[:160])

    combined = "\n".join(snippets)
    return HttpFingerprint(_identify(combined, port), last_status, None)


def probe_port(
    ip: str,
    port: int,
    timeout_s: float,
    username: str | None = None,
    password: str | None = None,
) -> ScanResult | None:
    is_open, latency = tcp_probe(ip, port, timeout_s)
    if not is_open:
        return None

    fingerprint = http_fingerprint(ip, port, timeout_s, username, password)
    return ScanResult(
        ip=ip,
        port=port,
        service=SERVICE_HINTS.get(port, "TCP service"),
        device=fingerprint.device,
        latency_ms=latency,
        http_status=fingerprint.status,
        fingerprint=fingerprint.fingerprint,
    )
