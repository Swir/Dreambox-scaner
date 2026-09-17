from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable

import requests
from requests.auth import HTTPBasicAuth

from .models import ScanResult

MAX_PLAYLIST_BYTES = 2 * 1024 * 1024


def _is_authorized_local_ip(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in ("-", "_") else "_" for char in value).strip("_") or "device"


def _playlist_candidates(device: str) -> tuple[str, ...]:
    lowered = device.lower()
    if "tvheadend" in lowered:
        return ("/playlist/channels", "/api/stream/playlist.m3u", "/playlist.m3u")
    if any(name in lowered for name in ("dreambox", "enigma2", "openwebif", "vu+", "nbox")):
        return ("/playlist.m3u", "/web/playlist.m3u")
    return ("/playlist.m3u",)


def _bounded_body(response: requests.Response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"Remote playlist exceeds the {max_bytes}-byte safety limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _looks_like_playlist(body: bytes, content_type: str) -> bool:
    stripped = body.lstrip()
    lowered_type = content_type.lower()
    return (
        stripped.startswith(b"#EXTM3U")
        or b"audio/x-mpegurl" in lowered_type.encode()
        or b"application/vnd.apple.mpegurl" in lowered_type.encode()
        or (b"#EXTINF" in body and b"http" in body.lower())
    )


def fetch_remote_playlist(
    result: ScanResult,
    *,
    output_dir: str | Path = "Device_Playlists",
    timeout_s: float = 5.0,
    username: str | None = None,
    password: str | None = None,
    prefer_https: bool = False,
    max_bytes: int = MAX_PLAYLIST_BYTES,
) -> Path | None:
    """Fetch an M3U playlist from one discovered device on an authorized local address.

    No redirects are followed and responses are capped to keep the compatibility feature
    bounded. Public Internet addresses are rejected even when the caller supplies them.
    """

    if not _is_authorized_local_ip(result.ip):
        raise ValueError("Remote playlist retrieval is restricted to private/local IP addresses")
    if max_bytes < 1024 or max_bytes > MAX_PLAYLIST_BYTES:
        raise ValueError(f"max_bytes must be between 1024 and {MAX_PLAYLIST_BYTES}")

    scheme = "https" if prefer_https or result.port == 443 else "http"
    auth = HTTPBasicAuth(username, password or "") if username else None
    headers = {"User-Agent": "DreamboxScanner/6.2 (+authorized-LAN-diagnostics)"}

    with requests.Session() as session:
        session.headers.update(headers)
        for path in _playlist_candidates(result.device):
            url = f"{scheme}://{result.ip}:{result.port}{path}"
            try:
                with session.get(
                    url,
                    timeout=timeout_s,
                    auth=auth,
                    verify=False,
                    allow_redirects=False,
                    stream=True,
                ) as response:
                    if response.status_code != 200:
                        continue
                    body = _bounded_body(response, max_bytes)
                    if not body or not _looks_like_playlist(body, response.headers.get("Content-Type", "")):
                        continue
            except requests.RequestException:
                continue

            destination = Path(output_dir).expanduser().resolve()
            destination.mkdir(parents=True, exist_ok=True)
            device_name = _safe_name(result.device)
            filename = destination / f"{device_name}_{result.ip.replace('.', '_')}_{result.port}.m3u"
            filename.write_bytes(body)
            return filename

    return None


def fetch_playlists_for_results(
    results: Iterable[ScanResult],
    *,
    output_dir: str | Path = "Device_Playlists",
    timeout_s: float = 5.0,
    username: str | None = None,
    password: str | None = None,
    prefer_https: bool = False,
) -> list[Path]:
    saved: list[Path] = []
    seen: set[tuple[str, int]] = set()
    for result in results:
        key = (result.ip, result.port)
        if key in seen or result.device in {"Unknown", "Enigma2 stream candidate"}:
            continue
        seen.add(key)
        path = fetch_remote_playlist(
            result,
            output_dir=output_dir,
            timeout_s=timeout_s,
            username=username,
            password=password,
            prefer_https=prefer_https,
        )
        if path is not None:
            saved.append(path)
    return saved
