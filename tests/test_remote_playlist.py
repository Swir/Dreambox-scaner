from pathlib import Path

import pytest

from dreambox_scanner.models import ScanResult
from dreambox_scanner.remote_playlist import fetch_remote_playlist


class FakeResponse:
    status_code = 200
    headers = {"Content-Type": "audio/x-mpegurl"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def iter_content(self, chunk_size=65536):
        yield b"#EXTM3U\n#EXTINF:-1,Demo\nhttp://192.168.1.20:8001/1:0:1\n"


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


def test_remote_playlist_rejects_public_targets(tmp_path: Path):
    result = ScanResult("8.8.8.8", 80, "HTTP", "Dreambox / Enigma2")
    with pytest.raises(ValueError, match="private/local"):
        fetch_remote_playlist(result, output_dir=tmp_path)


def test_remote_playlist_is_bounded_and_does_not_follow_redirects(tmp_path: Path, monkeypatch):
    fake = FakeSession()
    monkeypatch.setattr("dreambox_scanner.remote_playlist.requests.Session", lambda: fake)
    result = ScanResult("192.168.1.20", 8001, "Enigma2 stream", "Dreambox / Enigma2")

    saved = fetch_remote_playlist(result, output_dir=tmp_path, username="root", password="secret")

    assert saved is not None
    assert saved.exists()
    assert saved.read_text(encoding="utf-8").startswith("#EXTM3U")
    assert fake.calls
    _, kwargs = fake.calls[0]
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
