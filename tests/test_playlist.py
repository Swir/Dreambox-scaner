from pathlib import Path

from dreambox_scanner.models import ScanResult
from dreambox_scanner.playlist import generate_playlist, render_playlist


def test_render_playlist_supports_legacy_and_new_placeholders():
    result = ScanResult(ip="192.168.1.10", port=8001, service="HTTP", device="Enigma2")
    text = render_playlist(
        "#EXTM3U\nhttp://xxx.xxx.xxx.xxx:8001/\n# {{IP}} {{OPEN_PORTS}}\n{{DISCOVERED_SERVICES}}\n",
        "192.168.1.10",
        [result],
    )
    assert "xxx.xxx.xxx.xxx" not in text
    assert "192.168.1.10" in text
    assert "8001" in text
    assert "Enigma2" in text


def test_generate_playlist_creates_hits_file_and_template(tmp_path: Path):
    result = ScanResult(ip="192.168.1.20", port=80, service="HTTP", device="OpenWebif")
    hits = tmp_path / "HITS"
    template = tmp_path / "playlist_template.m3u"
    playlist = generate_playlist("192.168.1.20", [result], hits, template)
    assert template.exists()
    assert playlist.exists()
    assert playlist.name == "playlist_192_168_1_20.m3u"
    assert "192.168.1.20" in playlist.read_text(encoding="utf-8")
