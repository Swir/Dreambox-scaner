import csv
import json

from dreambox_scanner.models import ScanResult
from dreambox_scanner.output import save_results


def _sample():
    return [
        ScanResult(
            ip="192.168.1.20",
            port=80,
            service="HTTP / OpenWebif",
            device="Dreambox / Enigma2",
            latency_ms=2.5,
            http_status=200,
            fingerprint="OpenWebif",
        )
    ]


def test_json_export(tmp_path):
    path = save_results(_sample(), tmp_path / "scan.json", "json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data[0]["device"] == "Dreambox / Enigma2"
    assert data[0]["port"] == 80


def test_csv_export(tmp_path):
    path = save_results(_sample(), tmp_path / "scan.csv", "csv")
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["ip"] == "192.168.1.20"
    assert rows[0]["fingerprint"] == "OpenWebif"


def test_text_export(tmp_path):
    path = save_results(_sample(), tmp_path / "scan.txt", "text")
    text = path.read_text(encoding="utf-8")
    assert "IP: 192.168.1.20" in text
    assert "Port: 80" in text
    assert "Device: Dreambox / Enigma2" in text
    assert "Fingerprint: OpenWebif" in text
