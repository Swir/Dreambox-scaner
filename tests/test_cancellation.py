from threading import Event

import dreambox_scanner.scanner as scanner


def test_scan_host_honors_cancel_event(monkeypatch):
    cancel = Event()
    checked: list[int] = []

    def fake_probe(ip, port, timeout_s, username=None, password=None):
        return None

    def on_probe_done(ip, port, result):
        checked.append(port)
        cancel.set()

    monkeypatch.setattr(scanner, "probe_port", fake_probe)
    results = scanner.scan_host(
        "192.168.1.10",
        [80, 81, 82],
        cancel_event=cancel,
        on_probe_done=on_probe_done,
    )

    assert results == []
    assert checked == [80]
