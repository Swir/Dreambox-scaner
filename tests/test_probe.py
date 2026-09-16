from dreambox_scanner.probe import _identify


def test_identifies_dreambox():
    assert _identify("Server: Dreambox WebControl", 80) == "Dreambox / Enigma2"


def test_identifies_openwebif():
    assert _identify("OpenWebif", 80) == "Enigma2 / OpenWebif"


def test_identifies_vuplus_before_generic_enigma2():
    assert _identify("Vu+ OpenWebif", 80) == "Vu+ / Enigma2"


def test_identifies_kodi():
    assert _identify("Kodi JSON-RPC", 8080) == "Kodi"


def test_stream_port_is_candidate_only():
    assert _identify("", 8001) == "Enigma2 stream candidate"
