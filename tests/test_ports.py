import pytest

from dreambox_scanner.ports import PortSpecError, parse_ports


def test_parse_single_ports_and_ranges():
    assert parse_ports("80,443,8001-8002,8080") == (80, 443, 8001, 8002, 8080)


def test_parse_ports_removes_duplicates_preserving_order():
    assert parse_ports("80,80,79-81") == (80, 79, 81)


def test_parse_ports_rejects_invalid_ranges():
    with pytest.raises(PortSpecError):
        parse_ports("9000-8000")
    with pytest.raises(PortSpecError):
        parse_ports("0,80")
    with pytest.raises(PortSpecError):
        parse_ports("65536")
