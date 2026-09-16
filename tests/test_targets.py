import pytest

from dreambox_scanner.targets import TargetError, expand_targets, parse_target


def test_single_private_ip_is_allowed():
    assert [str(ip) for ip in parse_target("192.168.1.20")] == ["192.168.1.20"]


def test_small_private_cidr_expands_hosts():
    assert [str(ip) for ip in parse_target("192.168.1.0/30")] == ["192.168.1.1", "192.168.1.2"]


def test_public_ip_is_rejected():
    with pytest.raises(TargetError):
        parse_target("8.8.8.8")


def test_public_cidr_is_rejected():
    with pytest.raises(TargetError):
        parse_target("1.1.1.0/24")


def test_range_is_supported():
    assert [str(ip) for ip in parse_target("10.0.0.2-10.0.0.4")] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_duplicate_targets_are_removed():
    assert expand_targets(["192.168.1.2", "192.168.1.2"], max_hosts=10) == ["192.168.1.2"]


def test_configured_host_limit_is_enforced():
    with pytest.raises(TargetError):
        expand_targets(["192.168.0.0/24"], max_hosts=10)


def test_huge_private_cidr_is_rejected_before_expansion():
    with pytest.raises(TargetError, match="hard safety limit"):
        parse_target("10.0.0.0/8")


def test_huge_private_range_is_rejected_before_expansion():
    with pytest.raises(TargetError, match="hard safety limit"):
        parse_target("192.168.0.1-192.168.255.254")


def test_max_hosts_cannot_exceed_hard_limit():
    with pytest.raises(TargetError):
        expand_targets(["192.168.1.2"], max_hosts=4097)
