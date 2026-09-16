from __future__ import annotations

import ipaddress
from collections.abc import Iterable

MAX_HOSTS_HARD_LIMIT = 4096

_ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)


class TargetError(ValueError):
    """Raised when a requested target is invalid or outside authorized LAN scope."""


def is_allowed_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in network for network in _ALLOWED_NETWORKS)


def _validate_ip(ip: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
    if not is_allowed_ipv4(ip):
        raise TargetError(
            f"{ip} is outside the supported private/LAN scope. "
            "Dreambox Scanner v6 intentionally does not scan public Internet targets."
        )
    return ip


def _enforce_hard_limit(host_count: int, label: str) -> None:
    if host_count > MAX_HOSTS_HARD_LIMIT:
        raise TargetError(
            f"{label} expands to {host_count} hosts, above the hard safety limit of "
            f"{MAX_HOSTS_HARD_LIMIT}. Split it into smaller authorized ranges."
        )


def _from_range(value: str) -> list[ipaddress.IPv4Address]:
    start_raw, end_raw = (part.strip() for part in value.split("-", 1))
    try:
        start = _validate_ip(ipaddress.IPv4Address(start_raw))
        end = _validate_ip(ipaddress.IPv4Address(end_raw))
    except ipaddress.AddressValueError as exc:
        raise TargetError(f"Invalid IPv4 range: {value}") from exc
    if int(start) > int(end):
        raise TargetError(f"Range start must not be greater than range end: {value}")

    host_count = int(end) - int(start) + 1
    _enforce_hard_limit(host_count, value)
    return [ipaddress.IPv4Address(number) for number in range(int(start), int(end) + 1)]


def _from_cidr(value: str) -> list[ipaddress.IPv4Address]:
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise TargetError(f"Invalid IPv4 CIDR: {value}") from exc

    if not all(
        any(host in allowed for allowed in _ALLOWED_NETWORKS)
        for host in (network.network_address, network.broadcast_address)
    ):
        raise TargetError(
            f"{network} is outside the supported private/LAN scope. "
            "Use only networks you own or administer."
        )

    host_count = network.num_addresses if network.prefixlen >= 31 else max(0, network.num_addresses - 2)
    _enforce_hard_limit(host_count, str(network))
    if network.prefixlen == 32:
        return [_validate_ip(network.network_address)]
    return list(network.hosts())


def parse_target(value: str) -> list[ipaddress.IPv4Address]:
    value = value.strip()
    if not value:
        raise TargetError("Target cannot be empty.")
    if "-" in value:
        return _from_range(value)
    if "/" in value:
        return _from_cidr(value)
    try:
        return [_validate_ip(ipaddress.IPv4Address(value))]
    except ipaddress.AddressValueError as exc:
        raise TargetError(f"Invalid IPv4 address: {value}") from exc


def expand_targets(values: Iterable[str], max_hosts: int = 1024) -> list[str]:
    if not 1 <= max_hosts <= MAX_HOSTS_HARD_LIMIT:
        raise TargetError(f"max_hosts must be between 1 and {MAX_HOSTS_HARD_LIMIT}.")

    unique: dict[str, None] = {}
    for value in values:
        for ip in parse_target(value):
            unique.setdefault(str(ip), None)
            if len(unique) > max_hosts:
                raise TargetError(
                    f"Target selection exceeds the configured limit of {max_hosts} hosts. "
                    "Split large networks into smaller authorized scans."
                )
    return list(unique)
