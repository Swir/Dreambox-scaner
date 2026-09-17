from __future__ import annotations


class PortSpecError(ValueError):
    """Raised when a TCP port specification is invalid."""


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse comma-separated ports and inclusive ranges.

    Examples: ``80,443,8001-8002,8080`` and ``1-1024``.
    """
    ports: list[int] = []
    seen: set[int] = set()

    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue

        if "-" in part:
            start_raw, end_raw = (piece.strip() for piece in part.split("-", 1))
            try:
                start = int(start_raw)
                end = int(end_raw)
            except ValueError as exc:
                raise PortSpecError(f"Invalid port range: {part}") from exc
            if start > end:
                raise PortSpecError(f"Port range start must not exceed end: {part}")
            candidates = range(start, end + 1)
        else:
            try:
                candidates = (int(part),)
            except ValueError as exc:
                raise PortSpecError(f"Invalid port: {part}") from exc

        for port in candidates:
            if not 1 <= port <= 65535:
                raise PortSpecError(f"Port out of range: {port}")
            if port not in seen:
                seen.add(port)
                ports.append(port)

    if not ports:
        raise PortSpecError("At least one TCP port is required.")
    return tuple(ports)
