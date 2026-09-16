from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True, frozen=True)
class ScanResult:
    ip: str
    port: int
    service: str
    device: str
    latency_ms: float | None = None
    http_status: int | None = None
    fingerprint: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
