from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import ScanResult
from .probe import probe_port

DEFAULT_PORTS = (80, 443, 8001, 8002, 8080, 8888, 9981, 65001)


def scan_host(
    ip: str,
    ports: Iterable[int],
    timeout_ms: int = 750,
    username: str | None = None,
    password: str | None = None,
) -> list[ScanResult]:
    timeout_s = max(timeout_ms, 50) / 1000.0
    results: list[ScanResult] = []
    for port in ports:
        result = probe_port(ip, int(port), timeout_s, username, password)
        if result is not None:
            results.append(result)
    return results


def scan_targets(
    targets: Iterable[str],
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout_ms: int = 750,
    workers: int = 32,
    username: str | None = None,
    password: str | None = None,
    on_host_done: Callable[[str, list[ScanResult]], None] | None = None,
) -> list[ScanResult]:
    target_list = list(targets)
    if not target_list:
        return []

    worker_count = max(1, min(int(workers), 128, len(target_list)))
    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="dreambox-scan") as pool:
        futures = {
            pool.submit(scan_host, ip, ports, timeout_ms, username, password): ip
            for ip in target_list
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                host_results = future.result()
            except Exception:
                host_results = []
            results.extend(host_results)
            if on_host_done is not None:
                on_host_done(ip, host_results)

    return sorted(results, key=lambda item: (tuple(int(part) for part in item.ip.split(".")), item.port))
