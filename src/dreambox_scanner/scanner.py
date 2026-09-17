from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event

from .models import ScanResult
from .probe import probe_port

DEFAULT_PORTS = (80, 443, 8001, 8002, 8080, 8888, 9981)
logger = logging.getLogger("dreambox_scanner.scanner")


def scan_host(
    ip: str,
    ports: Iterable[int],
    timeout_ms: int = 750,
    username: str | None = None,
    password: str | None = None,
    cancel_event: Event | None = None,
    on_probe_done: Callable[[str, int, ScanResult | None], None] | None = None,
) -> list[ScanResult]:
    timeout_s = max(timeout_ms, 50) / 1000.0
    results: list[ScanResult] = []
    for port in ports:
        if cancel_event is not None and cancel_event.is_set():
            break
        result = probe_port(ip, int(port), timeout_s, username, password)
        if result is not None:
            results.append(result)
        if on_probe_done is not None:
            on_probe_done(ip, int(port), result)
    return results


def scan_targets(
    targets: Iterable[str],
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout_ms: int = 750,
    workers: int = 32,
    username: str | None = None,
    password: str | None = None,
    on_host_done: Callable[[str, list[ScanResult]], None] | None = None,
    cancel_event: Event | None = None,
    on_probe_done: Callable[[str, int, ScanResult | None], None] | None = None,
) -> list[ScanResult]:
    target_list = list(targets)
    if not target_list:
        return []

    port_list = tuple(dict.fromkeys(int(port) for port in ports))
    if not port_list:
        return []

    worker_count = max(1, min(int(workers), 128, len(target_list)))
    results: list[ScanResult] = []
    logger.info(
        "Starting authorized scan: hosts=%s ports=%s timeout_ms=%s workers=%s",
        len(target_list),
        len(port_list),
        timeout_ms,
        worker_count,
    )

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="dreambox-scan") as pool:
        futures = {
            pool.submit(
                scan_host,
                ip,
                port_list,
                timeout_ms,
                username,
                password,
                cancel_event,
                on_probe_done,
            ): ip
            for ip in target_list
        }
        for future in as_completed(futures):
            ip = futures[future]
            if cancel_event is not None and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
            try:
                host_results = future.result()
            except Exception:
                logger.exception("Unexpected scan failure for host %s", ip)
                host_results = []
            results.extend(host_results)
            if on_host_done is not None:
                on_host_done(ip, host_results)

    ordered = sorted(results, key=lambda item: (tuple(int(part) for part in item.ip.split(".")), item.port))
    logger.info(
        "Authorized scan completed: results=%s cancelled=%s",
        len(ordered),
        bool(cancel_event and cancel_event.is_set()),
    )
    return ordered
