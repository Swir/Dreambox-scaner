from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

import urllib3
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

from . import __version__
from .logging_utils import configure_logging
from .output import save_results
from .scanner import DEFAULT_PORTS, scan_targets
from .targets import TargetError, expand_targets

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
logger = logging.getLogger("dreambox_scanner.cli")


def _parse_ports(value: str) -> tuple[int, ...]:
    ports: list[int] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            port = int(raw)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port: {raw}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {port}")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("At least one port is required.")
    return tuple(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dreambox-scanner",
        description="Authorized LAN diagnostics for Dreambox, Enigma2 and related media devices.",
    )
    parser.add_argument("targets", nargs="+", help="Private IPv4, CIDR or range, e.g. 192.168.1.0/24")
    parser.add_argument(
        "--ports",
        type=_parse_ports,
        default=DEFAULT_PORTS,
        help="Comma-separated ports (default: 80,443,8001,8002,8080,8888,9981,65001)",
    )
    parser.add_argument("--timeout-ms", type=int, default=750, help="Connection timeout in milliseconds")
    parser.add_argument("--workers", type=int, default=32, help="Concurrent host workers, max 128")
    parser.add_argument("--max-hosts", type=int, default=1024, help="Host safety limit, max 4096")
    parser.add_argument("--username", help="Optional HTTP username for devices you administer")
    parser.add_argument(
        "--password-env",
        default="DREAMBOX_SCANNER_PASSWORD",
        help="Environment variable containing the optional HTTP password",
    )
    parser.add_argument("--output", help="Save results to this path")
    parser.add_argument("--format", choices=("json", "csv"), default="json", help="Output file format")
    parser.add_argument("--log-file", help="Optional custom log file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose file logging")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own or are authorized to administer every selected target",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _render_table(results) -> None:
    table = Table(title=f"Dreambox Scanner v{__version__}", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right")
    table.add_column("Service")
    table.add_column("Device", style="green")
    table.add_column("Latency", justify="right")
    table.add_column("HTTP", justify="right")

    for item in results:
        latency = "-" if item.latency_ms is None else f"{item.latency_ms:.2f} ms"
        status = "-" if item.http_status is None else str(item.http_status)
        table.add_row(item.ip, str(item.port), item.service, item.device, latency, status)
    console.print(table)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_path = configure_logging(args.log_file, verbose=args.verbose)

    if not args.authorized:
        console.print(
            "[bold red]Authorization confirmation required.[/bold red] "
            "Re-run with [bold]--authorized[/bold] only for networks you own or administer."
        )
        return 2
    if args.timeout_ms < 50 or args.timeout_ms > 30000:
        console.print("[red]--timeout-ms must be between 50 and 30000.[/red]")
        return 2
    if args.workers < 1 or args.workers > 128:
        console.print("[red]--workers must be between 1 and 128.[/red]")
        return 2

    try:
        targets = expand_targets(args.targets, max_hosts=args.max_hosts)
    except TargetError as exc:
        logger.warning("Rejected target selection: %s", exc)
        console.print(f"[red]{exc}[/red]")
        return 2

    password = os.getenv(args.password_env) if args.username else None
    if args.username and not password:
        console.print(
            f"[yellow]Username supplied but {args.password_env} is not set; trying authentication with an empty password.[/yellow]"
        )

    console.print(
        f"[bold cyan]Dreambox Scanner v{__version__}[/bold cyan] • "
        f"{len(targets)} host(s) • {len(args.ports)} port(s) • authorized LAN mode"
    )
    if args.verbose:
        console.print(f"[dim]Log: {log_path}[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=len(targets))

        def on_host_done(ip: str, host_results) -> None:
            progress.update(task, advance=1, description=f"Checked {ip}")

        results = scan_targets(
            targets,
            ports=args.ports,
            timeout_ms=args.timeout_ms,
            workers=args.workers,
            username=args.username,
            password=password,
            on_host_done=on_host_done,
        )

    if results:
        _render_table(results)
    else:
        console.print("[yellow]No matching open services were found on the selected authorized targets.[/yellow]")

    if args.output:
        path = save_results(results, Path(args.output), args.format)
        logger.info("Saved %s result(s) to %s", len(results), path)
        console.print(f"[green]Saved {len(results)} result(s) to {path}[/green]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
