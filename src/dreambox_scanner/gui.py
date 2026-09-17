from __future__ import annotations

import os
import queue
import sys
import threading
import webbrowser
from collections import defaultdict
from pathlib import Path
from tkinter import BooleanVar, StringVar, Tk, filedialog, messagebox, ttk

from . import __version__
from .models import ScanResult
from .output import save_results
from .playlist import generate_playlist
from .ports import PortSpecError, parse_ports
from .scanner import scan_targets
from .targets import TargetError, expand_targets

DEFAULT_PORT_SPEC = "80,443,8001-8002,8080,8888,9981"


def _resource_path(*parts: str) -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).resolve().parents[2]
    return base.joinpath(*parts)


class DreamboxScannerGUI:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(f"Dreambox Scanner v{__version__}")
        self.root.geometry("1040x720")
        self.root.minsize(900, 620)

        self.events: queue.Queue[tuple] = queue.Queue()
        self.cancel_event = threading.Event()
        self.results: list[ScanResult] = []
        self.scan_thread: threading.Thread | None = None
        self.total_probes = 0
        self.scanned_probes = 0
        self.open_ports = 0
        self.completed_hosts = 0

        self.target_var = StringVar(value="192.168.1.1")
        self.end_ip_var = StringVar(value="192.168.1.254")
        self.ports_var = StringVar(value=DEFAULT_PORT_SPEC)
        self.timeout_var = StringVar(value="750")
        self.workers_var = StringVar(value="32")
        self.username_var = StringVar()
        self.password_var = StringVar()
        self.authorized_var = BooleanVar(value=False)
        self.playlist_var = BooleanVar(value=True)
        self.status_var = StringVar(value="Ready — authorized private/LAN targets only")
        self.hosts_var = StringVar(value="Hosts: 0/0")
        self.ports_count_var = StringVar(value="Ports checked: 0/0")
        self.open_count_var = StringVar(value="Open ports: 0")

        self._configure_theme()
        self._apply_icon()
        self._build_ui()
        self.root.after(100, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_theme(self) -> None:
        self.root.configure(bg="#07111f")
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background="#07111f")
        style.configure("Card.TFrame", background="#0d1b2a")
        style.configure("TLabel", background="#07111f", foreground="#dbeafe", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#07111f", foreground="#60a5fa", font=("Segoe UI Semibold", 19))
        style.configure("Card.TLabel", background="#0d1b2a", foreground="#dbeafe")
        style.configure("Hint.TLabel", background="#07111f", foreground="#93c5fd", font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 7))
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10), padding=(14, 8))
        style.configure("Danger.TButton", font=("Segoe UI Semibold", 10), padding=(14, 8))
        style.configure("TCheckbutton", background="#0d1b2a", foreground="#dbeafe")
        style.configure("Treeview", background="#0a1726", fieldbackground="#0a1726", foreground="#e5efff", rowheight=26)
        style.configure("Treeview.Heading", background="#12263a", foreground="#bfdbfe", font=("Segoe UI Semibold", 10))
        style.map("Treeview", background=[("selected", "#1d4ed8")], foreground=[("selected", "#ffffff")])

    def _apply_icon(self) -> None:
        icon = _resource_path("assets", "dreambox-scanner.ico")
        if icon.exists():
            try:
                self.root.iconbitmap(default=str(icon))
            except Exception:
                pass

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text=f"Dreambox Scanner v{__version__}", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Restored desktop workflow + v6 modular scanner • Dreambox / Enigma2 / OpenWebif diagnostics",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        config = ttk.Frame(outer, style="Card.TFrame", padding=14)
        config.pack(fill="x")
        for index in range(6):
            config.columnconfigure(index, weight=1 if index in (1, 3, 5) else 0)

        self._labeled_entry(config, "Target / start IP", self.target_var, 0, 0)
        self._labeled_entry(config, "End IP (optional)", self.end_ip_var, 0, 2)
        self._labeled_entry(config, "Ports / ranges", self.ports_var, 0, 4)
        self._labeled_entry(config, "Timeout (ms)", self.timeout_var, 1, 0)
        self._labeled_entry(config, "Workers", self.workers_var, 1, 2)
        self._labeled_entry(config, "HTTP username", self.username_var, 1, 4)

        ttk.Label(config, text="HTTP password", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=(10, 0))
        password = ttk.Entry(config, textvariable=self.password_var, show="•")
        password.grid(row=2, column=1, sticky="ew", pady=(10, 0), padx=(0, 14))

        ttk.Checkbutton(config, text="Generate M3U in HITS/ when a host has open ports", variable=self.playlist_var).grid(
            row=2, column=2, columnspan=2, sticky="w", pady=(10, 0)
        )
        ttk.Checkbutton(
            config,
            text="I own/administer every selected target",
            variable=self.authorized_var,
        ).grid(row=2, column=4, columnspan=2, sticky="w", pady=(10, 0))

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=12)
        self.start_button = ttk.Button(buttons, text="Start scan", style="Accent.TButton", command=self.start_scan)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop", style="Danger.TButton", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.json_button = ttk.Button(buttons, text="Save JSON", command=lambda: self.save_results("json"), state="disabled")
        self.json_button.pack(side="left", padx=(18, 0))
        self.csv_button = ttk.Button(buttons, text="Save CSV", command=lambda: self.save_results("csv"), state="disabled")
        self.csv_button.pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Open HITS folder", command=self.open_hits).pack(side="right")

        results_card = ttk.Frame(outer, style="Card.TFrame", padding=8)
        results_card.pack(fill="both", expand=True)
        columns = ("ip", "port", "service", "device", "latency", "http")
        self.tree = ttk.Treeview(results_card, columns=columns, show="headings")
        headings = {
            "ip": "IP",
            "port": "Port",
            "service": "Service",
            "device": "Device",
            "latency": "Latency",
            "http": "HTTP",
        }
        widths = {"ip": 140, "port": 75, "service": 150, "device": 210, "latency": 105, "http": 75}
        for key in columns:
            self.tree.heading(key, text=headings[key])
            self.tree.column(key, width=widths[key], anchor="center" if key in ("port", "latency", "http") else "w")
        scroll = ttk.Scrollbar(results_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._show_selected_details)

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(10, 0))
        self.progress = ttk.Progressbar(footer, mode="determinate")
        self.progress.pack(fill="x")
        metrics = ttk.Frame(footer)
        metrics.pack(fill="x", pady=(6, 0))
        ttk.Label(metrics, textvariable=self.hosts_var).pack(side="left")
        ttk.Label(metrics, textvariable=self.ports_count_var).pack(side="left", padx=(18, 0))
        ttk.Label(metrics, textvariable=self.open_count_var).pack(side="left", padx=(18, 0))
        ttk.Label(metrics, textvariable=self.status_var, style="Hint.TLabel").pack(side="right")

    def _labeled_entry(self, parent, label: str, variable: StringVar, row: int, column: int) -> None:
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=column, sticky="w", padx=(0, 8), pady=(0 if row == 0 else 10, 0))
        ttk.Entry(parent, textvariable=variable).grid(
            row=row,
            column=column + 1,
            sticky="ew",
            padx=(0, 14),
            pady=(0 if row == 0 else 10, 0),
        )

    def _target_values(self) -> list[str]:
        start = self.target_var.get().strip()
        end = self.end_ip_var.get().strip()
        if not start:
            raise TargetError("Target / start IP cannot be empty.")
        if end:
            if "/" in start or "-" in start:
                raise TargetError("Leave End IP empty when Target already contains a CIDR or range.")
            return [f"{start}-{end}"]
        return [start]

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return
        if not self.authorized_var.get():
            messagebox.showerror("Authorization required", "Confirm that you own or administer every selected target.")
            return

        try:
            timeout_ms = int(self.timeout_var.get())
            workers = int(self.workers_var.get())
            if not 50 <= timeout_ms <= 30000:
                raise ValueError("Timeout must be between 50 and 30000 ms.")
            if not 1 <= workers <= 128:
                raise ValueError("Workers must be between 1 and 128.")
            targets = expand_targets(self._target_values(), max_hosts=4096)
            ports = parse_ports(self.ports_var.get())
        except (ValueError, TargetError, PortSpecError) as exc:
            messagebox.showerror("Invalid scan settings", str(exc))
            return

        self.total_probes = len(targets) * len(ports)
        if self.total_probes > 250_000 and not messagebox.askyesno(
            "Large authorized scan",
            f"This scan will perform up to {self.total_probes:,} TCP checks on your private/LAN targets. Continue?",
        ):
            return

        self.results.clear()
        self.cancel_event.clear()
        self.scanned_probes = 0
        self.open_ports = 0
        self.completed_hosts = 0
        self._expected_hosts = len(targets)
        self._expected_ports = len(ports)
        self.tree.delete(*self.tree.get_children())
        self.progress.configure(maximum=max(1, self.total_probes), value=0)
        self.hosts_var.set(f"Hosts: 0/{len(targets)}")
        self.ports_count_var.set(f"Ports checked: 0/{self.total_probes}")
        self.open_count_var.set("Open ports: 0")
        self.status_var.set("Scanning…")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.json_button.configure(state="disabled")
        self.csv_button.configure(state="disabled")

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(targets, ports, timeout_ms, workers),
            daemon=True,
            name="dreambox-gui-scan",
        )
        self.scan_thread.start()

    def _scan_worker(self, targets: list[str], ports: tuple[int, ...], timeout_ms: int, workers: int) -> None:
        playlist_enabled = self.playlist_var.get()
        username = self.username_var.get().strip() or None
        password = self.password_var.get() if username else None

        def probe_done(ip: str, port: int, result: ScanResult | None) -> None:
            self.events.put(("probe", ip, port, result))

        def host_done(ip: str, host_results: list[ScanResult]) -> None:
            if playlist_enabled and host_results:
                try:
                    path = generate_playlist(ip, host_results)
                    self.events.put(("playlist", ip, path))
                except Exception as exc:
                    self.events.put(("warning", f"Playlist for {ip}: {exc}"))
            self.events.put(("host", ip))

        try:
            results = scan_targets(
                targets,
                ports=ports,
                timeout_ms=timeout_ms,
                workers=workers,
                username=username,
                password=password,
                on_host_done=host_done,
                cancel_event=self.cancel_event,
                on_probe_done=probe_done,
            )
            self.events.put(("finished", results, self.cancel_event.is_set()))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def stop_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self.stop_button.configure(state="disabled")
            self.status_var.set("Stopping after active checks finish…")

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "probe":
                    _, _ip, _port, result = event
                    self.scanned_probes += 1
                    if result is not None:
                        self.results.append(result)
                        self.open_ports += 1
                        latency = "-" if result.latency_ms is None else f"{result.latency_ms:.1f} ms"
                        http = "-" if result.http_status is None else str(result.http_status)
                        self.tree.insert("", "end", values=(result.ip, result.port, result.service, result.device, latency, http))
                    self.progress.configure(value=min(self.scanned_probes, self.total_probes))
                    self.ports_count_var.set(f"Ports checked: {self.scanned_probes}/{self.total_probes}")
                    self.open_count_var.set(f"Open ports: {self.open_ports}")
                elif kind == "host":
                    self.completed_hosts += 1
                    self.hosts_var.set(f"Hosts: {self.completed_hosts}/{self._expected_hosts}")
                elif kind == "playlist":
                    _, ip, path = event
                    self.status_var.set(f"Playlist saved for {ip}: {path.name}")
                elif kind == "warning":
                    self.status_var.set(str(event[1]))
                elif kind == "finished":
                    _, results, cancelled = event
                    self.results = list(results)
                    self._finish_scan(cancelled)
                elif kind == "error":
                    self._finish_scan(False)
                    messagebox.showerror("Scan failed", str(event[1]))
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self._drain_events)

    def _finish_scan(self, cancelled: bool) -> None:
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        state = "Scan stopped" if cancelled else "Scan complete"
        self.status_var.set(f"{state} • {len(self.results)} open service(s)")
        enabled = "normal" if self.results else "disabled"
        self.json_button.configure(state=enabled)
        self.csv_button.configure(state=enabled)

    def save_results(self, fmt: str) -> None:
        if not self.results:
            return
        extension = ".json" if fmt == "json" else ".csv"
        path = filedialog.asksaveasfilename(
            defaultextension=extension,
            filetypes=[(fmt.upper(), f"*{extension}"), ("All files", "*.*")],
            initialfile=f"dreambox-scan{extension}",
        )
        if not path:
            return
        try:
            saved = save_results(self.results, Path(path), fmt)
            self.status_var.set(f"Saved {len(self.results)} result(s) to {saved.name}")
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def _show_selected_details(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        if not values:
            return
        messagebox.showinfo(
            "Port details",
            f"IP: {values[0]}\nPort: {values[1]}\nService: {values[2]}\nDevice: {values[3]}\nLatency: {values[4]}\nHTTP: {values[5]}",
        )

    def open_hits(self) -> None:
        path = Path("HITS").resolve()
        path.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt" and hasattr(os, "startfile"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            else:
                webbrowser.open(path.as_uri())
        except Exception as exc:
            messagebox.showerror("Cannot open folder", str(exc))

    def _on_close(self) -> None:
        self.cancel_event.set()
        self.root.destroy()


def launch_gui() -> int:
    root = Tk()
    DreamboxScannerGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_gui())
