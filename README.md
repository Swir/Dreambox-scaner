<div align="center">

<img src="assets/icon.svg" width="160" alt="Dreambox Scanner application icon">

# Dreambox Scanner v6.2

### Modern desktop + CLI diagnostics for Dreambox, Enigma2 and media receivers

[![CI](https://github.com/Swir/Dreambox-scaner/actions/workflows/ci.yml/badge.svg)](https://github.com/Swir/Dreambox-scaner/actions/workflows/ci.yml)
[![Windows Release](https://github.com/Swir/Dreambox-scaner/actions/workflows/release.yml/badge.svg)](https://github.com/Swir/Dreambox-scaner/actions/workflows/release.yml)
![Python](https://img.shields.io/badge/Python-3.10--3.14-3776AB?logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-EXE-0078D4?logo=windows&logoColor=white)
![Scope](https://img.shields.io/badge/Scope-Authorized%20LAN-22c55e)

**Desktop GUI • CLI • M3U playlists • JSON/CSV/TXT • Windows EXE • SHA256 • by Swir**

</div>

---

## Why v6.2 exists

The v6 rewrite improved architecture, safety checks, fingerprinting and release automation but removed several practical features from the older versions. v6.1 restored the desktop workflow; v6.2 performs a second regression pass against the former monolithic scanner and restores additional useful behavior without bringing back unsafe public-Internet scanning.

The application now has explicit regression coverage so later refactors are less likely to silently drop established workflows.

## Restored and improved from the classic versions

- **Desktop GUI** opens automatically when the Windows EXE is launched without command-line arguments.
- **Start IP + optional end IP workflow** for familiar private-LAN range scans.
- **TCP port ranges** such as `1-1024`, `8001-8002` and mixed specifications like `80,443,8001-8002,8080`.
- **Stop button** with cooperative cancellation instead of forcing the process closed.
- **Live progress bar** plus host, checked-port and open-port counters.
- **Double-click result details** for IP, port, detected service/device, latency and HTTP status.
- **M3U playlist generation** in `HITS/` for hosts with discovered open services.
- Compatible `playlist_template.m3u` support, including the classic `xxx.xxx.xxx.xxx` placeholder plus `{{IP}}`, `{{OPEN_PORTS}}` and `{{DISCOVERED_SERVICES}}` placeholders.
- **JSON, CSV and classic plain-text result export**.
- Optional HTTP username/password support for devices you administer.
- **Authorized remote M3U retrieval is restored in the CLI** for discovered private/local devices. Downloads are response-size limited, redirects are disabled and public IP addresses are rejected.
- Optional HTTPS preference for remote playlist retrieval on non-standard HTTPS ports.
- **Custom Dreambox Scanner icon** in this README, the Windows executable and the GUI window.

## Deliberately not restored

The old monolithic build included country-based random scanning of public Internet address ranges and could save credentials inside `config.json`. Those behaviors are intentionally not restored: v6.2 remains limited to targets you own/administer and does not add plaintext password persistence.

## Modern v6 engine retained

- Detect services commonly used by **Dreambox / Enigma2 / OpenWebif / Vu+ / Kodi / TVHeadend / NBox / HDHomeRun** setups.
- Scan a private IPv4 address, CIDR or explicit private IPv4 range.
- Public Internet targets are rejected by design.
- Hard target cap of 4096 hosts and worker cap of 128.
- Bounded concurrent host scanning.
- HTTP service fingerprinting where appropriate.
- Structured JSON and CSV exports plus plain-text compatibility export.
- Python 3.10–3.14 CI.
- Automated Windows `DreamboxScanner.exe` + portable ZIP + SHA256 checksums.
- Modular `src/dreambox_scanner/` code instead of duplicate version files.

## Windows usage

Download the latest release and run:

```text
DreamboxScanner.exe
```

Launching the EXE normally opens the desktop GUI. The same EXE supports command-line mode when arguments are supplied:

```powershell
DreamboxScanner.exe 192.168.1.0/24 --authorized --ports 80,443,8001-8002,8080
```

## Run from source

```bash
git clone https://github.com/Swir/Dreambox-scaner.git
cd Dreambox-scaner
python -m pip install -r requirements.txt
python main.py
```

After installing the package, the two frontends are also available separately:

```bash
python -m pip install -e .
dreambox-scanner-gui
dreambox-scanner 192.168.1.0/24 --authorized
```

## GUI workflow

1. Enter a private target/start IP.
2. Optionally enter an end IP. Leave it blank when the first field already contains a CIDR or range.
3. Enter ports or ranges, for example `80,443,8001-8002,8080`.
4. Adjust timeout/workers if needed.
5. Confirm that you own or administer every selected target.
6. Start the scan. Use **Stop** at any time.
7. Double-click a result for details, save JSON/CSV, or open the generated `HITS/` folder.

For very large private-LAN scan combinations the GUI asks for an additional confirmation before continuing.

## Generated M3U playlists

When **Generate M3U in HITS/** is enabled, every host with discovered open services can receive:

```text
HITS/playlist_192_168_1_25.m3u
```

On first use the application creates `playlist_template.m3u`. You may edit that template. Supported placeholders:

```text
xxx.xxx.xxx.xxx
{{IP}}
{{OPEN_PORTS}}
{{DISCOVERED_SERVICES}}
```

The classic IP placeholder remains supported for compatibility with older templates.

## Remote device playlists

The older terminal scanner could also download playlists exposed by discovered receivers. v6.2 restores that function as an explicit, authorized-LAN CLI option:

```powershell
$env:DREAMBOX_SCANNER_PASSWORD = "your-password"
dreambox-scanner 192.168.1.25 --authorized --username root --fetch-device-playlists
```

Downloaded playlists go to `Device_Playlists/` by default. Use `--playlist-dir` to choose another directory. If a receiver exposes HTTPS on a non-standard port, add `--prefer-https`.

This compatibility path does **not** follow redirects, caps each response at 2 MiB and refuses public IP addresses.

## CLI examples

Scan selected devices:

```bash
dreambox-scanner 192.168.1.20 192.168.1.50 --authorized
```

Scan ports 1 through 1024 on one authorized LAN device:

```bash
dreambox-scanner 192.168.1.20 --authorized --ports 1-1024
```

Scan a small IP range and export JSON:

```bash
dreambox-scanner 192.168.1.20-192.168.1.40 --authorized --ports 80,443,8001-8002 --output scan-results.json --format json
```

Use classic text export:

```bash
dreambox-scanner 192.168.1.20 --authorized --output scan-results.txt --format text
```

Use HTTP credentials without putting a password into command-line history:

```powershell
$env:DREAMBOX_SCANNER_PASSWORD = "your-password"
dreambox-scanner 192.168.1.25 --authorized --username root
```

## Supported target scope

v6.2 accepts IPv4 addresses from:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `169.254.0.0/16`

Public Internet targets are rejected. See [SECURITY.md](SECURITY.md) for safeguards and responsible-use guidance.

## Project layout

```text
Dreambox-scaner/
├─ assets/
│  └─ icon.svg
├─ src/dreambox_scanner/
│  ├─ cli.py
│  ├─ gui.py
│  ├─ logging_utils.py
│  ├─ models.py
│  ├─ output.py
│  ├─ playlist.py
│  ├─ ports.py
│  ├─ probe.py
│  ├─ remote_playlist.py
│  ├─ scanner.py
│  └─ targets.py
├─ tests/
├─ tools/build_icon.py
├─ main.py
├─ scanner.py
├─ pyproject.toml
└─ requirements.txt
```

## Windows releases

Release builds run regression tests first, verify the GUI module, generate the Windows ICO, build the application with PyInstaller and publish:

- `DreamboxScanner.exe`
- `DreamboxScanner.exe.sha256`
- `DreamboxScanner-vX.Y.Z-Windows-x64.zip`
- `DreamboxScanner-vX.Y.Z-Windows-x64.zip.sha256`

## Development and regression tests

```bash
python -m pip install -e ".[dev]"
pytest
python -m compileall -q src main.py
```

Regression coverage includes target validation, service probing, JSON/CSV/TXT exports, TCP port-range parsing, generated M3U compatibility, bounded remote M3U retrieval and cooperative scan cancellation.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

<div align="center">

Developed by **Swir** · [GitHub profile](https://github.com/Swir)

**Classic functionality restored where it is safe. Modern architecture retained.**

</div>
