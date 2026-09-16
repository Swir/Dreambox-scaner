<div align="center">

<img src="assets/icon.svg" width="150" alt="Dreambox Scanner icon">

# Dreambox Scanner v6

### Authorized LAN diagnostics for Dreambox, Enigma2 and media receivers

[![CI](https://github.com/Swir/Dreambox-scaner/actions/workflows/ci.yml/badge.svg)](https://github.com/Swir/Dreambox-scaner/actions/workflows/ci.yml)
[![Windows Release](https://github.com/Swir/Dreambox-scaner/actions/workflows/release.yml/badge.svg)](https://github.com/Swir/Dreambox-scaner/actions/workflows/release.yml)
![Python](https://img.shields.io/badge/Python-3.10--3.14-3776AB?logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-EXE-0078D4?logo=windows&logoColor=white)
![Scope](https://img.shields.io/badge/Scope-Authorized%20LAN-22c55e)

**Modular Python • Rich CLI • Windows EXE • JSON/CSV • SHA256 • by Swir**

</div>

---

## What changed in v6

Dreambox Scanner v6 is a clean rewrite of the original single-file utility. The old country-wide public IP generator and duplicate script copies are gone. v6 is intentionally focused on devices inside private networks that you own or administer.

The code now lives in `src/dreambox_scanner/`, has automated tests, bounded concurrency, typed results, structured exports, a dedicated application icon and a reproducible Windows release pipeline.

## Features

- Detect open services commonly used by **Dreambox / Enigma2 / OpenWebif / Vu+ / Kodi / TVHeadend / NBox / HDHomeRun** setups.
- Scan a single private IPv4 address, CIDR or explicit private IPv4 range.
- Reject public Internet targets by design.
- Hard target cap of 4096 hosts and worker cap of 128.
- Fast bounded concurrent host scanning.
- HTTP service fingerprinting where appropriate.
- Optional HTTP authentication without putting the password in command-line history.
- Rich progress display and result table.
- JSON and CSV exports.
- Python 3.10–3.14 CI.
- Automated Windows `DreamboxScanner.exe` + portable ZIP + SHA256 checksums.
- Custom Dreambox Scanner v6 icon.

## Quick start

```bash
git clone https://github.com/Swir/Dreambox-scaner.git
cd Dreambox-scaner
python -m pip install -r requirements.txt
python main.py 192.168.1.0/24 --authorized
```

The compatibility launcher also works:

```bash
python scanner.py 192.168.1.0/24 --authorized
```

After installing the package:

```bash
python -m pip install -e .
dreambox-scanner 192.168.1.0/24 --authorized
```

## Examples

Scan selected devices:

```bash
dreambox-scanner 192.168.1.20 192.168.1.50 --authorized
```

Scan a small range and export JSON:

```bash
dreambox-scanner 192.168.1.20-192.168.1.40 --authorized --output scan-results.json --format json
```

Choose ports and a shorter timeout:

```bash
dreambox-scanner 10.0.0.0/24 --authorized --ports 80,443,8001,8002,8080,9981 --timeout-ms 500
```

Use HTTP credentials for devices you administer without exposing a password in shell history:

```powershell
$env:DREAMBOX_SCANNER_PASSWORD = "your-password"
dreambox-scanner 192.168.1.25 --authorized --username root
```

## Supported target scope

v6 accepts IPv4 addresses from:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `169.254.0.0/16`

Public Internet targets are rejected. See [SECURITY.md](SECURITY.md) for the project safeguards.

## Project layout

```text
Dreambox-scaner/
├─ assets/
│  └─ icon.svg
├─ src/dreambox_scanner/
│  ├─ cli.py
│  ├─ models.py
│  ├─ output.py
│  ├─ probe.py
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

Tagged/release builds run tests first, generate the Windows `.ico`, build `DreamboxScanner.exe` with PyInstaller and publish:

- `DreamboxScanner.exe`
- `DreamboxScanner.exe.sha256`
- `DreamboxScanner-vX.Y.Z-Windows-x64.zip`
- `DreamboxScanner-vX.Y.Z-Windows-x64.zip.sha256`

## Responsible use

Run Dreambox Scanner only against devices and networks you own or are explicitly authorized to administer. v6 contains technical safeguards that prevent public IPv4 scanning, but authorization remains the user's responsibility.

## Development

```bash
python -m pip install -e . pytest
pytest
python -m compileall -q src main.py
```

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

<div align="center">

Developed by **Swir** · [GitHub profile](https://github.com/Swir)

**Clean code. Reproducible releases. Authorized network diagnostics.**

</div>
