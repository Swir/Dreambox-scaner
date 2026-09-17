# Changelog

All notable Dreambox Scanner changes are documented here.

## [6.2.0] - 2026-09-17

### Restored
- Classic plain-text scan result export alongside JSON and CSV.
- Authorized remote M3U retrieval from discovered private/local media devices.
- Optional HTTPS preference for receivers exposing playlist endpoints on non-standard HTTPS ports.

### Hardened
- Remote playlist retrieval refuses public Internet IP addresses even if called directly.
- Remote playlist responses are capped at 2 MiB.
- HTTP redirects are disabled for compatibility downloads.
- Credentials remain runtime-only; the legacy plaintext password persistence from `config.json` was intentionally not restored.

### Tested
- Regression coverage for plain-text export.
- Regression coverage for private/local-only playlist retrieval and redirect blocking.

## [6.1.0] - 2026-09-17

### Restored
- Desktop GUI workflow from the classic v5 line, rebuilt on top of the modular v6 engine.
- Start IP + optional end IP range entry.
- Stop/cancel control for active scans.
- Live host, checked-port and open-port counters plus a progress bar.
- Double-click port/service details.
- M3U playlist generation in `HITS/`.
- Compatibility with the classic `xxx.xxx.xxx.xxx` playlist template placeholder.

### Added
- Mixed TCP port specifications and inclusive ranges such as `80,443,8001-8002` and `1-1024` in GUI and CLI.
- New playlist placeholders: `{{IP}}`, `{{OPEN_PORTS}}` and `{{DISCOVERED_SERVICES}}`.
- Direct JSON/CSV save actions in the GUI.
- Cooperative cancellation support in the modular scanner engine.
- Per-port progress callbacks for accurate UI counters.
- Regression tests for port ranges, playlist compatibility and cancellation.
- `dreambox-scanner-gui` console entry point.
- Windows GUI import smoke test and runtime ICO packaging.

### Fixed
- Prevented Tkinter variables from being accessed from the background scanning thread.
- Preserved command-line behavior while making a normal Windows EXE launch open the GUI.

## [6.0.0] - 2026-09-16

### Added
- New modular `src/dreambox_scanner` architecture.
- Typed scan results and structured JSON/CSV export.
- Private/LAN target validation with a hard host-count safety limit.
- Explicit `--authorized` confirmation before scanning.
- Focused Dreambox, Enigma2/OpenWebif, Vu+, Kodi, TVHeadend, NBox and HDHomeRun service hints.
- Bounded concurrent scanning with configurable timeout and workers.
- Optional HTTP credentials via environment variable instead of command-line password storage.
- Custom Dreambox Scanner v6 application artwork and automated Windows ICO generation.
- CI across Python 3.10 through 3.14.
- Automated Windows EXE, portable ZIP and SHA256 release pipeline.

### Changed
- Replaced the legacy country-wide public IP generator with authorized LAN-only targeting.
- Split the old single-file scripts into reusable modules.
- Replaced duplicate version scripts with one maintained implementation.

### Removed
- Public/country-wide target generation and other functionality outside authorized LAN diagnostics.
