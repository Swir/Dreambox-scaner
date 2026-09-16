# Changelog

All notable Dreambox Scanner changes are documented here.

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
- Reduced the dependency list from a large unrelated environment dump to the packages actually used by the project.
- Replaced legacy version-copy development with semantic versioning and a package-based code layout.

### Removed
- Public Internet country-range scanning.
- Duplicate `wersja 4.py` / `wersja 5.py` development copies from the v6 architecture.
- Unrelated runtime dependencies.

## [5.5] - 2024-01-29
- Historical Windows release from the original single-file implementation.
