# Changelog

## [0.1.2] - 2025-12-24
### Fixed
- Removed Bash 4-only `mapfile/readarray` usage for macOS `/bin/bash 3.2` compatibility.
- Fixed missing Nmap NSE script name by replacing `ftp-banner` with `banner` and using `ftp-syst` for FTP packs.
- Improved stability: scan commands now write to per-scan log files and won't break the watch loop on transient scan failures.

### Added
- `--version` flag and updated banner to `v0.1.2`.
- Baseline service packs generation for known services from baseline nmap output (saved under `nmap/baseline_packs/`).
- Consistent output/log structure: `.nmap` reports under `nmap/` and detailed logs under `logs/`.

### Changed
- Updated README output tree to match the real generated paths/files:
  - `baseline_tcp_ports.csv` and `baseline_tcp_ports.lines`
  - `last_tcp_set.lines`
  - `baseline_packs_index.txt` and `new_ports_index.txt`
  - per-scan logs for masscan/nmap and per-port deep/pack scans

## [0.1.0] - 2025-12-23
### Added
- Baseline TCP discovery (masscan) + baseline TCP service scan (nmap -sC -sV)
- Watch mode rescans with change detection
- New-port alerts (beep + macOS notification) + deep scan per new port
- Smart Auto Service Packs (service+port fallback) for common services
- Optional UDP selective baseline + optional UDP watch
- Clean output structure under ./scans/<TARGET>/
- Helpful “open latest …” commands printed after scans
