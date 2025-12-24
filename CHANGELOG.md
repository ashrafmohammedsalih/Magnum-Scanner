# Changelog

## [0.1.0] - 2025-12-23
### Added
- Baseline TCP discovery (masscan) + baseline TCP service scan (nmap -sC -sV)
- Watch mode rescans with change detection
- New-port alerts (beep + macOS notification) + deep scan per new port
- Smart Auto Service Packs (service+port fallback) for common services
- Optional UDP selective baseline + optional UDP watch
- Clean output structure under ./scans/<TARGET>/
- Helpful “open latest …” commands printed after scans
