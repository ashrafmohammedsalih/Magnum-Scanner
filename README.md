# Magnum Scanner 🏎️
Baseline + Watch + Alerts + Smart Auto Service Packs (service+port fallback).  
Designed for HTB / THM / OSCP-style workflows on macOS/Linux.

## ⚠️ Disclaimer
Use ONLY on targets you own or have explicit permission to test.  
You are responsible for complying with laws and platform rules.

---

## Requirements
- `nmap`
- `masscan`
- `sudo` access (Masscan + Nmap SYN scan needs root)
- macOS notifications: `osascript` (built-in)

---

## Installation (macOS)
### 1) Install tools
**Homebrew:**
```bash
brew install nmap masscan
```

### 2) Make script executable
```bash
chmod +x magnum.sh
```

### 3) Test
```bash
./magnum.sh --version
./magnum.sh --help
```

---

## Quick Start (macOS)

### Watch mode (rescan every 3 minutes)
```bash
./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)"
```

### Run only ONE cycle
```bash
./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --once
```

### Disable deep scans on NEW tcp ports
```bash
./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --no-deep
```

### Disable UDP selective
```bash
./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --no-udp
```

### Force router ip (if auto-detect fails)
```bash
./magnum.sh 10.10.10.172 3 --iface utun4 --router-ip 10.10.14.1 --outdir "$(pwd)"
```

### Produce Nmap outputs as -oA (.nmap + .xml + .gnmap)
```bash
./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --nmap-all
```

---

## What it does (high-level)

### Baseline (first run only)
- Full TCP discovery via `masscan` (0–65535)
- Full TCP service scan via `nmap -sS -sC -sV` on discovered ports (saved as `.nmap`)
- Smart Auto Service Packs per baseline port (service+port fallback):
  - HTTP/HTTPS, SMB, LDAP/LDAPS, RDP, WinRM, DNS, FTP, SMTP, MSSQL, MySQL, Postgres, SSH
- Optional UDP selective baseline: `nmap -sU --top-ports 50 --open` (if UDP enabled)

### Watch loop
- Re-runs masscan each interval
- If TCP port-set changed: runs a new full TCP report
- If a NEW port vs baseline appears:
  - Beep + macOS notification
  - Deep scan on the new port only (saved under `nmap/new_ports/`)
  - Extra HTTP scan if port looks web-ish (80/443/8080/8000/8443/8888)
  - Service pack scan (service+port fallback)

---

## Output structure
All outputs go under your current directory (or `--outdir`) like:
```
./scans/<TARGET>/
  masscan/
    masscan_baseline_<TS>.gnmap
    masscan_rescan_<TS>.gnmap

  nmap/
    nmap_baseline_tcp_<TS>.nmap
    nmap_change_tcp_<TS>.nmap
    nmap_baseline_udp_<TS>.nmap            (if UDP enabled)
    nmap_change_udp_<TS>.nmap              (if UDP watch enabled)

    baseline_packs/
      nmap_<service>_pack_baseline_tcp_<TS>_p<PORT>.nmap

    new_ports/
      nmap_deep_tcp_<TS>_p<PORT>.nmap
      nmap_http_tcp_<TS>_p<PORT>.nmap      (only for web ports)
      nmap_<service>_pack_new_tcp_<TS>_p<PORT>.nmap

  logs/
    baseline_tcp_ports.txt
    last_tcp_set.txt
    seen_new_tcp_ports.txt
    alerts_new_tcp_ports.txt
    baseline_packs_index.txt
    new_ports_index.txt
    baseline_udp_ports.txt                 (if UDP enabled)
    last_udp_set.txt                       (if UDP enabled)
```

---

## Handy controls
- Press **ENTER** to force a rescan immediately
- Or:
  ```bash
  touch ./trigger_rescan
  ```

---

## Troubleshooting (macOS / HTB)

### 1) “Host seems down” in Nmap
Many HTB targets drop ICMP/ping probes. Use `-Pn`.  
Magnum enables `-Pn` by default. If you disabled it with `--no-pn`, re-run without `--no-pn`.

Manual example:
```bash
nmap -Pn -sC -sV <target>
```

### 2) “You requested a scan type which requires root privileges”
`nmap -sS` needs root. Magnum will call `sudo nmap` when needed.
If you still see this, run:
```bash
sudo ./magnum.sh <target> 3 --iface utun4 --outdir "$(pwd)"
```

### 3) ROUTER_IP auto-detect fails for utun4
Fix by forcing it:
```bash
./magnum.sh <target> 3 --iface utun4 --router-ip 10.10.14.1 --outdir "$(pwd)"
```

To see your current VPN gateway quickly (typical HTB is `10.10.14.1`):
```bash
route -n get 10.10.10.10 | grep gateway
```

### 4) Masscan shows ports but Nmap shows nothing
Nmap might think host is down unless `-Pn` is used, or the host is rate-limiting.
- Keep `-Pn` ON (default)
- Try a slower interval / lower rate

### 5) Why do ports change between rescans?
This can happen in HTB/THM/OSCP labs because:
- Service starts/stops (crashes, restarts, or is triggered by your actions)
- NAT / VPN jitter and packet loss
- Rate limiting / IDS drops some probes
- Load balancers or port-knocking-like behavior (rare but possible)

---

## FAQ (HTB/THM/OSCP) — “Different open ports on rescan?”
Yes, it can happen. Best practice:
- Run a slower confirmation scan when results matter.
- Use `-Pn` in restricted environments.
- Compare multiple scans; treat Masscan as “discovery hint” and Nmap as “confirmation”.

---

## Help / Version
```bash
./magnum.sh --help
./magnum.sh --version
```

## License
MIT
