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
./magnum.sh --help
./magnum.sh --version
```

---

## Quick Start (macOS)

### Watch mode (rescan every 3 minutes)
```bash
sudo -E ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)"
```

### Run only ONE cycle (baseline then exit)
```bash
sudo -E ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --once
```

### Disable deep scans on NEW TCP ports
```bash
sudo -E ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --no-deep
```

### Disable UDP selective baseline
```bash
sudo -E ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --no-udp
```

### Force router IP (if auto-detect fails)
```bash
sudo -E ./magnum.sh 10.10.10.172 3 --iface utun4 --router-ip 10.10.14.1 --outdir "$(pwd)"
```

### Produce Nmap outputs as -oA (.nmap + .xml + .gnmap)
```bash
sudo -E ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --nmap-all
```

---

## What it does (high-level)

### Baseline (first run only)
- Full TCP discovery via `masscan` (0–65535)
- Full TCP service scan via `nmap -sS -sC -sV` on discovered ports (saved as `.nmap`)
- **Baseline service packs** (known services only) generated from the baseline nmap output:
  - `http, smb, ldap, winrm, dns, ftp, ssh, smtp`
  - If a baseline port/service is not recognized, no pack is generated for it.
- Optional UDP selective baseline: `nmap -sU --top-ports 50 --open` (if UDP enabled)

### Watch loop
- Re-runs masscan each interval (or when manually triggered)
- If TCP port-set changed: runs a new full TCP change report
- If a NEW port vs baseline appears:
  - Beep + macOS notification
  - Deep scan on the new port only (saved under `nmap/new_ports/`)
  - Extra HTTP scan if port looks web-ish (80/443/8000/8080/8081/8443/8888)
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

    baseline_packs/
      nmap_<pack>_pack_baseline_tcp_<TS>_p<PORT>.nmap

    new_ports/
      nmap_deep_tcp_<TS>_p<PORT>.nmap
      nmap_http_tcp_<TS>_p<PORT>.nmap      (only for web-ish ports)
      nmap_<pack>_pack_new_tcp_<TS>_p<PORT>.nmap

  logs/
    baseline_tcp_ports.csv
    baseline_tcp_ports.lines
    last_tcp_set.lines

    baseline_packs_index.txt
    new_ports_index.txt

    masscan_baseline_<TS>.log
    masscan_rescan_<TS>.log

    nmap_baseline_tcp_<TS>.log
    nmap_change_tcp_<TS>.log
    nmap_baseline_udp_<TS>.log             (if UDP enabled)

    nmap_deep_tcp_<TS>_p<PORT>.log
    nmap_<pack>_pack_baseline_tcp_<TS>_p<PORT>.log
    nmap_<pack>_pack_new_tcp_<TS>_p<PORT>.log
```

> Note: `baseline_packs/` may be empty if the baseline scan doesn't include any recognized services at that moment.

---

## Handy controls
- Press **ENTER** to force a rescan immediately
- Or create the trigger file under your `--outdir` root:
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
`nmap -sS` needs root. Magnum calls `sudo nmap` internally.
If you still see this, run:
```bash
sudo -E ./magnum.sh <target> 3 --iface utun4 --outdir "$(pwd)"
```

### 3) ROUTER_IP auto-detect fails for utun4
Fix by forcing it:
```bash
sudo -E ./magnum.sh <target> 3 --iface utun4 --router-ip 10.10.14.1 --outdir "$(pwd)"
```

To see your current VPN gateway quickly (typical HTB is `10.10.14.1`):
```bash
route -n get 10.10.10.10 | grep gateway
```

### 4) Current rescan shows “Current TCP ports: -”
This means masscan rescan didn’t report any open ports (packet loss / rate limiting / transient target behavior).
Check the rescan log:
```bash
less "./scans/<TARGET>/logs/masscan_rescan_<TS>.log"
```
Try lowering rate, increasing wait, or just rescan again.

### 5) Why do ports change between rescans?
This can happen in HTB/THM/OSCP labs because:
- Service starts/stops (crashes, restarts, or is triggered by your actions)
- NAT / VPN jitter and packet loss
- Rate limiting / IDS drops some probes

---

## Help / Version
```bash
./magnum.sh --help
./magnum.sh --version
```

## License
MIT
