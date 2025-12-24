#!/bin/bash
# ==============================================================================
# Magnum Scanner 🏎️  (macOS Bash 3.2 compatible • Quiet Terminal)
# Baseline once → Watch → Alert → Deep scan new ports (plus smart service packs)
#
# Usage:
#   chmod +x magnum.sh
#   sudo -E ./magnum.sh <target> <interval_min> --iface utun4 --outdir "$(pwd)"
#   sudo -E ./magnum.sh <target> <interval_min> --iface utun4 --outdir "$(pwd)" --once
#
# Options:
#   --iface <name>        Interface (default: utun4)
#   --router-ip <ip>      Force router IP (auto-detect best-effort if omitted)
#   --outdir <path>       Write ./scans/<TARGET>/ under this directory (default: PWD)
#   --once                Run baseline cycle once then exit
#   --no-udp              Disable UDP selective baseline
#   --udp-watch           Enable UDP watch (OFF by default)
#   --no-deep             Disable deep scans on new TCP ports
#   --no-pn               Disable -Pn (not recommended on HTB/THM)
#   --nmap-all            Use -oA (xml+gnmap+nmap). Default is -oN (.nmap only)
#   --rate <n>            masscan rate (default: 800)
#   --wait <sec>          masscan wait seconds (default: 5)
#   --help                Show help
#
# Notes:
# - Terminal output is HEADLINES ONLY. Full details are saved to .nmap/.log files.
# - macOS notifications use osascript (built-in).
# - Compatible with macOS /bin/bash 3.2 (NO mapfile/readarray).
# ==============================================================================

set -euo pipefail

VERSION="0.1.2"

# -------------------------
# Args (positional)
# -------------------------
TARGET="${1:-}"
INTERVAL_MIN="${2:-}"

if [ $# -ge 2 ]; then
  shift 2
fi

# -------------------------
# Defaults
# -------------------------
IFACE="utun4"
ROUTER_IP=""            # auto-detect if empty, can override via --router-ip
OUTDIR=""               # default = pwd
ONCE=0

UDP_ENABLED=1
UDP_WATCH=0

DEEP_ENABLED=1
PN_ENABLED=1            # -Pn default ON

NMAP_ALL=0              # 0 => -oN (.nmap only), 1 => -oA (.nmap+.xml+.gnmap)

MASSCAN_RATE=800
MASSCAN_WAIT=5

WEB_PORTS_REGEX='^(80|443|8000|8080|8081|8443|8888)$'

# -------------------------
# Privilege helper (avoid nested sudo)
# -------------------------
SUDO=""
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  SUDO="sudo"
fi

# -------------------------
# Helpers
# -------------------------
die() { echo "[!] $*" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ts_display() { date +"%Y-%m-%d %H:%M:%S"; }
ts_file() { date +"%Y-%m-%d_%H-%M-%S"; }

is_number() { echo "${1:-}" | grep -Eq '^[0-9]+$'; }

beep() { printf "\a" >/dev/null 2>&1 || true; }

notify_macos() {
  local title="$1"
  local msg="$2"
  if have_cmd osascript; then
    osascript -e "display notification \"${msg}\" with title \"${title}\"" >/dev/null 2>&1 || true
  fi
}

# macOS router auto-detect (best-effort)
autodetect_router_ip() {
  local ip="$1"
  local gw=""
  gw="$(route -n get "$ip" 2>/dev/null | awk '/gateway:/{print $2; exit}')"
  if [ -n "$gw" ]; then
    echo "$gw"
    return 0
  fi

  # HTB common fallback for utun*
  if echo "$IFACE" | grep -Eq '^utun[0-9]+$'; then
    echo "10.10.14.1"
    return 0
  fi

  echo ""
  return 0
}

# SAFE parsing of ports from masscan .gnmap -> csv (no grep => no crash with pipefail)
extract_ports_from_gnmap() {
  local gnmap="$1"

  [ -f "$gnmap" ] || { echo ""; return 0; }

  awk '
    /Ports:/ {
      sub(/.*Ports: /,"");
      gsub(/, /,",");
      n=split($0,a,",");
      for(i=1;i<=n;i++){
        split(a[i],b,"/");
        if(b[2]=="open"){
          print b[1]
        }
      }
    }
  ' "$gnmap" 2>/dev/null \
    | sed '/^$/d' \
    | sort -n \
    | uniq \
    | paste -sd, - 2>/dev/null || true

  return 0
}

# CSV -> sorted unique lines
csv_to_lines() {
  echo "${1:-}" \
    | tr ',' '\n' \
    | sed '/^$/d' \
    | sort -n \
    | uniq || true
}

ports_pretty() {
  local ports_csv="${1:-}"
  if [ -z "$ports_csv" ]; then
    echo "-"
  else
    echo "$ports_csv"
  fi
}

# New ports vs baseline (baseline lines file, current lines file)
diff_new_ports_files() {
  local baseline_lines="$1"
  local current_lines="$2"
  comm -13 "$baseline_lines" "$current_lines" 2>/dev/null || true
}

# Service+port fallback pack
guess_pack() {
  local port="$1"
  local svc="${2:-}"
  svc="$(echo "$svc" | tr '[:upper:]' '[:lower:]')"

  if echo "$port" | grep -Eq "$WEB_PORTS_REGEX" \
    || echo "$svc" | grep -Eq 'http|https|ssl/http'; then
    echo "http"; return 0
  fi

  case "$port" in
    445|139) echo "smb" ;;
    389|636|3268|3269) echo "ldap" ;;
    5985|5986) echo "winrm" ;;
    3389) echo "rdp" ;;
    53) echo "dns" ;;
    21) echo "ftp" ;;
    22) echo "ssh" ;;
    25|465|587) echo "smtp" ;;
    1433) echo "mssql" ;;
    3306) echo "mysql" ;;
    5432) echo "postgres" ;;
    *) echo "generic" ;;
  esac
}

# -------------------------
# Quiet runners (stdout/stderr -> logs)
# -------------------------
run_masscan() {
  local ip="$1"
  local out_gnmap="$2"
  local log_file="$3"
  local rate="$4"
  local wait_s="$5"

  $SUDO masscan "$ip" \
    -p0-65535 \
    --rate "$rate" \
    --wait "$wait_s" \
    -e "$IFACE" \
    --router-ip "$ROUTER_IP" \
    -oG "$out_gnmap" \
    >"$log_file" 2>&1 || true
}

run_nmap_tcp_full() {
  local ip="$1"
  local ports_csv="$2"
  local out_base="$3"
  local log_file="$4"

  local pn_flag=""
  if [ "$PN_ENABLED" -eq 1 ]; then pn_flag="-Pn"; fi

  if [ "$NMAP_ALL" -eq 1 ]; then
    $SUDO nmap $pn_flag -sS -sV -sC -T3 --version-all --max-retries 3 \
      -p "$ports_csv" "$ip" -oA "$out_base" \
      >"$log_file" 2>&1 || true
  else
    $SUDO nmap $pn_flag -sS -sV -sC -T3 --version-all --max-retries 3 \
      -p "$ports_csv" "$ip" -oN "$out_base" \
      >"$log_file" 2>&1 || true
  fi
}

run_nmap_udp_selective() {
  local ip="$1"
  local out_base="$2"
  local log_file="$3"

  local pn_flag=""
  if [ "$PN_ENABLED" -eq 1 ]; then pn_flag="-Pn"; fi

  if [ "$NMAP_ALL" -eq 1 ]; then
    $SUDO nmap $pn_flag -sU --top-ports 50 --open -T3 \
      "$ip" -oA "$out_base" >"$log_file" 2>&1 || true
  else
    $SUDO nmap $pn_flag -sU --top-ports 50 --open -T3 \
      "$ip" -oN "$out_base" >"$log_file" 2>&1 || true
  fi
}

run_nmap_deep_port() {
  local ip="$1"
  local port="$2"
  local out_file="$3"
  local log_file="$4"

  local pn_flag=""
  if [ "$PN_ENABLED" -eq 1 ]; then pn_flag="-Pn"; fi

  $SUDO nmap $pn_flag -sS -sV -sC -T3 --version-all --max-retries 3 \
    -p "$port" "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
}

run_nmap_http_port() {
  local ip="$1"
  local port="$2"
  local out_file="$3"
  local log_file="$4"

  local pn_flag=""
  if [ "$PN_ENABLED" -eq 1 ]; then pn_flag="-Pn"; fi

  $SUDO nmap $pn_flag -sS -sV -T3 \
    -p "$port" \
    --script "http-title,http-headers,http-methods,http-enum,http-server-header,ssl-cert,ssl-enum-ciphers" \
    "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
}

run_pack() {
  local pack="$1"
  local ip="$2"
  local port="$3"
  local out_file="$4"
  local log_file="$5"

  local pn_flag=""
  if [ "$PN_ENABLED" -eq 1 ]; then pn_flag="-Pn"; fi

  case "$pack" in
    smb)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "smb2-security-mode,smb2-time,smb-os-discovery,smb-security-mode,smb-enum-shares,smb-enum-users" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    ldap)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "ldap-rootdse,ldap-search,ssl-cert" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    winrm)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "http-title,http-headers" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    dns)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "dns-service-discovery,dns-nsid" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    ftp)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "ftp-anon,ftp-syst,banner" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    ssh)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "ssh-hostkey,ssh2-enum-algos" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    smtp)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "smtp-commands,smtp-enum-users,smtp-open-relay" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
    http)
      run_nmap_http_port "$ip" "$port" "$out_file" "$log_file"
      ;;
    *)
      $SUDO nmap $pn_flag -sS -sV -T3 -p "$port" \
        --script "banner,default" \
        "$ip" -oN "$out_file" >"$log_file" 2>&1 || true
      ;;
  esac
}

print_help() {
  cat <<EOF
Magnum Scanner v$VERSION

Usage:
  magnum.sh <target> <interval_min> [options]

Options:
  --iface <name>        Interface (default: utun4)
  --router-ip <ip>      Force router IP (otherwise auto-detect best-effort)
  --outdir <path>       Write ./scans/<TARGET>/ under this directory (default: PWD)
  --once                Run one baseline cycle then exit
  --no-udp              Disable UDP selective baseline
  --udp-watch           Enable UDP watch (OFF by default)
  --no-deep             Disable deep scans on new TCP ports
  --no-pn               Disable -Pn (not recommended on HTB/THM)
  --nmap-all            Use -oA (xml+gnmap+nmap). Default is -oN (.nmap only)
  --rate <n>            masscan rate (default: 800)
  --wait <sec>          masscan wait seconds (default: 5)
  --help                Show help

Examples:
  sudo -E ./magnum.sh 10.10.10.77 10 --iface utun4 --outdir "\$(pwd)"
  sudo -E ./magnum.sh 10.10.10.77 10 --iface utun4 --outdir "\$(pwd)" --once
EOF
}

# -------------------------
# Parse options
# -------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACE="${2:-}"; shift 2 ;;
    --router-ip) ROUTER_IP="${2:-}"; shift 2 ;;
    --outdir) OUTDIR="${2:-}"; shift 2 ;;
    --once) ONCE=1; shift ;;
    --no-udp) UDP_ENABLED=0; shift ;;
    --udp-watch) UDP_WATCH=1; shift ;;
    --no-deep) DEEP_ENABLED=0; shift ;;
    --no-pn) PN_ENABLED=0; shift ;;
    --nmap-all) NMAP_ALL=1; shift ;;
    --rate) MASSCAN_RATE="${2:-}"; shift 2 ;;
    --wait) MASSCAN_WAIT="${2:-}"; shift 2 ;;
    --help) print_help; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

# -------------------------
# Validation
# -------------------------
[ -n "$TARGET" ] || { print_help; exit 1; }
[ -n "$INTERVAL_MIN" ] || { print_help; exit 1; }
is_number "$INTERVAL_MIN" || die "Interval must be a number (minutes)"
is_number "$MASSCAN_RATE" || die "--rate must be a number"
is_number "$MASSCAN_WAIT" || die "--wait must be a number"

have_cmd nmap || die "nmap not found"
have_cmd masscan || die "masscan not found"

[ -n "$OUTDIR" ] || OUTDIR="$(pwd)"

if [ -z "$ROUTER_IP" ]; then
  ROUTER_IP="$(autodetect_router_ip "$TARGET")"
fi
[ -n "$ROUTER_IP" ] || die "Could not auto-detect ROUTER_IP. Use --router-ip <ip>"

# -------------------------
# Directories
# -------------------------
BASE_DIR="$OUTDIR/scans/$TARGET"
MASSCAN_DIR="$BASE_DIR/masscan"
NMAP_DIR="$BASE_DIR/nmap"
PACKS_DIR="$NMAP_DIR/baseline_packs"
NEW_DIR="$NMAP_DIR/new_ports"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$MASSCAN_DIR" "$NMAP_DIR" "$PACKS_DIR" "$NEW_DIR" "$LOG_DIR"

# -------------------------
# Banner (red)
# -------------------------
clear >/dev/null 2>&1 || true
RED="\033[1;31m"
NC="\033[0m"

printf "%b" "$RED"
cat <<'BANNER'

            ███╗   ███╗ █████╗  ██████╗ ███╗   ██╗██╗   ██╗███╗   ███╗
            ████╗ ████║██╔══██╗██╔════╝ ████╗  ██║██║   ██║████╗ ████║
            ██╔████╔██║███████║██║  ███╗██╔██╗ ██║██║   ██║██╔████╔██║
            ██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║██║   ██║██║╚██╔╝██║
            ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
            ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝

           ═══════════════════════════════     RACING MODE     ═══════════════════════════════


          _________________________________                          ____________________________________
        _/ ____  ____  ____ ____  ____  __ \_   Go ahead, Magnum   _/ __  ____  ____  ____  ____    ____ \_
        /_/___/__/___/__/___/__/_/___/__/___/                       /_/__\__\_/__\__\_/__\_/__\_/__\_/__\_\


BANNER
printf "%b" "$NC"

MODE_LABEL="WATCH"
if [ "$ONCE" -eq 1 ]; then MODE_LABEL="ONCE"; fi

echo "      =[ Magnum Scanner | v$VERSION ]"
echo "+ -- --=[ Target : $TARGET ]"
echo "+ -- --=[ IFACE  : $IFACE | Router : $ROUTER_IP ]"
echo "+ -- --=[ Mode   : $MODE_LABEL | Interval : ${INTERVAL_MIN}m ]"
echo "+ -- --=[ TCP Deep : $([ "$DEEP_ENABLED" -eq 1 ] && echo ON || echo OFF) ]"
echo "+ -- --=[ UDP Sel  : $([ "$UDP_ENABLED" -eq 1 ] && echo ON || echo OFF) | UDP Watch: $([ "$UDP_WATCH" -eq 1 ] && echo ON || echo OFF) ]"
echo "+ -- --=[ -Pn      : $([ "$PN_ENABLED" -eq 1 ] && echo ON || echo OFF) ]"
echo "+ -- --=[ NmapOut  : $([ "$NMAP_ALL" -eq 1 ] && echo "oA (xml+gnmap+nmap)" || echo "oN (.nmap only)") ]"
echo "+ -- --=[ OutDir   : $OUTDIR ]"
echo

# ==============================================================================
# BASELINE
# ==============================================================================
BASE_TS="$(ts_file)"

BASE_MASSCAN="$MASSCAN_DIR/masscan_baseline_${BASE_TS}.gnmap"
BASE_MASSCAN_LOG="$LOG_DIR/masscan_baseline_${BASE_TS}.log"

echo "[+] TCP Baseline (masscan)"
run_masscan "$TARGET" "$BASE_MASSCAN" "$BASE_MASSCAN_LOG" "$MASSCAN_RATE" "$MASSCAN_WAIT"

BASE_PORTS="$(extract_ports_from_gnmap "$BASE_MASSCAN")"
[ -n "$BASE_PORTS" ] || die "No open TCP ports found in baseline (see log: $BASE_MASSCAN_LOG)"

echo "[+] Baseline TCP ports: $(ports_pretty "$BASE_PORTS")"

# Baseline ports tracking files
BASELINE_CSV_FILE="$LOG_DIR/baseline_tcp_ports.csv"
BASELINE_LINES_FILE="$LOG_DIR/baseline_tcp_ports.lines"
LAST_LINES_FILE="$LOG_DIR/last_tcp_set.lines"

echo "$BASE_PORTS" > "$BASELINE_CSV_FILE"
csv_to_lines "$BASE_PORTS" > "$BASELINE_LINES_FILE"
cp "$BASELINE_LINES_FILE" "$LAST_LINES_FILE"

# Baseline full Nmap report
BASE_NMAP_LOG="$LOG_DIR/nmap_baseline_tcp_${BASE_TS}.log"
if [ "$NMAP_ALL" -eq 1 ]; then
  BASE_NMAP_BASE="$NMAP_DIR/nmap_baseline_tcp_${BASE_TS}"
  BASE_NMAP_FILE="${BASE_NMAP_BASE}.nmap"
else
  BASE_NMAP_FILE="$NMAP_DIR/nmap_baseline_tcp_${BASE_TS}.nmap"
  BASE_NMAP_BASE="$BASE_NMAP_FILE"
fi

echo
echo "[+] Baseline TCP service scan (nmap -sC -sV) -> full output saved"
run_nmap_tcp_full "$TARGET" "$BASE_PORTS" "$BASE_NMAP_BASE" "$BASE_NMAP_LOG"
echo "[+] Saved baseline report: $BASE_NMAP_FILE"

# Baseline service packs
echo
echo "[+] Baseline service packs (known services only)"
: > "$LOG_DIR/baseline_packs_index.txt"

BASE_SVC_TMP="$LOG_DIR/_baseline_services_${BASE_TS}.tmp"
awk '/\/tcp[[:space:]]+open/{print $1, $3}' "$BASE_NMAP_FILE" 2>/dev/null > "$BASE_SVC_TMP" || true

while read -r p_field svc; do
  [ -n "${p_field:-}" ] || continue
  port="${p_field%%/*}"

  pack="$(guess_pack "$port" "$svc")"
  case "$pack" in
    http|smb|ldap|winrm|dns|ftp|ssh|smtp)
      out="$PACKS_DIR/nmap_${pack}_pack_baseline_tcp_${BASE_TS}_p${port}.nmap"
      log="$LOG_DIR/nmap_${pack}_pack_baseline_tcp_${BASE_TS}_p${port}.log"
      run_pack "$pack" "$TARGET" "$port" "$out" "$log"
      echo "  [+] ${port}/tcp -> ${pack} pack (saved: $out)"
      echo "$out" >> "$LOG_DIR/baseline_packs_index.txt"
      ;;
    *) ;;
  esac
done < "$BASE_SVC_TMP"

rm -f "$BASE_SVC_TMP" >/dev/null 2>&1 || true

# UDP baseline
if [ "$UDP_ENABLED" -eq 1 ]; then
  echo
  echo "[+] UDP Selective Baseline (nmap -sU --top-ports 50 --open)"
  UDP_LOG="$LOG_DIR/nmap_baseline_udp_${BASE_TS}.log"
  if [ "$NMAP_ALL" -eq 1 ]; then
    UDP_BASE="$NMAP_DIR/nmap_baseline_udp_${BASE_TS}"
    UDP_FILE="${UDP_BASE}.nmap"
  else
    UDP_FILE="$NMAP_DIR/nmap_baseline_udp_${BASE_TS}.nmap"
    UDP_BASE="$UDP_FILE"
  fi
  run_nmap_udp_selective "$TARGET" "$UDP_BASE" "$UDP_LOG"
  echo "[+] Saved UDP baseline report: $UDP_FILE"
fi

echo
echo "🧭 Helper commands:"
echo "  open baseline full report:     less \"$BASE_NMAP_FILE\""
echo "  open baseline packs index:     less \"$LOG_DIR/baseline_packs_index.txt\""
echo "  open new ports index:          less \"$LOG_DIR/new_ports_index.txt\""
echo

if [ "$ONCE" -eq 1 ]; then
  echo "[✓] Baseline cycle completed at $(ts_display)"
  exit 0
fi

# ==============================================================================
# WATCH
# ==============================================================================
echo "=============================================="
echo "[*] WATCH MODE STARTED"
echo "[*] Target   : $TARGET"
echo "[*] Interval : $INTERVAL_MIN minute(s)"
echo "[*] Trigger  : press ENTER or: touch \"$OUTDIR/trigger_rescan\""
echo "=============================================="
echo

: > "$LOG_DIR/new_ports_index.txt"
rm -f "$OUTDIR/trigger_rescan" >/dev/null 2>&1 || true

while true; do
  if read -r -t $((INTERVAL_MIN * 60)) _; then
    echo "[!] Manual trigger detected (ENTER)"
  fi

  if [ -f "$OUTDIR/trigger_rescan" ]; then
    echo "[!] Manual trigger detected (file: trigger_rescan)"
    rm -f "$OUTDIR/trigger_rescan" >/dev/null 2>&1 || true
  fi

  CUR_TS="$(ts_file)"

  CUR_MASSCAN="$MASSCAN_DIR/masscan_rescan_${CUR_TS}.gnmap"
  CUR_MASSCAN_LOG="$LOG_DIR/masscan_rescan_${CUR_TS}.log"

  echo "----------------------------------------------"
  echo "[*] Rescan at $(ts_display) (TS=$CUR_TS)"

  run_masscan "$TARGET" "$CUR_MASSCAN" "$CUR_MASSCAN_LOG" "$MASSCAN_RATE" "$MASSCAN_WAIT"
  CUR_PORTS="$(extract_ports_from_gnmap "$CUR_MASSCAN")"

  echo "[+] Current TCP ports: $(ports_pretty "$CUR_PORTS")"

  CUR_LINES_TMP="$LOG_DIR/_current_tcp_${CUR_TS}.lines"
  csv_to_lines "$CUR_PORTS" > "$CUR_LINES_TMP"

  if diff -q "$CUR_LINES_TMP" "$LAST_LINES_FILE" >/dev/null 2>&1; then
    echo "[+] No TCP port-set change"
  else
    echo "[+] TCP port-set changed -> running full nmap change report"

    CHANGE_LOG="$LOG_DIR/nmap_change_tcp_${CUR_TS}.log"
    if [ "$NMAP_ALL" -eq 1 ]; then
      CHANGE_BASE="$NMAP_DIR/nmap_change_tcp_${CUR_TS}"
      CHANGE_FILE="${CHANGE_BASE}.nmap"
    else
      CHANGE_FILE="$NMAP_DIR/nmap_change_tcp_${CUR_TS}.nmap"
      CHANGE_BASE="$CHANGE_FILE"
    fi

    if [ -n "$CUR_PORTS" ]; then
      run_nmap_tcp_full "$TARGET" "$CUR_PORTS" "$CHANGE_BASE" "$CHANGE_LOG"
      echo "[+] Saved change report: $CHANGE_FILE"
    else
      echo "[!] No ports found in current rescan (see: $CUR_MASSCAN_LOG)"
    fi

    cp "$CUR_LINES_TMP" "$LAST_LINES_FILE"

    NEWPORTS_LIST="$(diff_new_ports_files "$BASELINE_LINES_FILE" "$CUR_LINES_TMP" | tr -d '\r')"
    if [ -n "$NEWPORTS_LIST" ]; then
      echo "[🚨] New TCP ports vs baseline: $(echo "$NEWPORTS_LIST" | paste -sd' ' -)"

      echo "$NEWPORTS_LIST" | while read -r p; do
        [ -n "${p:-}" ] || continue

        beep
        notify_macos "Magnum Scanner" "New port: ${p}/tcp"

        if [ "$DEEP_ENABLED" -eq 1 ]; then
          deep_out="$NEW_DIR/nmap_deep_tcp_${CUR_TS}_p${p}.nmap"
          deep_log="$LOG_DIR/nmap_deep_tcp_${CUR_TS}_p${p}.log"
          run_nmap_deep_port "$TARGET" "$p" "$deep_out" "$deep_log"
          echo "  [+] Deep scan saved: $deep_out"
          echo "$deep_out" >> "$LOG_DIR/new_ports_index.txt"

          if echo "$p" | grep -Eq "$WEB_PORTS_REGEX"; then
            http_out="$NEW_DIR/nmap_http_tcp_${CUR_TS}_p${p}.nmap"
            http_log="$LOG_DIR/nmap_http_tcp_${CUR_TS}_p${p}.log"
            run_nmap_http_port "$TARGET" "$p" "$http_out" "$http_log"
            echo "  [+] HTTP scan saved: $http_out"
            echo "$http_out" >> "$LOG_DIR/new_ports_index.txt"
          fi

          pack="$(guess_pack "$p" "")"
          if [ "$pack" != "generic" ]; then
            pack_out="$NEW_DIR/nmap_${pack}_pack_new_tcp_${CUR_TS}_p${p}.nmap"
            pack_log="$LOG_DIR/nmap_${pack}_pack_new_tcp_${CUR_TS}_p${p}.log"
            run_pack "$pack" "$TARGET" "$p" "$pack_out" "$pack_log"
            echo "  [+] ${pack} pack saved: $pack_out"
            echo "$pack_out" >> "$LOG_DIR/new_ports_index.txt"
          fi
        fi
      done
    else
      echo "[+] No new TCP ports vs baseline"
    fi
  fi

  echo
  echo "🧭 Helper commands:"
  echo "  open baseline full report:     less \"$BASE_NMAP_FILE\""
  if [ -f "$NMAP_DIR/nmap_change_tcp_${CUR_TS}.nmap" ]; then
    echo "  open latest change report:     less \"$NMAP_DIR/nmap_change_tcp_${CUR_TS}.nmap\""
  fi
  echo "  open baseline packs index:     less \"$LOG_DIR/baseline_packs_index.txt\""
  echo "  open new ports index:          less \"$LOG_DIR/new_ports_index.txt\""
  echo

  rm -f "$CUR_LINES_TMP" >/dev/null 2>&1 || true
done
