#!/usr/bin/env bash
# =====================================================
# Magnum Scanner 🏎️
# Baseline + Watch + Alerts + Smart Auto Service Packs (service+port fallback)
# macOS/Linux | writes results to PWD (or --outdir)
#
# Quick:
#   ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)"
#   ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --once
#
# Trigger rescan:
#   press ENTER  OR  touch ./trigger_rescan   (in your current directory)
# =====================================================

set -euo pipefail

MAGNUM_NAME="Magnum Scanner"
MAGNUM_VERSION="0.1.0"
MAGNUM_AUTHOR="Ashraf"

print_version() { echo "${MAGNUM_NAME} v${MAGNUM_VERSION} — by ${MAGNUM_AUTHOR}"; }

print_help() {
cat <<'EOF'
Magnum Scanner — Baseline + Watch + Alerts + Smart Auto Service Packs (service+port fallback)

Usage:
  magnum.sh <target-ip> [minutes] [options]

Examples (macOS/HTB):
  ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)"
  ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --once
  ./magnum.sh 10.10.10.172 3 --iface utun4 --router-ip 10.10.14.1 --outdir "$(pwd)"
  ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --no-udp
  ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --no-deep
  ./magnum.sh 10.10.10.172 3 --iface utun4 --outdir "$(pwd)" --nmap-all

Options:
  --once               Run baseline (if missing) + ONE rescan cycle then exit.
  --outdir <path>      Write outputs under <path>. Default: current directory.
  --iface <name>       VPN interface (default: utun4). Examples: tun0, utun4, wg0
  --router-ip <ip>     Force router-ip for masscan (overrides auto-detect).
  --no-deep            Disable deep scans on NEW tcp ports.
  --no-udp             Disable UDP selective baseline scan.
  --udp-watch          Also rescan UDP selective list each cycle (optional).
  --no-pn              Disable -Pn (NOT recommended for HTB/THM/OSCP).
  --nmap-all           Use -oA (creates .nmap + .xml + .gnmap). Default is .nmap only.
  -V, --version        Show version.
  -h, --help           Show help.

Trigger (watch mode):
  - Press ENTER to rescan now
  - Or: touch ./trigger_rescan  (in your current directory)
EOF
}

# fast pre-parse for help/version
for a in "${@:-}"; do
  [[ "$a" == "--help" || "$a" == "-h" ]] && { print_help; exit 0; }
  [[ "$a" == "--version" || "$a" == "-V" ]] && { print_version; exit 0; }
done

# -----------------------------
# Required tools
# -----------------------------
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing required command: $1"; exit 1; }; }
need_cmd nmap
need_cmd masscan
need_cmd sed
need_cmd awk
need_cmd sort
need_cmd uniq
need_cmd paste
need_cmd comm

# -----------------------------
# Args
# -----------------------------
TARGET="${1:-}"
RESCAN_MINUTES="${2:-5}"

if [[ -z "$TARGET" ]]; then
  print_help
  exit 1
fi

# if 2nd arg isn't an integer, treat as missing minutes
if [[ -n "${2:-}" ]] && ! [[ "${2:-}" =~ ^[0-9]+$ ]]; then
  RESCAN_MINUTES=5
fi

if ! [[ "$RESCAN_MINUTES" =~ ^[0-9]+$ ]] || [[ "$RESCAN_MINUTES" -lt 1 ]]; then
  echo "[!] minutes must be >= 1"
  exit 1
fi

# -----------------------------
# Flags (defaults)
# -----------------------------
ONCE_MODE=0
OUTDIR=""
IFACE="utun4"
ROUTER_IP_MANUAL=""
DEEP_ENABLE=1
UDP_ENABLE=1
UDP_WATCH=0
USE_PN=1
NMAP_ALL=0

ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[$i]}" in
    --once) ONCE_MODE=1 ;;
    --outdir) ((i++)); OUTDIR="${ARGS[$i]:-}"; [[ -n "$OUTDIR" ]] || { echo "[!] --outdir needs a path"; exit 1; } ;;
    --iface) ((i++)); IFACE="${ARGS[$i]:-}"; [[ -n "$IFACE" ]] || { echo "[!] --iface needs a name"; exit 1; } ;;
    --router-ip) ((i++)); ROUTER_IP_MANUAL="${ARGS[$i]:-}"; [[ -n "$ROUTER_IP_MANUAL" ]] || { echo "[!] --router-ip needs an ip"; exit 1; } ;;
    --no-deep) DEEP_ENABLE=0 ;;
    --no-udp) UDP_ENABLE=0 ;;
    --udp-watch) UDP_WATCH=1 ;;
    --no-pn) USE_PN=0 ;;
    --nmap-all) NMAP_ALL=1 ;;
    --help|-h) print_help; exit 0 ;;
    --version|-V) print_version; exit 0 ;;
  esac
  ((i++))
done

# -----------------------------
# OS helpers
# -----------------------------
is_macos() { [[ "$(uname -s)" == "Darwin" ]]; }
ts_display() { date +"%Y-%m-%d %H:%M:%S"; }
ts_file()    { date +"%Y-%m-%d_%H-%M-%S"; }

NMAP_PN=""
[[ "$USE_PN" -eq 1 ]] && NMAP_PN="-Pn"

# Use sudo for nmap when not root (needed for -sS)
SUDO_NMAP=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO_NMAP="sudo"
fi

# -----------------------------
# Beep + macOS Notification
# -----------------------------
ENABLE_BEEP=1
ENABLE_NOTIFY=1
beep() { [[ "$ENABLE_BEEP" -eq 1 ]] && printf "\a" || true; }

escape_osascript() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  echo "$s"
}
notify_user() {
  [[ "$ENABLE_NOTIFY" -eq 1 ]] || return 0
  local title="$1" message="$2"
  if is_macos && command -v osascript >/dev/null 2>&1; then
    local t m
    t="$(escape_osascript "$title")"
    m="$(escape_osascript "$message")"
    osascript -e "display notification \"${m}\" with title \"${t}\"" >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# Output root (PWD-based)
# -----------------------------
RUN_DIR="$(pwd)"
if [[ -n "$OUTDIR" ]]; then
  PROJECT_DIR="$(cd "$RUN_DIR" && mkdir -p "$OUTDIR" && cd "$OUTDIR" && pwd)"
else
  PROJECT_DIR="$RUN_DIR"
fi

SCANS_DIR="${PROJECT_DIR}/scans"
BASE_DIR="${SCANS_DIR}/${TARGET}"
MASSCAN_DIR="${BASE_DIR}/masscan"
NMAP_DIR="${BASE_DIR}/nmap"
NEWPORTS_DIR="${NMAP_DIR}/new_ports"
BASELINE_PACKS_DIR="${NMAP_DIR}/baseline_packs"
LOG_DIR="${BASE_DIR}/logs"

mkdir -p "$MASSCAN_DIR" "$NMAP_DIR" "$NEWPORTS_DIR" "$BASELINE_PACKS_DIR" "$LOG_DIR"
TRIGGER_FILE="${PROJECT_DIR}/trigger_rescan"

# -----------------------------
# ROUTER IP auto-detect (macOS-friendly)
# -----------------------------
get_iface_ipv4() {
  local iface="$1"
  if is_macos; then
    ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2; exit}'
  else
    ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
  fi
}
get_gateway_to_target() {
  local target="$1"
  if is_macos; then
    route -n get "$target" 2>/dev/null | awk '/gateway:/{print $2; exit}'
  else
    ip route get "$target" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}'
  fi
}
get_iface_gateway_default() {
  local iface="$1"
  if is_macos; then
    netstat -rn -f inet 2>/dev/null | awk -v ifc="$iface" '$1=="default" && $NF==ifc {print $2; exit}'
  else
    ip route show 0.0.0.0/0 dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}'
  fi
}

if [[ -n "$ROUTER_IP_MANUAL" ]]; then
  ROUTER_IP="$ROUTER_IP_MANUAL"
else
  ROUTER_IP="$(get_gateway_to_target "$TARGET" || true)"
  [[ -z "$ROUTER_IP" ]] && ROUTER_IP="$(get_iface_gateway_default "$IFACE" || true)"
  [[ -z "$ROUTER_IP" ]] && ROUTER_IP="$(get_iface_ipv4 "$IFACE" || true)"
fi

if [[ -z "${ROUTER_IP:-}" ]]; then
  echo "[!] Could not auto-detect ROUTER_IP for interface: $IFACE"
  echo "    - Verify interface name (--iface tun0 / utun4 / wg0)"
  echo "    - Or force it: --router-ip 10.10.14.1"
  exit 1
fi

# -----------------------------
# Banner
# -----------------------------
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

echo
echo "      =[ ${MAGNUM_NAME} | v${MAGNUM_VERSION} ]"
echo "+ -- --=[ Target : $TARGET ]"
echo "+ -- --=[ IFACE  : $IFACE | Router : $ROUTER_IP ]"
echo "+ -- --=[ Mode   : $([[ "$ONCE_MODE" -eq 1 ]] && echo ONCE || echo WATCH) | Interval : ${RESCAN_MINUTES}m ]"
echo "+ -- --=[ TCP Deep : $([[ "$DEEP_ENABLE" -eq 1 ]] && echo ON || echo OFF) ]"
echo "+ -- --=[ UDP Sel  : $([[ "$UDP_ENABLE" -eq 1 ]] && echo ON || echo OFF) | UDP Watch: $([[ "$UDP_WATCH" -eq 1 ]] && echo ON || echo OFF) ]"
echo "+ -- --=[ -Pn      : $([[ "$USE_PN" -eq 1 ]] && echo ON || echo OFF) ]"
echo "+ -- --=[ NmapOut  : $([[ "$NMAP_ALL" -eq 1 ]] && echo 'oA (.nmap+xml+gnmap)' || echo 'oN (.nmap only)') ]"
echo "+ -- --=[ OutDir   : $PROJECT_DIR ]"
echo

# -----------------------------
# State files (NO initial/current/tcp-ports-details)
# -----------------------------
BASELINE_TCP_FILE="${LOG_DIR}/baseline_tcp_ports.txt"
LAST_TCP_SET_FILE="${LOG_DIR}/last_tcp_set.txt"
SEEN_NEW_TCP_FILE="${LOG_DIR}/seen_new_tcp_ports.txt"
ALERT_TCP_FILE="${LOG_DIR}/alerts_new_tcp_ports.txt"
BASELINE_PACKS_INDEX="${LOG_DIR}/baseline_packs_index.txt"
NEW_PORTS_INDEX="${LOG_DIR}/new_ports_index.txt"

BASELINE_UDP_FILE="${LOG_DIR}/baseline_udp_ports.txt"
LAST_UDP_SET_FILE="${LOG_DIR}/last_udp_set.txt"

touch "$SEEN_NEW_TCP_FILE" "$ALERT_TCP_FILE" "$LAST_TCP_SET_FILE" "$BASELINE_PACKS_INDEX" "$NEW_PORTS_INDEX" \
      "$BASELINE_UDP_FILE" "$LAST_UDP_SET_FILE"

# -----------------------------
# Masscan + parse
# -----------------------------
run_masscan_tcp() {
  local out="$1" rate="$2" wait="$3"
  sudo masscan "$TARGET" \
    -p0-65535 \
    --rate "$rate" \
    --wait "$wait" \
    -e "$IFACE" \
    --router-ip "$ROUTER_IP" \
    -oG "$out"
}

extract_tcp_ports_sorted() {
  local gnmap="$1"
  grep 'Ports:' "$gnmap" \
    | sed -E 's/.*Ports: //' \
    | tr ',' '\n' \
    | cut -d/ -f1 \
    | sort -n \
    | uniq
}

# -----------------------------
# Nmap wrappers (full reports)
# -----------------------------
nmap_full_tcp_report() {
  local ts="$1" tag="$2" ports_csv="$3"
  if [[ "$NMAP_ALL" -eq 1 ]]; then
    local base="${NMAP_DIR}/nmap_${tag}_tcp_${ts}"
    ${SUDO_NMAP} nmap $NMAP_PN -p "$ports_csv" -sS -sV -sC \
      -T3 --version-all --max-retries 3 --host-timeout 300s \
      "$TARGET" -oA "$base"
    echo "${base}.nmap"
  else
    local out="${NMAP_DIR}/nmap_${tag}_tcp_${ts}.nmap"
    ${SUDO_NMAP} nmap $NMAP_PN -p "$ports_csv" -sS -sV -sC \
      -T3 --version-all --max-retries 3 --host-timeout 300s \
      "$TARGET" -oN "$out"
    echo "$out"
  fi
}

nmap_one_port_scripts_to_dir() {
  local dir="$1" port="$2" ts="$3" name="$4" scripts="$5"
  if [[ "$NMAP_ALL" -eq 1 ]]; then
    local base="${dir}/nmap_${name}_tcp_${ts}_p${port}"
    ${SUDO_NMAP} nmap $NMAP_PN -p "$port" -sV -T3 --version-all \
      --max-retries 2 --host-timeout 180s --script "$scripts" \
      "$TARGET" -oA "$base"
    echo "${base}.nmap"
  else
    local out="${dir}/nmap_${name}_tcp_${ts}_p${port}.nmap"
    ${SUDO_NMAP} nmap $NMAP_PN -p "$port" -sV -T3 --version-all \
      --max-retries 2 --host-timeout 180s --script "$scripts" \
      "$TARGET" -oN "$out"
    echo "$out"
  fi
}

tcp_quick_fingerprint_line() {
  local port="$1"
  ${SUDO_NMAP} nmap $NMAP_PN -p "$port" -sV --version-light -T3 \
    --max-retries 2 --host-timeout 120s "$TARGET" 2>/dev/null \
    | awk '/^[0-9]+\/tcp[[:space:]]+open/ {print; exit}'
}

tcp_quick_fingerprint_pretty() {
  local port="$1"
  local line service
  line="$(tcp_quick_fingerprint_line "$port" || true)"
  service="$(echo "$line" | awk '{print $3}')"
  [[ -z "$service" ]] && service="unknown"
  echo "$(echo "$service" | tr '[:lower:]' '[:upper:]') on ${port}"
}

tcp_quick_fingerprint_service() {
  local port="$1"
  local line svc
  line="$(tcp_quick_fingerprint_line "$port" || true)"
  svc="$(echo "$line" | awk '{print tolower($3)}')"
  [[ -z "$svc" ]] && svc="unknown"

  case "$svc" in
    http|http-alt|http-proxy|ssl/http|https|https-alt) echo "http" ;;
    microsoft-ds|netbios-ssn|smb) echo "smb" ;;
    ldap|ssl/ldap|ldaps) echo "ldap" ;;
    ms-wbt-server|rdp) echo "rdp" ;;
    domain|dns) echo "dns" ;;
    ftp) echo "ftp" ;;
    smtp|smtps|submission) echo "smtp" ;;
    ms-sql-s|mssql) echo "mssql" ;;
    mysql) echo "mysql" ;;
    postgresql|postgres|pgsql) echo "postgres" ;;
    ssh) echo "ssh" ;;
    winrm) echo "winrm" ;;
    *) echo "$svc" ;;
  esac
}

# -----------------------------
# Deep + HTTP scan for NEW ports
# -----------------------------
tcp_deep_scan_new_port() {
  local port="$1" ts="$2"
  [[ "$DEEP_ENABLE" -eq 1 ]] || { echo "|"; return 0; }

  local deep_file http_file
  deep_file=""
  http_file=""

  # Deep scan (per port)
  if [[ "$NMAP_ALL" -eq 1 ]]; then
    local base="${NEWPORTS_DIR}/nmap_deep_tcp_${ts}_p${port}"
    ${SUDO_NMAP} nmap $NMAP_PN -p "$port" -sC -sV -sS \
      -T3 --version-all --max-retries 3 --host-timeout 180s \
      "$TARGET" -oA "$base"
    deep_file="${base}.nmap"
  else
    local out="${NEWPORTS_DIR}/nmap_deep_tcp_${ts}_p${port}.nmap"
    ${SUDO_NMAP} nmap $NMAP_PN -p "$port" -sC -sV -sS \
      -T3 --version-all --max-retries 3 --host-timeout 180s \
      "$TARGET" -oN "$out"
    deep_file="$out"
  fi

  # Extra HTTP scripts if looks web-ish (port-based)
  case "$port" in
    80|443|8080|8000|8443|8888)
      if [[ "$NMAP_ALL" -eq 1 ]]; then
        local hbase="${NEWPORTS_DIR}/nmap_http_tcp_${ts}_p${port}"
        ${SUDO_NMAP} nmap $NMAP_PN -p "$port" \
          --script "http-title,http-methods,http-headers,http-enum" \
          -T3 --max-retries 2 --host-timeout 180s \
          "$TARGET" -oA "$hbase"
        http_file="${hbase}.nmap"
      else
        local hout="${NEWPORTS_DIR}/nmap_http_tcp_${ts}_p${port}.nmap"
        ${SUDO_NMAP} nmap $NMAP_PN -p "$port" \
          --script "http-title,http-methods,http-headers,http-enum" \
          -T3 --max-retries 2 --host-timeout 180s \
          "$TARGET" -oN "$hout"
        http_file="$hout"
      fi
    ;;
  esac

  echo "${deep_file}|${http_file}"
}

# -----------------------------
# Smart Auto Service Packs (service+port fallback)
# -----------------------------
detect_pack_service() {
  local port="$1"
  local svc
  svc="$(tcp_quick_fingerprint_service "$port")"

  # fallback for unknown/tcpwrapped/ssl-ish
  if [[ "$svc" == "unknown" || "$svc" == "tcpwrapped" || "$svc" == "ssl" ]]; then
    case "$port" in
      22) svc="ssh" ;;
      21) svc="ftp" ;;
      25|465|587) svc="smtp" ;;
      53) svc="dns" ;;
      80|443|8080|8000|8443|8888) svc="http" ;;
      139|445) svc="smb" ;;
      389|636|3268|3269) svc="ldap" ;;
      3389) svc="rdp" ;;
      5985|5986) svc="winrm" ;;
      1433) svc="mssql" ;;
      3306) svc="mysql" ;;
      5432) svc="postgres" ;;
      *) svc="unknown" ;;
    esac
  fi
  echo "$svc"
}

run_pack_to_dir() {
  local dir="$1" port="$2" ts="$3" mode_tag="$4"  # baseline|new
  local svc out_name scripts out_file

  svc="$(detect_pack_service "$port")"

  case "$svc" in
    http)   out_name="web_pack_${mode_tag}"; scripts="http-title,http-methods,http-headers,http-enum" ;;
    ssh)    out_name="ssh_pack_${mode_tag}"; scripts="ssh2-enum-algos,ssh-hostkey" ;;
    smb)    out_name="smb_pack_${mode_tag}"; scripts="smb-os-discovery,smb2-security-mode,smb2-time,smb-enum-shares,smb-enum-users" ;;
    ldap)
      out_name="ldap_pack_${mode_tag}"
      if [[ "$port" == "636" || "$port" == "3269" ]]; then
        scripts="ldap-rootdse,ldap-search,ssl-cert,ssl-date"
      else
        scripts="ldap-rootdse,ldap-search"
      fi
    ;;
    rdp)    out_name="rdp_pack_${mode_tag}"; scripts="rdp-ntlm-info,rdp-enum-encryption" ;;
    winrm)
      out_name="winrm_pack_${mode_tag}"
      if [[ "$port" == "5986" ]]; then
        scripts="http-title,http-headers,ssl-cert,ssl-date"
      else
        scripts="http-title,http-headers"
      fi
    ;;
    dns)    out_name="dns_pack_${mode_tag}"; scripts="dns-recursion,dns-nsid,dns-service-discovery" ;;
    ftp)    out_name="ftp_pack_${mode_tag}"; scripts="ftp-anon,ftp-syst" ;;
    smtp)
      out_name="smtp_pack_${mode_tag}"
      if [[ "$port" == "465" ]]; then
        scripts="smtp-commands,ssl-cert,ssl-date"
      else
        scripts="smtp-commands"
      fi
    ;;
    mssql)  out_name="mssql_pack_${mode_tag}"; scripts="ms-sql-info,ms-sql-ntlm-info" ;;
    mysql)  out_name="mysql_pack_${mode_tag}"; scripts="mysql-info" ;;
    postgres) out_name="postgres_pack_${mode_tag}"; scripts="pgsql-info" ;;
    *) return 1 ;;
  esac

  out_file="$(nmap_one_port_scripts_to_dir "$dir" "$port" "$ts" "${out_name}" "$scripts")"
  echo "$svc|$out_file"
  return 0
}

# -----------------------------
# UDP Selective (conservative)
# -----------------------------
udp_selective_scan() {
  local ts="$1" tag="$2"
  local out
  if [[ "$NMAP_ALL" -eq 1 ]]; then
    local base="${NMAP_DIR}/nmap_${tag}_udp_${ts}"
    ${SUDO_NMAP} nmap $NMAP_PN -sU --top-ports 50 --open \
      -T3 --max-retries 2 --host-timeout 300s \
      "$TARGET" -oA "$base"
    out="${base}.nmap"
  else
    out="${NMAP_DIR}/nmap_${tag}_udp_${ts}.nmap"
    ${SUDO_NMAP} nmap $NMAP_PN -sU --top-ports 50 --open \
      -T3 --max-retries 2 --host-timeout 300s \
      "$TARGET" -oN "$out"
  fi
  echo "$out"
}

extract_udp_ports_sorted_from_nmap() {
  local nmapfile="$1"
  awk '/^[0-9]+\/udp[[:space:]]+open/ {split($1,a,"/"); print a[1]}' "$nmapfile" \
    | sort -n | uniq
}

# -----------------------------
# Helper: latest files + commands
# -----------------------------
latest_file() { ls -t $1 2>/dev/null | head -n 1 || true; }

print_helpers() {
  local latest_change latest_baseline latest_deep latest_http latest_pack latest_basepack
  latest_change="$(latest_file "${NMAP_DIR}/nmap_change_tcp_"*.nmap)"
  latest_baseline="$(latest_file "${NMAP_DIR}/nmap_baseline_tcp_"*.nmap)"
  latest_deep="$(latest_file "${NEWPORTS_DIR}/nmap_deep_tcp_"*_p*.nmap)"
  latest_http="$(latest_file "${NEWPORTS_DIR}/nmap_http_tcp_"*_p*.nmap)"
  latest_pack="$(latest_file "${NEWPORTS_DIR}/nmap_"*"_pack_new_tcp_"*_p*.nmap)"
  latest_basepack="$(latest_file "${BASELINE_PACKS_DIR}/nmap_"*"_pack_baseline_tcp_"*_p*.nmap)"

  echo
  echo "🧭 Helper commands:"
  [[ -n "$latest_baseline" ]] && echo "  open baseline full report:     less \"${latest_baseline}\""
  [[ -n "$latest_change"   ]] && echo "  open latest change report:     less \"${latest_change}\""
  [[ -n "$latest_basepack" ]] && echo "  open latest baseline pack:     less \"${latest_basepack}\""
  [[ -f "$BASELINE_PACKS_INDEX" ]] && echo "  open baseline packs index:     less \"${BASELINE_PACKS_INDEX}\""
  [[ -f "$NEW_PORTS_INDEX" ]] && echo "  open new ports index:          less \"${NEW_PORTS_INDEX}\""
  [[ -n "$latest_deep" ]] && echo "  open latest new-port deep:     less \"${latest_deep}\""
  [[ -n "$latest_http" ]] && echo "  open latest http new-port:     less \"${latest_http}\""
  [[ -n "$latest_pack" ]] && echo "  open latest new-port pack:     less \"${latest_pack}\""
  echo
}

# =====================================================
# BASELINE (first time only)
# =====================================================
if [[ ! -s "$BASELINE_TCP_FILE" ]]; then
  TS="$(ts_file)"
  echo "[+] TCP Baseline (masscan)"
  BASE_OUT="${MASSCAN_DIR}/masscan_baseline_${TS}.gnmap"
  run_masscan_tcp "$BASE_OUT" 800 5

  extract_tcp_ports_sorted "$BASE_OUT" > "$BASELINE_TCP_FILE"
  if [[ ! -s "$BASELINE_TCP_FILE" ]]; then
    echo "[!] No open TCP ports in baseline."
    exit 1
  fi

  BASE_CSV="$(paste -sd, - < "$BASELINE_TCP_FILE")"
  echo "[+] Baseline TCP ports: $BASE_CSV"
  echo

  echo "[+] Baseline TCP service scan (nmap -sC -sV) -> full output .nmap"
  baseline_report="$(nmap_full_tcp_report "$TS" "baseline" "$BASE_CSV")"
  echo "[+] Saved baseline report: $baseline_report"
  echo

  echo "==================================================" >> "$BASELINE_PACKS_INDEX"
  echo "Baseline Packs Index | Target=$TARGET | TS=$TS"     >> "$BASELINE_PACKS_INDEX"
  echo "Time: $(ts_display)"                               >> "$BASELINE_PACKS_INDEX"
  echo "Format: PORT | SERVICE | PACK_FILE"                >> "$BASELINE_PACKS_INDEX"
  echo "--------------------------------------------------" >> "$BASELINE_PACKS_INDEX"

  echo "[+] Baseline service packs (known services only)"
  while read -r p; do
    [[ -z "$p" ]] && continue
    if result="$(run_pack_to_dir "$BASELINE_PACKS_DIR" "$p" "$TS" "baseline")"; then
      svc="$(echo "$result" | cut -d'|' -f1)"
      file="$(echo "$result" | cut -d'|' -f2-)"
      echo "  [+] ${p}/tcp -> $svc"
      printf "%s | %s | %s\n" "$p" "$svc" "$file" >> "$BASELINE_PACKS_INDEX"
    fi
  done < "$BASELINE_TCP_FILE"
  echo >> "$BASELINE_PACKS_INDEX"

  if [[ "$UDP_ENABLE" -eq 1 ]]; then
    echo
    echo "[+] UDP Selective Baseline (nmap -sU --top-ports 50 --open)"
    udp_report="$(udp_selective_scan "$TS" "baseline")"
    echo "[+] Saved UDP baseline report: $udp_report"
    extract_udp_ports_sorted_from_nmap "$udp_report" > "$BASELINE_UDP_FILE" || true
    cat "$BASELINE_UDP_FILE" > "$LAST_UDP_SET_FILE" || true
  fi

  cat "$BASELINE_TCP_FILE" > "$LAST_TCP_SET_FILE"
  print_helpers
fi

# =====================================================
# RESCAN CYCLE
# =====================================================
do_rescan() {
  local TS RESCAN_OUT CURRENT_SORTED CURRENT_CSV change_report
  TS="$(ts_file)"

  echo "[*] Rescan at $(ts_display) (TS=$TS)"
  RESCAN_OUT="${MASSCAN_DIR}/masscan_rescan_${TS}.gnmap"
  run_masscan_tcp "$RESCAN_OUT" 400 8

  CURRENT_SORTED="$(extract_tcp_ports_sorted "$RESCAN_OUT" || true)"
  if [[ -z "$CURRENT_SORTED" ]]; then
    echo "[!] No TCP ports found this cycle."
    print_helpers
    return 0
  fi

  CURRENT_CSV="$(echo "$CURRENT_SORTED" | paste -sd, -)"
  echo "[+] Current TCP ports: $CURRENT_CSV"
  echo

  # Full report ONLY if port-set changed since last cycle
  if ! diff -q <(echo "$CURRENT_SORTED") <(cat "$LAST_TCP_SET_FILE" 2>/dev/null | awk 'NF' | sort -n | uniq) >/dev/null 2>&1; then
    echo "[+] TCP port-set changed -> running full nmap report (nmap -sC -sV)"
    change_report="$(nmap_full_tcp_report "$TS" "change" "$CURRENT_CSV")"
    echo "[+] Saved change report: $change_report"
    echo "$CURRENT_SORTED" > "$LAST_TCP_SET_FILE"
  else
    echo "[+] TCP port-set unchanged -> no full report"
  fi

  # NEW ports vs baseline
  local NEW_VS_BASELINE NEW_UNSEEN
  NEW_VS_BASELINE="$(comm -13 <(sort -n "$BASELINE_TCP_FILE" | uniq) <(echo "$CURRENT_SORTED" | sort -n | uniq) || true)"
  NEW_UNSEEN="$(comm -13 <(sort -n "$SEEN_NEW_TCP_FILE" | uniq) <(echo "$NEW_VS_BASELINE" | sort -n | uniq) || true)"

  if [[ -n "$NEW_UNSEEN" ]]; then
    echo
    echo "==================================================" >> "$NEW_PORTS_INDEX"
    echo "New Ports Index | Target=$TARGET | TS=$TS"          >> "$NEW_PORTS_INDEX"
    echo "Time: $(ts_display)"                              >> "$NEW_PORTS_INDEX"
    echo "Format: PORT | SHORT | DEEP_FILE | HTTP_FILE | PACK_SERVICE | PACK_FILE" >> "$NEW_PORTS_INDEX"
    echo "--------------------------------------------------" >> "$NEW_PORTS_INDEX"

    echo "🚨 NEW TCP PORTS DETECTED (vs baseline) 🚨"
    while read -r p; do
      [[ -z "$p" ]] && continue
      echo "$p" >> "$SEEN_NEW_TCP_FILE"

      short="$(tcp_quick_fingerprint_pretty "$p")"
      echo "$(ts_display) | $TARGET | NEW TCP: ${p}/tcp | ${short}" | tee -a "$ALERT_TCP_FILE" >/dev/null

      beep
      notify_user "🚨 New TCP Port: ${p}/tcp" "${short} (${TARGET})"

      deep_http="$(tcp_deep_scan_new_port "$p" "$TS")"
      deep_file="$(echo "$deep_http" | cut -d'|' -f1)"
      http_file="$(echo "$deep_http" | cut -d'|' -f2)"

      pack_service=""
      pack_file=""
      if result="$(run_pack_to_dir "$NEWPORTS_DIR" "$p" "$TS" "new")"; then
        pack_service="$(echo "$result" | cut -d'|' -f1)"
        pack_file="$(echo "$result" | cut -d'|' -f2-)"
      fi

      printf "%s | %s | %s | %s | %s | %s\n" \
        "$p" "$short" "$deep_file" "$http_file" "$pack_service" "$pack_file" >> "$NEW_PORTS_INDEX"

      echo "  [+] Saved new-port scans for: ${p}/tcp"
    done <<< "$NEW_UNSEEN"
    echo >> "$NEW_PORTS_INDEX"
  else
    echo "[+] No new TCP ports vs baseline"
  fi

  # Optional UDP watch
  if [[ "$UDP_ENABLE" -eq 1 && "$UDP_WATCH" -eq 1 ]]; then
    echo
    echo "[+] UDP Selective Watch (top 50 open)"
    udp_change_report="$(udp_selective_scan "$TS" "change")"
    echo "[+] Saved UDP change report: $udp_change_report"
    udp_ports_now="$(extract_udp_ports_sorted_from_nmap "$udp_change_report" || true)"
    if ! diff -q <(echo "$udp_ports_now") <(cat "$LAST_UDP_SET_FILE" 2>/dev/null | awk 'NF' | sort -n | uniq) >/dev/null 2>&1; then
      echo "[!] UDP port-set changed (see report above)"
      echo "$udp_ports_now" > "$LAST_UDP_SET_FILE" || true
    else
      echo "[+] UDP port-set unchanged"
    fi
  fi

  print_helpers
  echo "----------------------------------------------"
}

# =====================================================
# ONCE MODE
# =====================================================
if [[ "$ONCE_MODE" -eq 1 ]]; then
  echo "[*] --once enabled: running ONE rescan cycle then exiting."
  do_rescan
  echo "[✓] Done (--once)."
  exit 0
fi

# =====================================================
# WATCH LOOP
# =====================================================
RESCAN_SECONDS=$((RESCAN_MINUTES * 60))

echo "=============================================="
echo "[*] WATCH MODE STARTED"
echo "[*] Target   : $TARGET"
echo "[*] Interval : ${RESCAN_MINUTES} minute(s)"
echo "[*] Trigger  : press ENTER or: touch ${TRIGGER_FILE}"
echo "=============================================="
echo

last_run_epoch="$(date +%s)"

while true; do
  # Manual ENTER trigger (1s polling)
  if read -r -t 1 _; then
    echo "[!] Manual trigger detected (ENTER)"
    do_rescan
    last_run_epoch="$(date +%s)"
    continue
  fi

  # Trigger file
  if [[ -f "$TRIGGER_FILE" ]]; then
    echo "[!] Trigger file detected: $TRIGGER_FILE"
    rm -f "$TRIGGER_FILE" || true
    do_rescan
    last_run_epoch="$(date +%s)"
    continue
  fi

  # Time-based
  now_epoch="$(date +%s)"
  if (( now_epoch - last_run_epoch >= RESCAN_SECONDS )); then
    do_rescan
    last_run_epoch="$(date +%s)"
  fi
done
