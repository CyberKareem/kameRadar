#!/usr/bin/env bash
# kameRadar — fast, practical OSCP-style recon wrapper for nmap + recon hints
# Usage: ./kameRadar.sh -H <target> [-o outdir] [-p profile] [--udp-top N] [--dns server] [--no-pn]
# Profiles:
#   quick    : TCP top ports + UDP top 200 + basic detail
#   balanced : TCP all ports + UDP top 200 + detail on discovered ports (recommended)
#   beast    : balanced + extra scripts (still avoids "scan the whole universe" UDP)

set -Eeuo pipefail

# ---------- Colors ----------
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'
  YELLOW=$'\033[0;33m'
  GREEN=$'\033[0;32m'
  NC=$'\033[0m'
else
  RED=""; YELLOW=""; GREEN=""; NC=""
fi

# ---------- Defaults ----------
HOST=""
OUTDIR="."
PROFILE="balanced"
UDP_TOP="200"
DNS_SERVER=""
USE_PN="yes"       # default: -Pn (OSCP-safe; avoids missing hosts due to ICMP filtering)
EXTRA_SCRIPTS="no" # enabled in beast
VERBOSE="no"

# ---------- Helpers ----------
die() { echo "${RED}[!]${NC} $*" >&2; exit 1; }
info() { echo "${GREEN}[+]${NC} $*"; }
warn() { echo "${YELLOW}[-]${NC} $*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

is_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

resolve_ipv4() {
  # best-effort IPv4 resolution without depending on one tool
  local name="$1"
  local ip=""

  if command -v getent >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1{print $1}')"
  fi
  if [[ -z "${ip}" ]] && command -v host >/dev/null 2>&1; then
    if [[ -n "${DNS_SERVER}" ]]; then
      ip="$(host -4 -W 1 "$name" "$DNS_SERVER" 2>/dev/null | awk '/has address/{print $NF; exit}')"
    else
      ip="$(host -4 -W 1 "$name" 2>/dev/null | awk '/has address/{print $NF; exit}')"
    fi
  fi
  echo "$ip"
}

extract_open_ports_gnmap() {
  # Args: <file.gnmap> <proto tcp|udp>
  local file="$1"
  local proto="$2"
  [[ -f "$file" ]] || return 0

  awk -F'Ports: ' '/Ports: /{print $2}' "$file" \
    | tr ',' '\n' \
    | awk -F'/' -v p="$proto" '$2=="open" && $3==p {print $1}' \
    | sort -n \
    | paste -sd, -
}

write_summary() {
  local summary="$1"
  local target="$2"
  local ip="$3"
  local tcp_ports="$4"
  local udp_ports="$5"

  {
    echo "# kameRadar Summary"
    echo
    echo "- Target: \`$target\`"
    [[ -n "$ip" ]] && echo "- Resolved IPv4: \`$ip\`"
    echo "- Profile: \`$PROFILE\`"
    echo "- UDP Top Ports: \`$UDP_TOP\`"
    echo "- nmap mode: \`$([[ "$USE_PN" == "yes" ]] && echo "-Pn" || echo "ping")\`"
    echo
    echo "## Open Ports"
    echo
    echo "- TCP: \`${tcp_ports:-none}\`"
    echo "- UDP: \`${udp_ports:-none}\`"
    echo
    echo "## Output Files"
    echo
    echo "- TCP discovery: \`tcp_all.*\` (or \`tcp_top.*\` in quick)"
    echo "- UDP discovery: \`udp_top.*\`"
    echo "- TCP detail: \`tcp_detail.*\`"
    echo "- UDP detail: \`udp_detail.*\`"
    echo "- Recon suggestions: \`RECON.txt\`"
    echo
    echo "## Next Steps"
    echo
    echo "- Start with HTTP/SMB/SNMP/LDAP depending on what’s open."
    echo "- Use RECON.txt to run targeted enumeration (no auto-exec)."
  } > "$summary"
}

generate_recon() {
  # Args: <recon_file> <target> <tcp_ports> <udp_ports>
  local recon_file="$1"
  local target="$2"
  local tcp_ports="$3"
  local udp_ports="$4"

  {
    echo "# Recon Suggestions (copy/paste)"
    echo

    if [[ -n "$tcp_ports" ]]; then
      echo "## Nmap follow-ups"
      echo "nmap -Pn -sC -sV -p${tcp_ports} $target -oN recon_nmap_tcp_detail.txt"
      echo
    fi

    if [[ -n "$udp_ports" ]]; then
      echo "nmap -Pn -sU -sC -sV -p${udp_ports} $target -oN recon_nmap_udp_detail.txt"
      echo
    fi

    if [[ "$tcp_ports" == *"80"* || "$tcp_ports" == *"443"* || "$tcp_ports" == *"8080"* || "$tcp_ports" == *"8000"* ]]; then
      echo "## Web"
      echo "whatweb http://$target/"
      echo "curl -i http://$target/"
      echo "ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$target/FUZZ -fc 404 -t 50"
      echo
      echo "# VHOST fuzz (HTB-style):"
      echo "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://$target/ -H 'Host: FUZZ.<domain>' -fs <baseline_size> -t 50"
      echo
    fi

    if [[ "$tcp_ports" == *"445"* || "$tcp_ports" == *"139"* ]]; then
      echo "## SMB"
      echo "smbclient -L //$target/ -N"
      echo "smbmap -H $target"
      echo "enum4linux -a $target"
      echo
    fi

    if [[ "$udp_ports" == *"161"* ]]; then
      echo "## SNMP"
      echo "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $target"
      echo "snmpwalk -v2c -c public $target 1.3.6.1.2.1.1"
      echo
    fi

    if [[ "$tcp_ports" == *"22"* ]]; then
      echo "## SSH"
      echo "ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa user@$target"
      echo
    fi

    echo "## Notes"
    echo "- Always confirm creds reuse across services (SSH/WinRM/RDP/SMB)."
    echo "- Save proof screenshots and exact commands for reporting."
  } > "$recon_file"
}

run_nmap() {
  # Args: <label> <command...>
  local label="$1"; shift
  info "$label"
  if [[ "$VERBOSE" == "yes" ]]; then
    echo "${YELLOW}CMD:${NC} $*"
  fi
  "$@"
}

# ---------- Arg parsing ----------
# Supports both short and long options.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--host) HOST="${2:-}"; shift 2 ;;
    -o|--output) OUTDIR="${2:-}"; shift 2 ;;
    -p|--profile) PROFILE="${2:-}"; shift 2 ;;
    --udp-top) UDP_TOP="${2:-}"; shift 2 ;;
    -d|--dns) DNS_SERVER="${2:-}"; shift 2 ;;
    --no-pn) USE_PN="no"; shift ;;
    -v|--verbose) VERBOSE="yes"; shift ;;
    -h|--help)
      cat <<'EOF'
kameRadar — OSCP-style recon wrapper

Usage:
  ./kameRadar.sh -H <target> [-o outdir] [-p quick|balanced|beast] [--udp-top N] [-d dns_server] [--no-pn] [-v]

Examples:
  ./kameRadar.sh -H 10.10.10.10
  ./kameRadar.sh -H pandora.htb -p balanced -o scans/
  ./kameRadar.sh -H 10.10.10.10 -p beast --udp-top 500 -v
EOF
      exit 0
      ;;
    *)
      die "Unknown option: $1 (use -h for help)"
      ;;
  esac
done

[[ -n "$HOST" ]] || die "Target is required. Use: -H <target>"

case "$PROFILE" in
  quick)    EXTRA_SCRIPTS="no" ;;
  balanced) EXTRA_SCRIPTS="no" ;;
  beast)    EXTRA_SCRIPTS="yes" ;;
  *) die "Invalid profile: $PROFILE (use quick|balanced|beast)" ;;
esac

# ---------- Requirements ----------
need_cmd nmap
mkdir -p "$OUTDIR"

# Create a safe per-target folder
SAFE_NAME="${HOST//\//_}"
SAFE_NAME="${SAFE_NAME//:/_}"
WORKDIR="${OUTDIR%/}/${SAFE_NAME}"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# ---------- Target resolution ----------
TARGET="$HOST"
RESOLVED_IP=""
if ! is_ip "$HOST"; then
  RESOLVED_IP="$(resolve_ipv4 "$HOST")"
fi

# DNS string for nmap (only affects some lookups)
DNSSTRING=""
if [[ -n "$DNS_SERVER" ]]; then
  DNSSTRING="--dns-server=$DNS_SERVER"
fi

# Ping handling
PNFLAG=()
if [[ "$USE_PN" == "yes" ]]; then
  PNFLAG=(-Pn)
fi

info "Target: $TARGET"
[[ -n "$RESOLVED_IP" ]] && info "Resolved IPv4: $RESOLVED_IP"
info "Profile: $PROFILE"
info "Workdir: $WORKDIR"

# ---------- Scans ----------
# QUICK: TCP top ports + UDP top N + detail on discovered
# BALANCED/BEAST: TCP all ports + UDP top N + detail on discovered

TCP_DISC="tcp_all"
if [[ "$PROFILE" == "quick" ]]; then
  TCP_DISC="tcp_top"
  run_nmap "TCP discovery (top ports)" \
    nmap "${PNFLAG[@]}" -sS --open -sV --version-light $DNSSTRING -oA "$TCP_DISC" "$TARGET"
else
  run_nmap "TCP discovery (all ports)" \
    nmap "${PNFLAG[@]}" -sS -p- --open --min-rate 3000 --max-retries 1 $DNSSTRING -oA "$TCP_DISC" "$TARGET"
fi

run_nmap "UDP discovery (top ${UDP_TOP})" \
  sudo nmap "${PNFLAG[@]}" -sU --top-ports "$UDP_TOP" --open -sV --version-light --max-retries 1 $DNSSTRING -oA "udp_top" "$TARGET"

TCP_PORTS="$(extract_open_ports_gnmap "${TCP_DISC}.gnmap" tcp || true)"
UDP_PORTS="$(extract_open_ports_gnmap "udp_top.gnmap" udp || true)"

if [[ -n "$TCP_PORTS" ]]; then
  # detail scan on discovered TCP ports
  if [[ "$EXTRA_SCRIPTS" == "yes" ]]; then
    run_nmap "TCP detail (scripts+version+OS guess)" \
      sudo nmap "${PNFLAG[@]}" -sC -sV --version-all -O --osscan-guess -p "$TCP_PORTS" --open $DNSSTRING -oA "tcp_detail" "$TARGET"
  else
    run_nmap "TCP detail (default scripts+version)" \
      nmap "${PNFLAG[@]}" -sC -sV -p "$TCP_PORTS" --open $DNSSTRING -oA "tcp_detail" "$TARGET"
  fi
else
  warn "No open TCP ports detected."
fi

if [[ -n "$UDP_PORTS" ]]; then
  # detail scan on discovered UDP ports
  if [[ "$EXTRA_SCRIPTS" == "yes" ]]; then
    run_nmap "UDP detail (default scripts+version)" \
      sudo nmap "${PNFLAG[@]}" -sU -sC -sV -p "$UDP_PORTS" --open $DNSSTRING -oA "udp_detail" "$TARGET"
  else
    run_nmap "UDP detail (version only)" \
      sudo nmap "${PNFLAG[@]}" -sU -sV -p "$UDP_PORTS" --open $DNSSTRING -oA "udp_detail" "$TARGET"
  fi
else
  warn "No open UDP ports detected in top ${UDP_TOP}."
fi

# ---------- Recon suggestions + Summary ----------
generate_recon "RECON.txt" "$TARGET" "${TCP_PORTS:-}" "${UDP_PORTS:-}"
write_summary "SUMMARY.md" "$TARGET" "${RESOLVED_IP:-}" "${TCP_PORTS:-}" "${UDP_PORTS:-}"

info "Done."
info "Open SUMMARY.md and RECON.txt"
