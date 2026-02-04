#!/usr/bin/env bash
# kameRadar — OSCP-friendly recon + web enum (streamed output)
# Authorized testing only.

set -Eeuo pipefail

# ---------- Colors ----------
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'
else
  RED=""; YELLOW=""; GREEN=""; NC=""
fi

die(){ echo "${RED}[!]${NC} $*" >&2; exit 1; }
info(){ echo "${GREEN}[+]${NC} $*"; }
warn(){ echo "${YELLOW}[-]${NC} $*"; }

need(){ command -v "$1" >/dev/null 2>&1 || die "Missing: $1"; }

# Line-buffer to show output in real time (better with tee)
run() {
  local label="$1"; shift
  info "$label"
  stdbuf -oL -eL "$@" 2>&1 | tee -a "$LOG"
  echo
}

is_ip(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

extract_ports_gnmap() {
  # Args: <file.gnmap> <tcp|udp>
  local file="$1" proto="$2"
  [[ -f "$file" ]] || { echo ""; return 0; }
  awk -F'Ports: ' '/Ports: /{print $2}' "$file" \
    | tr ',' '\n' \
    | awk -F'/' -v p="$proto" '$2=="open" && $3==p {print $1}' \
    | sort -n | paste -sd, -
}

has_port() {
  # Args: <csv> <port>
  local csv="$1" p="$2"
  [[ ",$csv," == *",$p,"* ]]
}

# ---------- Defaults ----------
HOST=""
OUTDIR="scans"
PROFILE="balanced"    # quick|balanced|beast
UDP_TOP=200
USE_PN=1              # default: -Pn
WEB=1                 # run web enum if HTTP found
DIR_ENUM=1
VHOST_ENUM=0          # off by default (needs domain)
DOMAIN=""             # optional domain for vhost fuzz when HOST is IP
DIR_WORDLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
VHOST_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
THREADS=50
EXTS="php,html,txt,js,zip,bak,old,conf,log"
TIMEOUT=10

usage(){
  cat <<EOF
kameRadar — OSCP-friendly recon + web enum (streamed output)

Usage:
  $0 -H <target> [-o outdir] [-p quick|balanced|beast] [--udp-top N] [--no-pn]
     [--no-web] [--no-dir] [--vhost] [--domain example.htb]
     [--dir-wordlist <path>] [--vhost-wordlist <path>] [--threads N] [--exts csv]

Examples:
  $0 -H 10.129.10.210
  $0 -H pandora.htb -p balanced
  $0 -H 10.10.10.10 --vhost --domain siteisup.htb
EOF
  exit 1
}

# ---------- Args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--host) HOST="${2:-}"; shift 2;;
    -o|--output) OUTDIR="${2:-}"; shift 2;;
    -p|--profile) PROFILE="${2:-}"; shift 2;;
    --udp-top) UDP_TOP="${2:-}"; shift 2;;
    --no-pn) USE_PN=0; shift;;
    --no-web) WEB=0; shift;;
    --no-dir) DIR_ENUM=0; shift;;
    --vhost) VHOST_ENUM=1; shift;;
    --domain) DOMAIN="${2:-}"; shift 2;;
    --dir-wordlist) DIR_WORDLIST="${2:-}"; shift 2;;
    --vhost-wordlist) VHOST_WORDLIST="${2:-}"; shift 2;;
    --threads) THREADS="${2:-}"; shift 2;;
    --exts) EXTS="${2:-}"; shift 2;;
    -h|--help) usage;;
    *) die "Unknown option: $1 (use -h)";;
  esac
done

[[ -n "$HOST" ]] || usage

case "$PROFILE" in
  quick|balanced|beast) ;;
  *) die "Profile must be quick|balanced|beast";;
esac

need nmap
need curl

# ---------- Workspace ----------
SAFE="${HOST//[^a-zA-Z0-9._-]/_}"
WORKDIR="${OUTDIR%/}/${SAFE}"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
LOG="kameRadar_${SAFE}.log"
: > "$LOG"

PN=()
[[ $USE_PN -eq 1 ]] && PN=(-Pn)

info "Target: $HOST"
info "Profile: $PROFILE"
info "Workdir: $WORKDIR"
echo

# ---------- 1) Quick TCP scan (shows something fast) ----------
# This is the “real-time feel”: you get ports quickly, then go deeper.
run "TCP quick scan (top ports)" \
  nmap "${PN[@]}" -sS --open -T4 --top-ports 1000 -oA tcp_quick "$HOST"

TCP_PORTS="$(extract_ports_gnmap tcp_quick.gnmap tcp || true)"
info "TCP open (quick): ${TCP_PORTS:-none}"
echo

# ---------- 2) Full TCP scan (balanced/beast) ----------
if [[ "$PROFILE" != "quick" ]]; then
  run "TCP full scan (all ports)" \
    nmap "${PN[@]}" -sS -p- --open --min-rate 3000 --max-retries 1 -oA tcp_all "$HOST"
  TCP_ALL_PORTS="$(extract_ports_gnmap tcp_all.gnmap tcp || true)"
  TCP_PORTS="${TCP_ALL_PORTS:-$TCP_PORTS}"
  info "TCP open (full): ${TCP_PORTS:-none}"
  echo
fi

# ---------- 3) UDP top ports (to catch SNMP/161, DNS/53, etc.) ----------
if sudo -n true 2>/dev/null; then
  run "UDP scan (top ${UDP_TOP})" \
    sudo nmap "${PN[@]}" -sU --top-ports "$UDP_TOP" --open -sV --version-light --max-retries 1 -oA udp_top "$HOST"
  UDP_PORTS="$(extract_ports_gnmap udp_top.gnmap udp || true)"
  info "UDP open: ${UDP_PORTS:-none}"
  echo
else
  warn "No passwordless sudo available — skipping UDP scan. Run manually with sudo if needed."
  UDP_PORTS=""
fi

# ---------- 4) Detail scan (only on discovered ports) ----------
if [[ -n "${TCP_PORTS:-}" ]]; then
  if [[ "$PROFILE" == "beast" ]]; then
    run "TCP detail (scripts+versions+OS guess)" \
      sudo nmap "${PN[@]}" -sC -sV --version-all -O --osscan-guess -p "$TCP_PORTS" --open -oA tcp_detail "$HOST"
  else
    run "TCP detail (default scripts+versions)" \
      nmap "${PN[@]}" -sC -sV -p "$TCP_PORTS" --open -oA tcp_detail "$HOST"
  fi
fi

if [[ -n "${UDP_PORTS:-}" ]] && sudo -n true 2>/dev/null; then
  run "UDP detail (default scripts+versions)" \
    sudo nmap "${PN[@]}" -sU -sC -sV -p "$UDP_PORTS" --open -oA udp_detail "$HOST"
fi

# ---------- 5) Web enum (dir bust + optional vhost fuzz) ----------
WEBPORT=""
PROTO="http"
CURL_OPTS=( -sS --max-time "$TIMEOUT" )

# detect common web ports
for p in 80 443 8080 8000 8443; do
  if [[ -n "${TCP_PORTS:-}" ]] && has_port "$TCP_PORTS" "$p"; then
    WEBPORT="$p"
    break
  fi
done

if [[ $WEB -eq 1 && -n "$WEBPORT" ]]; then
  mkdir -p web

  if [[ "$WEBPORT" == "443" || "$WEBPORT" == "8443" ]]; then
    PROTO="https"
    CURL_OPTS+=( -k )
  fi

  BASE_URL="${PROTO}://${HOST}:${WEBPORT}"
  info "Web detected: $BASE_URL"
  echo

  # Baseline size (for vhost filtering)
  BASELINE_SIZE="$(curl "${CURL_OPTS[@]}" "$BASE_URL/" | wc -c | tr -d ' ')"
  info "Baseline response size: $BASELINE_SIZE bytes"
  echo

  # Directory busting
  if [[ $DIR_ENUM -eq 1 ]]; then
    if command -v feroxbuster >/dev/null 2>&1; then
      run "Directory bust (feroxbuster)" \
        feroxbuster -u "$BASE_URL" -w "$DIR_WORDLIST" -x "$EXTS" -t "$THREADS" --quiet \
        -o "web/ferox_${SAFE}_${WEBPORT}.txt"
    elif command -v ffuf >/dev/null 2>&1; then
      run "Directory bust (ffuf)" \
        ffuf -w "$DIR_WORDLIST" -u "$BASE_URL/FUZZ" -t "$THREADS" \
        -e "$(echo "$EXTS" | sed 's/,/,./g;s/^/./')" -fc 404 \
        -o "web/ffuf_dir_${SAFE}_${WEBPORT}.json" -of json
    else
      warn "No feroxbuster/ffuf found. Install one to enable dir busting."
    fi
  fi

  # VHOST / “subdomain” fuzz (Host header fuzz)
  if [[ $VHOST_ENUM -eq 1 ]]; then
    command -v ffuf >/dev/null 2>&1 || warn "ffuf not found — vhost fuzz needs ffuf."
    if command -v ffuf >/dev/null 2>&1; then
      # Decide domain to fuzz
      # If HOST is a domain, use it; else require --domain
      if ! is_ip "$HOST"; then
        FUZZ_DOMAIN="$HOST"
      else
        [[ -n "$DOMAIN" ]] || die "--vhost requires a domain. Use: --domain siteisup.htb"
        FUZZ_DOMAIN="$DOMAIN"
      fi

      run "VHOST fuzz (ffuf Host header)" \
        ffuf -w "$VHOST_WORDLIST" -u "$BASE_URL/" \
        -H "Host: FUZZ.${FUZZ_DOMAIN}" -t "$THREADS" \
        -mc 200,204,301,302,307,401,403 -fs "$BASELINE_SIZE" \
        -o "web/ffuf_vhost_${SAFE}_${WEBPORT}.json" -of json
    fi
  fi
fi

info "Finished. Logs: $WORKDIR/$LOG"
info "Artifacts: tcp_*.{nmap,gnmap,xml} udp_*.{nmap,gnmap,xml} web/*"
