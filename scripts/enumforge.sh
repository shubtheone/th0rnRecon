#!/usr/bin/env bash
set -Eeuo pipefail

THREADS=30
KATANA_DEPTH=3
MAX_DIRSEARCH_TARGETS=5
MAX_TRIVY_TARGETS=20
MAX_NIKTO_TARGETS=20

RUN_NUCLEI=0
RUN_GF=0
RUN_SUBZY=0
RUN_CORSY=0
RUN_DIRSEARCH=0
RUN_TRIVY=0
RUN_NIKTO=0
RUN_FULL=0
USE_ARCHIVE=1

DOMAIN=""
OUTDIR=""
HTTPX_BIN="httpx"

NUCLEI_TEMPLATES="${HOME}/nuclei-templates"
OPENREDIREX_PAYLOAD="${HOME}/openredirex"
CORSY_SCRIPT="corsy.py"
CORSY_HEADERS=$'User-Agent: Mozilla/5.0\nCookie: SESSION=enumforge'
BXSS_PAYLOAD=""

DIRSEARCH_EXT="conf,config,bak,backup,swg,old,db,sql,asp,aspx,py,rb,php,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,lock,log,rar,swp,tar,tar.bz2,tar.gz,txt,wadl,zip,xml"

usage() {
  cat <<'EOF'
EnumForge - website enumeration pipeline

Usage:
  ./enumforge.sh -d example.com [options]

Required:
  -d, --domain DOMAIN         Target root domain

Options:
  -o, --out DIR               Output directory (default: recon-<domain>-<timestamp>)
  -t, --threads N             Threads/concurrency for tools (default: 30)
  --katana-depth N            Katana crawl depth (default: 3)
  --no-archive                Skip gau/waybackurls collection

  --nuclei                    Run nuclei scans (JS exposures + cve/osint/tech tags)
  --gf                        Run gf filters (lfi, redirect, xss)
  --subzy                     Run subdomain takeover checks
  --corsy                     Run CORS misconfiguration checks (requires corsy.py)
  --dirsearch                 Run dirsearch on live subdomains
  --trivy                     Run trivy web scan on live URLs
  --nikto                     Run nikto scan on live URLs
  --full                      Enable all optional scans

  --nuclei-templates DIR      Nuclei template directory (default: ~/nuclei-templates)
  --openredirex-payload PATH  OpenRedirex payload file/path (default: ~/openredirex)
  --corsy-script PATH         Path to corsy.py (default: ./corsy.py)
  --corsy-headers STRING      Extra headers for corsy.py (use $'A:1\nB:2')
  --bxss-payload STRING       Payload for bxss (enables bxss step under --gf)

  --max-dirsearch-targets N   Limit live hosts for dirsearch (default: 5)
  --max-trivy-targets N       Limit live URLs for trivy (default: 20)
  --max-nikto-targets N       Limit live URLs for nikto (default: 20)
  -h, --help                  Show this help

Examples:
  ./enumforge.sh -d example.com --full
  ./enumforge.sh -d example.com --nuclei --gf --subzy --trivy --nikto
EOF
}

log() {
  printf '[*] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "Missing dependency: $cmd"
    exit 1
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

resolve_httpx_bin() {
  local candidate=""
  local help_text=""

  if have_cmd httpx; then
    candidate="$(command -v httpx)"
    help_text="$($candidate -h 2>&1 || true)"
    if printf '%s' "$help_text" | grep -qi 'projectdiscovery\|httpx - fast and multi-purpose'; then
      HTTPX_BIN="$candidate"
      return 0
    fi
  fi

  if have_cmd go; then
    candidate="$(go env GOPATH)/bin/httpx"
    if [[ -x "$candidate" ]]; then
      HTTPX_BIN="$candidate"
      return 0
    fi
  fi

  if [[ -x "${HOME}/go/bin/httpx" ]]; then
    HTTPX_BIN="${HOME}/go/bin/httpx"
    return 0
  fi

  return 1
}

sanitize_domain() {
  local raw="$1"
  raw="${raw#http://}"
  raw="${raw#https://}"
  raw="${raw%%/*}"
  raw="${raw%%:*}"
  printf '%s' "${raw,,}"
}

normalize_subdomains() {
  awk -v root="$DOMAIN" '
    BEGIN { suffix = "." root }
    {
      gsub(/\r/, "", $0)
      gsub(/^\*\./, "", $0)
      line = tolower($0)
      if (line == "") next
      if (line == root) {
        print line
        next
      }
      if (length(line) > length(suffix) && substr(line, length(line) - length(suffix) + 1) == suffix) {
        print line
      }
    }
  ' | sort -u
}

line_count() {
  local file="$1"
  if [[ -s "$file" ]]; then
    wc -l < "$file" | tr -d ' '
  else
    printf '0'
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      DOMAIN="$2"
      shift 2
      ;;
    -o|--out)
      OUTDIR="$2"
      shift 2
      ;;
    -t|--threads)
      THREADS="$2"
      shift 2
      ;;
    --katana-depth)
      KATANA_DEPTH="$2"
      shift 2
      ;;
    --no-archive)
      USE_ARCHIVE=0
      shift
      ;;
    --nuclei)
      RUN_NUCLEI=1
      shift
      ;;
    --gf)
      RUN_GF=1
      shift
      ;;
    --subzy)
      RUN_SUBZY=1
      shift
      ;;
    --corsy)
      RUN_CORSY=1
      shift
      ;;
    --dirsearch)
      RUN_DIRSEARCH=1
      shift
      ;;
    --trivy)
      RUN_TRIVY=1
      shift
      ;;
    --nikto)
      RUN_NIKTO=1
      shift
      ;;
    --full)
      RUN_FULL=1
      shift
      ;;
    --nuclei-templates)
      NUCLEI_TEMPLATES="$2"
      shift 2
      ;;
    --openredirex-payload)
      OPENREDIREX_PAYLOAD="$2"
      shift 2
      ;;
    --corsy-script)
      CORSY_SCRIPT="$2"
      shift 2
      ;;
    --corsy-headers)
      CORSY_HEADERS="$2"
      shift 2
      ;;
    --bxss-payload)
      BXSS_PAYLOAD="$2"
      RUN_GF=1
      shift 2
      ;;
    --max-dirsearch-targets)
      MAX_DIRSEARCH_TARGETS="$2"
      shift 2
      ;;
    --max-trivy-targets)
      MAX_TRIVY_TARGETS="$2"
      shift 2
      ;;
    --max-nikto-targets)
      MAX_NIKTO_TARGETS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      warn "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  usage
  exit 1
fi

DOMAIN="$(sanitize_domain "$DOMAIN")"
if [[ -z "$DOMAIN" ]]; then
  warn "Invalid domain"
  exit 1
fi

if [[ "$RUN_FULL" -eq 1 ]]; then
  RUN_NUCLEI=1
  RUN_GF=1
  RUN_SUBZY=1
  RUN_CORSY=1
  RUN_DIRSEARCH=1
  RUN_TRIVY=1
  RUN_NIKTO=1
fi

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="recon-${DOMAIN}-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$OUTDIR"/subdomains "$OUTDIR"/urls "$OUTDIR"/scans "$OUTDIR"/logs

CRT_RAW="$OUTDIR/logs/crtsh_raw.json"
CRT_SUBS="$OUTDIR/subdomains/crtsh.txt"
SUBFINDER_SUBS="$OUTDIR/subdomains/subfinder.txt"
ALL_SUBS="$OUTDIR/subdomains/all.txt"
ALIVE_URLS="$OUTDIR/subdomains/alive_urls.txt"
ALIVE_HOSTS="$OUTDIR/subdomains/alive_hosts.txt"

KATANA_URLS="$OUTDIR/urls/katana.txt"
QURLS="$OUTDIR/urls/qurls.txt"
ARCHIVE_URLS="$OUTDIR/urls/archive.txt"
ALL_URLS="$OUTDIR/urls/allurls.txt"
LIVE_URLS="$OUTDIR/urls/live_urls.txt"
SENSITIVE_URLS="$OUTDIR/urls/sensitive_urls.txt"
JS_URLS="$OUTDIR/urls/js.txt"

SCANS_DIR="$OUTDIR/scans"
REPORT_FILE="$OUTDIR/report.txt"

for cmd in curl python3 subfinder katana awk sed grep sort; do
  require_cmd "$cmd"
done

if ! resolve_httpx_bin; then
  warn "Could not find ProjectDiscovery httpx binary"
  warn "Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  exit 1
fi

log "Domain: $DOMAIN"
log "Output: $OUTDIR"

: > "$CRT_SUBS"
: > "$SUBFINDER_SUBS"
: > "$ALIVE_URLS"
: > "$ALIVE_HOSTS"
: > "$KATANA_URLS"
: > "$QURLS"
: > "$ARCHIVE_URLS"
: > "$ALL_URLS"
: > "$LIVE_URLS"
: > "$SENSITIVE_URLS"
: > "$JS_URLS"

log "Step 1/7: Collecting subdomains (crt.sh + subfinder)"
(
  if curl -fsSL "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$CRT_RAW"; then
    python3 - "$DOMAIN" "$CRT_RAW" > "$CRT_SUBS" <<'PY'
import json
import sys

domain = sys.argv[1].lower()
path = sys.argv[2]

try:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()
except OSError:
    sys.exit(0)

if not raw:
    sys.exit(0)

def parse_payload(payload):
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        fixed = payload.replace("}\n{", "},{").replace("}{", "},{")
        return json.loads(f"[{fixed}]")

try:
    data = parse_payload(raw)
except Exception:
    sys.exit(0)

seen = set()
suffix = "." + domain

for row in data:
    names = str(row.get("name_value", ""))
    for name in names.splitlines():
        n = name.strip().lower().lstrip("*.")
        if not n:
            continue
        if n == domain or n.endswith(suffix):
            if n not in seen:
                seen.add(n)
                print(n)
PY
  else
    warn "crt.sh query failed"
  fi
) &
pid_crt=$!

(
  subfinder -silent -d "$DOMAIN" -o "$SUBFINDER_SUBS" || true
) &
pid_subfinder=$!

wait "$pid_crt"
wait "$pid_subfinder"

cat "$CRT_SUBS" "$SUBFINDER_SUBS" | normalize_subdomains > "$ALL_SUBS"

if [[ ! -s "$ALL_SUBS" ]]; then
  warn "No subdomains found. Exiting."
  exit 1
fi

log "Step 2/7: Probing live subdomains with httpx"
"$HTTPX_BIN" -silent -l "$ALL_SUBS" -threads "$THREADS" -o "$ALIVE_URLS" || true

awk -F/ 'NF >= 3 { print $3 }' "$ALIVE_URLS" | awk -F: '{ print tolower($1) }' | sort -u > "$ALIVE_HOSTS"

if [[ ! -s "$ALIVE_URLS" ]]; then
  warn "No live subdomains detected."
fi

log "Step 3/7: Crawling live targets with katana"
if [[ -s "$ALIVE_URLS" ]]; then
  katana -silent -list "$ALIVE_URLS" -d "$KATANA_DEPTH" -o "$KATANA_URLS" || true
  katana -silent -list "$ALIVE_URLS" -ps -f qurl -d "$KATANA_DEPTH" -o "$QURLS" || true
fi

log "Step 4/7: Optional archive URL collection"
if [[ "$USE_ARCHIVE" -eq 1 ]]; then
  if have_cmd gau; then
    gau "$DOMAIN" >> "$ARCHIVE_URLS" || true
  else
    warn "gau not found, skipping"
  fi

  if have_cmd waybackurls && [[ -s "$ALIVE_HOSTS" ]]; then
    waybackurls < "$ALIVE_HOSTS" >> "$ARCHIVE_URLS" || true
  elif ! have_cmd waybackurls; then
    warn "waybackurls not found, skipping"
  fi
fi

log "Step 5/7: Building URL lists and filtering"
cat "$KATANA_URLS" "$ARCHIVE_URLS" | awk '/^https?:\/\// { print }' | sed 's/#.*$//' | sort -u > "$ALL_URLS"

if [[ -s "$ALL_URLS" ]]; then
  "$HTTPX_BIN" -silent -l "$ALL_URLS" -threads "$THREADS" -o "$LIVE_URLS" || true
fi

awk 'tolower($0) ~ /\.(txt|log|cache|secret|db|backup|yml|yaml|json|gz|rar|zip|config)(\?|$)/ { print }' "$ALL_URLS" | sort -u > "$SENSITIVE_URLS"
awk 'tolower($0) ~ /\.js(\?|$)/ { print }' "$ALL_URLS" | sort -u > "$JS_URLS"

log "Step 6/7: Running optional scans"
if [[ "$RUN_NUCLEI" -eq 1 ]]; then
  if have_cmd nuclei; then
    EXPOSURES_TPL="${NUCLEI_TEMPLATES}/http/exposures/"

    if [[ -s "$JS_URLS" ]]; then
      if [[ -d "$EXPOSURES_TPL" ]]; then
        nuclei -silent -l "$JS_URLS" -t "$EXPOSURES_TPL" -c "$THREADS" -o "$SCANS_DIR/nuclei_js_exposures.txt" || true
      else
        warn "Nuclei exposure templates not found at $EXPOSURES_TPL"
      fi
    fi

    if [[ -s "$ALIVE_URLS" ]]; then
      nuclei -silent -l "$ALIVE_URLS" -tags cve,osint,tech -c "$THREADS" -o "$SCANS_DIR/nuclei_cve_osint_tech.txt" || true
    fi
  else
    warn "nuclei not found, skipping nuclei scans"
  fi
fi

if [[ "$RUN_GF" -eq 1 ]]; then
  if have_cmd gf; then
    gf lfi < "$ALL_URLS" | sort -u > "$SCANS_DIR/gf_lfi.txt" || true
    gf redirect < "$ALL_URLS" | sort -u > "$SCANS_DIR/gf_redirect.txt" || true

    if [[ -s "$QURLS" ]]; then
      gf xss < "$QURLS" | sort -u > "$SCANS_DIR/gf_xss.txt" || true
    else
      gf xss < "$ALL_URLS" | sort -u > "$SCANS_DIR/gf_xss.txt" || true
    fi

    if have_cmd nuclei && [[ -s "$SCANS_DIR/gf_lfi.txt" ]]; then
      nuclei -silent -l "$SCANS_DIR/gf_lfi.txt" -tags lfi -c "$THREADS" -o "$SCANS_DIR/nuclei_lfi.txt" || true
    fi

    if have_cmd openredirex && [[ -s "$SCANS_DIR/gf_redirect.txt" ]]; then
      if [[ -e "$OPENREDIREX_PAYLOAD" ]]; then
        openredirex -p "$OPENREDIREX_PAYLOAD" < "$SCANS_DIR/gf_redirect.txt" > "$SCANS_DIR/openredirex.txt" || true
      else
        warn "OpenRedirex payload path not found: $OPENREDIREX_PAYLOAD"
      fi
    fi

    if [[ -n "$BXSS_PAYLOAD" ]]; then
      if have_cmd bxss && [[ -s "$SCANS_DIR/gf_xss.txt" ]]; then
        bxss -appendMode -payload "$BXSS_PAYLOAD" -parameters < "$SCANS_DIR/gf_xss.txt" > "$SCANS_DIR/bxss.txt" || true
      else
        warn "bxss not found or no xss parameter candidates"
      fi
    fi
  else
    warn "gf not found, skipping gf scans"
  fi
fi

if [[ "$RUN_SUBZY" -eq 1 ]]; then
  if have_cmd subzy; then
    subzy run --targets "$ALL_SUBS" --concurrency "$THREADS" --hide_fails --verify_ssl > "$SCANS_DIR/subzy.txt" || true
  else
    warn "subzy not found, skipping takeover checks"
  fi
fi

if [[ "$RUN_CORSY" -eq 1 ]]; then
  if [[ -f "$CORSY_SCRIPT" ]]; then
    python3 "$CORSY_SCRIPT" -I "$ALIVE_HOSTS" -t "$THREADS" --headers "$CORSY_HEADERS" > "$SCANS_DIR/corsy.txt" || true
  else
    warn "corsy script not found: $CORSY_SCRIPT"
  fi
fi

if [[ "$RUN_DIRSEARCH" -eq 1 ]]; then
  if have_cmd dirsearch; then
    count=0
    while IFS= read -r target; do
      if [[ -z "$target" ]]; then
        continue
      fi

      count=$((count + 1))
      if (( count > MAX_DIRSEARCH_TARGETS )); then
        break
      fi

      safe_name="$(printf '%s' "$target" | sed 's#^https\?://##; s#[^A-Za-z0-9._-]#_#g')"
      dirsearch -u "$target" -e "$DIRSEARCH_EXT" --plain-text-report "$SCANS_DIR/dirsearch_${safe_name}.txt" > "$OUTDIR/logs/dirsearch_${safe_name}.log" 2>&1 || true
    done < "$ALIVE_URLS"
  else
    warn "dirsearch not found, skipping dirsearch"
  fi
fi

if [[ "$RUN_TRIVY" -eq 1 ]]; then
  if have_cmd trivy; then
    count=0
    while IFS= read -r target; do
      if [[ -z "$target" ]]; then
        continue
      fi

      count=$((count + 1))
      if (( count > MAX_TRIVY_TARGETS )); then
        break
      fi

      safe_name="$(printf '%s' "$target" | sed 's#^https\?://##; s#[^A-Za-z0-9._-]#_#g')"
      trivy web --quiet --timeout 5m --format json -o "$SCANS_DIR/trivy_${safe_name}.json" "$target" > "$OUTDIR/logs/trivy_${safe_name}.log" 2>&1 || true
    done < "$LIVE_URLS"
  else
    warn "trivy not found, skipping trivy"
  fi
fi

if [[ "$RUN_NIKTO" -eq 1 ]]; then
  if have_cmd nikto; then
    count=0
    while IFS= read -r target; do
      if [[ -z "$target" ]]; then
        continue
      fi

      count=$((count + 1))
      if (( count > MAX_NIKTO_TARGETS )); then
        break
      fi

      safe_name="$(printf '%s' "$target" | sed 's#^https\?://##; s#[^A-Za-z0-9._-]#_#g')"
      nikto -h "$target" -Format txt -output "$SCANS_DIR/nikto_${safe_name}.txt" > "$OUTDIR/logs/nikto_${safe_name}.log" 2>&1 || true
    done < "$LIVE_URLS"
  else
    warn "nikto not found, skipping nikto"
  fi
fi

log "Step 7/7: Writing report"
cat > "$REPORT_FILE" <<EOF
Domain: $DOMAIN
Output directory: $OUTDIR
Generated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Subdomains discovered: $(line_count "$ALL_SUBS")
Live subdomains: $(line_count "$ALIVE_URLS")

URLs collected: $(line_count "$ALL_URLS")
Live URLs: $(line_count "$LIVE_URLS")
JavaScript URLs: $(line_count "$JS_URLS")
Sensitive-extension URLs: $(line_count "$SENSITIVE_URLS")

Primary files:
- $ALL_SUBS
- $ALIVE_URLS
- $ALL_URLS
- $LIVE_URLS
- $SENSITIVE_URLS
- $JS_URLS
EOF

log "Done. Report: $REPORT_FILE"
log "Key outputs:"
printf '    %s\n' "$ALL_SUBS" "$ALIVE_URLS" "$ALL_URLS" "$LIVE_URLS" "$SENSITIVE_URLS" "$JS_URLS"
