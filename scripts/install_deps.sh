#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd apt-get; then
  printf '[!] This installer currently supports Debian/Ubuntu (apt-get).\n' >&2
  printf '[!] Install dependencies manually on your distro.\n' >&2
  exit 1
fi

printf '[*] Installing OS packages...\n'
$SUDO apt-get update
$SUDO apt-get install -y \
  curl wget git jq python3 python3-pip ca-certificates unzip tar \
  golang-go ruby-full perl

if ! need_cmd go; then
  printf '[!] Go is required but not available after install.\n' >&2
  exit 1
fi

GOBIN_PATH="$(go env GOPATH)/bin"
mkdir -p "$GOBIN_PATH"

printf '[*] Installing Go-based tooling...\n'
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/PentestPad/subzy@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest
go install github.com/devanshbatham/OpenRedireX/cmd/openredirex@latest
go install github.com/ethicalhackingplayground/bxss@latest

printf '[*] Installing gf patterns...\n'
if [[ ! -d "${HOME}/.gf" ]]; then
  git clone https://github.com/1ndianl33t/Gf-Patterns.git "${HOME}/.gf"
fi

printf '[*] Installing Python dependencies...\n'
python3 -m pip install --user --upgrade pip
python3 -m pip install --user requests tldextract

printf '[*] Installing Nikto...\n'
if ! need_cmd nikto; then
  git clone https://github.com/sullo/nikto.git /tmp/nikto
  $SUDO ln -sf /tmp/nikto/program/nikto.pl /usr/local/bin/nikto
  $SUDO chmod +x /usr/local/bin/nikto
fi

printf '[*] Installing Trivy...\n'
if ! need_cmd trivy; then
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO apt-key add -
  echo 'deb https://aquasecurity.github.io/trivy-repo/deb generic main' | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null
  $SUDO apt-get update
  $SUDO apt-get install -y trivy
fi

printf '[*] Installing dirsearch...\n'
if ! need_cmd dirsearch; then
  git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch || true
  $SUDO ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
  $SUDO chmod +x /usr/local/bin/dirsearch
fi

printf '[*] Updating nuclei templates...\n'
"${GOBIN_PATH}/nuclei" -update-templates || true

printf '[*] Done. Add Go bin to PATH if missing:\n'
printf '    export PATH="$PATH:%s"\n' "$GOBIN_PATH"
