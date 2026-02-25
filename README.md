# th0rnRecon

**th0rnRecon** is a comprehensive Python-based web reconnaissance tool designed for CTF (Capture The Flag) web challenges. It automates the initial information-gathering phase by running multiple checks against a target URL and consolidating the results.

---

## Features

| Module | Description |
|---|---|
| Common File Check | Probes for well-known files such as `robots.txt`, `.env`, `.git/HEAD`, `phpinfo.php`, and more |
| Directory Discovery | Brute-forces paths using a custom wordlist with multi-threaded requests |
| HTTP Method Testing | Discovers which HTTP verbs (GET, POST, PUT, DELETE, TRACE, …) the server accepts |
| Backup File Detection | Looks for backup copies of static assets (`.bak`, `.old`, `.swp`, `~`, etc.) and common archives (`backup.zip`, `db.sql`, …) |
| API Endpoint Discovery | Checks common API paths (`/api`, `/api/v1`, `/swagger`, `/graphql`, …) |
| Site Map Builder | Parses the index page to list all scripts, stylesheets, images, links, iframes, and WebSocket URLs |
| Local Download & Flag Search | Mirrors the site with `wget` and scans all downloaded files for a user-supplied flag regex |
| Nmap Port Scan | Runs an nmap SYN/version scan against the target host to reveal open ports and services |
| JSON Output | Persists every finding to a structured JSON report |

---

## How It Works

1. **Initialisation** – The `WebReconTool` class is instantiated with the target URL and optional parameters (wordlist, flag format, thread count, timeout, output file).
2. **Banner** – A coloured banner is printed showing the target and active configuration.
3. **Target check** – A quick GET request verifies the host is reachable before any scanning begins.
4. **Parallel scanning** – Directory discovery and backup-file checks use a `ThreadPoolExecutor` so many requests are sent simultaneously, controlled by the `--threads` option.
5. **Result accumulation** – Every check stores its findings in an in-memory `results` dictionary.
6. **Summary & save** – After all modules finish (or on `Ctrl+C`), a human-readable summary is printed and the full results dictionary is optionally written to a JSON file.

---

## Requirements

- Python 3.7+
- `requests`
- `beautifulsoup4`
- `colorama`
- `nmap` (system package, required only for the port-scan module)
- `wget` (system package, required only for the local download module)

Install Python dependencies:

```bash
pip install requests beautifulsoup4 colorama
```

---

## Installation

```bash
git clone https://github.com/shubtheone/th0rnRecon.git
cd th0rnRecon
pip install requests beautifulsoup4 colorama
```

---

## Usage

```
python3 th0rnRecon.py <url> [options]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `url` | Target URL (required) | – |
| `-w`, `--wordlist` | Path to the wordlist for directory discovery | `common.txt` |
| `-f`, `--flag-format` | Flag regex pattern used when searching downloaded files (e.g. `"flag\{.*?\}"`) | None |
| `-t`, `--threads` | Number of concurrent threads | `10` |
| `-o`, `--output` | Path for the JSON results file | None |
| `--timeout` | HTTP request timeout in seconds | `5` |

### Examples

**Basic scan:**
```bash
python3 th0rnRecon.py http://target.ctf.local
```

**With a custom wordlist and 20 threads:**
```bash
python3 th0rnRecon.py http://target.ctf.local -w /usr/share/wordlists/dirb/big.txt -t 20
```

**Search for flags and save results:**
```bash
python3 th0rnRecon.py http://target.ctf.local -f "CTF\{.*?\}" -o results.json
```

**Full options:**
```bash
python3 th0rnRecon.py http://target.ctf.local \
    -w wordlist.txt \
    -f "flag\{.*?\}" \
    -t 15 \
    -o output.json \
    --timeout 10
```

---

## Output

Running the tool prints colour-coded progress to the terminal:

- **Cyan** – section headers
- **Green** – successful findings
- **Yellow** – informational messages / warnings
- **Red** – errors

When `-o` / `--output` is supplied, all findings are written to a JSON file with the following top-level keys:

```json
{
  "target": "...",
  "common_files": {},
  "directory_discovery": [],
  "http_methods": {},
  "backup_files": [],
  "api_endpoints": {},
  "site_map": {},
  "local_files": {},
  "nmap_results": ""
}
```

---

## Notes

- The nmap module uses a SYN scan (`-sS`) which requires **root / administrator privileges** on most systems.
- The local download module requires `wget` and `grep` to be available in `PATH`.
- Use responsibly and only against systems you have explicit permission to test.
