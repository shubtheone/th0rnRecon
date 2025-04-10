#!/usr/bin/env python3
"""
th0rnRecon - CTF Web Challenge Reconnaissance Tool
A comprehensive tool for initial web reconnaissance in CTF challenges
"""

import os
import sys
import requests
import subprocess
import re
import argparse
import concurrent.futures
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import json
from requests.exceptions import RequestException, ConnectionError, Timeout
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class WebReconTool:
    def __init__(self, url, wordlist="common.txt", flag_format=None, threads=10, output=None, timeout=5):
        self.url = url if url.endswith('/') else f"{url}/"
        self.base_url = urlparse(url).netloc
        self.scheme = urlparse(url).scheme
        self.wordlist = wordlist
        self.flag_format = flag_format
        self.threads = threads
        self.timeout = timeout
        self.output_file = output
        self.results = {
            "target": url,
            "common_files": {},
            "directory_discovery": [],
            "http_methods": {},
            "backup_files": [],
            "api_endpoints": {},
            "site_map": {},
            "local_files": {},
            "nmap_results": ""
        }

    def print_banner(self):
        banner = f"""
        {Fore.CYAN}╔════════════════════════════════════════════════╗
        ║   {Fore.GREEN}th0rnRecon - CTF Web Challenge Recon{Fore.CYAN}       ║
        ╚════════════════════════════════════════════════╝{Style.RESET_ALL}

        Target: {Fore.YELLOW}{self.url}{Style.RESET_ALL}
        Wordlist: {self.wordlist}
        Flag Format: {self.flag_format if self.flag_format else "Not specified"}

        {Fore.CYAN}Starting reconnaissance...{Style.RESET_ALL}
        """
        print(banner)

    def check_common_files(self):
        """Check for common files like robots.txt, sitemap.xml, .htaccess, .DS_Store"""
        print(f"\n{Fore.CYAN}[+] Checking for common files...{Style.RESET_ALL}")
        common_files = ["robots.txt", "sitemap.xml", ".htaccess", ".DS_Store",
                       ".git/HEAD", "security.txt", ".well-known/security.txt",
                       "favicon.ico", "crossdomain.xml", "phpinfo.php", "info.php",
                       ".env", "wp-login.php", "adminer.php", "admin.php", "console"]

        for file in common_files:
            try:
                url = f"{self.url}{file}"
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    print(f"  {Fore.GREEN}[✓] Found: {url} ({len(response.content)} bytes){Style.RESET_ALL}")
                    self.results["common_files"][file] = {
                        "status": response.status_code,
                        "size": len(response.content),
                        "url": url
                    }

                    # If it's robots.txt, extract paths
                    if file == "robots.txt":
                        paths = re.findall(r'Disallow: (.*)', response.text)
                        if paths:
                            print(f"    {Fore.YELLOW}[-] Disallowed paths in robots.txt:{Style.RESET_ALL}")
                            for path in paths:
                                print(f"      {Fore.YELLOW}- {path}{Style.RESET_ALL}")
                                # Add these paths to be scanned later
                                self.results["common_files"]["robots_paths"] = paths
            except RequestException:
                pass

    def directory_discovery(self):
        """Perform directory and file discovery using wordlist"""
        print(f"\n{Fore.CYAN}[+] Performing directory and file discovery...{Style.RESET_ALL}")

        if not os.path.exists(self.wordlist):
            print(f"  {Fore.RED}[!] Wordlist not found: {self.wordlist}{Style.RESET_ALL}")
            return

        with open(self.wordlist, 'r') as f:
            endpoints = [line.strip() for line in f.readlines()]

        total = len(endpoints)
        print(f"  {Fore.YELLOW}[-] Loaded {total} endpoints from wordlist{Style.RESET_ALL}")

        found_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.check_endpoint, endpoint): endpoint for endpoint in endpoints}

            for i, future in enumerate(concurrent.futures.as_completed(future_to_url), 1):
                endpoint = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        found_count += 1
                        self.results["directory_discovery"].append(result)

                    # Progress indicator every 100 requests
                    if i % 100 == 0 or i == total:
                        progress = (i / total) * 100
                        print(f"  {Fore.YELLOW}[-] Progress: {i}/{total} ({progress:.1f}%) - Found: {found_count}{Style.RESET_ALL}", end='\r')
                except Exception as e:
                    print(f"  {Fore.RED}[!] Error checking {endpoint}: {str(e)}{Style.RESET_ALL}")

        print(f"\n  {Fore.GREEN}[✓] Found {found_count} accessible endpoints{Style.RESET_ALL}")

    def check_endpoint(self, endpoint):
        """Check if an endpoint exists"""
        url = f"{self.url}{endpoint}"
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                content_type = response.headers.get('Content-Type', '')
                size = len(response.content)
                print(f"  {Fore.GREEN}[✓] {url} ({response.status_code}) - {size} bytes{Style.RESET_ALL}")
                return {
                    "url": url,
                    "status": response.status_code,
                    "size": size,
                    "content_type": content_type
                }
            return None
        except RequestException:
            return None

    def check_http_methods(self):
        """Check which HTTP methods are allowed"""
        print(f"\n{Fore.CYAN}[+] Checking allowed HTTP methods...{Style.RESET_ALL}")

        try:
            response = requests.options(self.url, timeout=self.timeout)
            allowed_methods = response.headers.get('Allow', '')

            if allowed_methods:
                methods = [m.strip() for m in allowed_methods.split(',')]
                print(f"  {Fore.GREEN}[✓] Allowed methods: {', '.join(methods)}{Style.RESET_ALL}")

                for method in methods:
                    method_response = requests.request(method, self.url, timeout=self.timeout)
                    if method not in ['GET', 'HEAD', 'POST', 'OPTIONS']:
                        print(f"  {Fore.YELLOW}[!] Potentially interesting method: {method}{Style.RESET_ALL}")

                self.results["http_methods"]["allowed"] = methods

                # Test non-standard methods if they're allowed
                interesting_methods = [m for m in methods if m not in ['GET', 'HEAD', 'POST', 'OPTIONS']]
                for method in interesting_methods:
                    try:
                        print(f"  {Fore.YELLOW}[-] {method} response: {method_response.status_code}{Style.RESET_ALL}")
                        self.results["http_methods"][method] = {
                            "status": method_response.status_code,
                            "size": len(method_response.content)
                        }
                    except RequestException:
                        pass
            else:
                print(f"  {Fore.YELLOW}[-] No Allow header found, testing common methods{Style.RESET_ALL}")
                for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']:
                    try:
                        method_response = requests.request(method, self.url, timeout=self.timeout)
                        if method_response.status_code != 405:  # Method not allowed
                            print(f"  {Fore.GREEN}[✓] {method} allowed ({method_response.status_code}){Style.RESET_ALL}")
                            self.results["http_methods"][method] = {
                                "status": method_response.status_code,
                                "size": len(method_response.content) if method != 'HEAD' else 0
                            }
                    except RequestException:
                        pass
        except RequestException as e:
            print(f"  {Fore.RED}[!] Error checking HTTP methods: {str(e)}{Style.RESET_ALL}")

    def check_backup_files(self):
        """Check for common backup files"""
        print(f"\n{Fore.CYAN}[+] Checking for backup files...{Style.RESET_ALL}")

        # Get index page content to look for files
        try:
            response = requests.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract JS, CSS and other files
            js_files = [script.get('src') for script in soup.find_all('script', src=True)]
            css_files = [link.get('href') for link in soup.find_all('link', rel='stylesheet')]
            images = [img.get('src') for img in soup.find_all('img', src=True)]

            files = js_files + css_files + images

            # Clean up file paths
            files = [f for f in files if f]
            files = [f.split('?')[0] for f in files]  # Remove query parameters

            # Add index.html, index.php etc.
            files.extend(['index.html', 'index.php', 'index.js', 'main.js', 'app.js', 'style.css'])

            # Deduplicate
            files = list(set(files))

            # Add backup extensions
            backup_extensions = ['.bak', '.backup', '.old', '.save', '.swp', '~', '.copy', '.orig', '.tmp', '.txt', '.back']

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_file = {}

                for file_path in files:
                     common_backups = ['backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'database.sql',
                     'site.zip', 'www.zip', 'web.config.bak', '.git/config', 'wp-config.php.bak']

                for backup in common_backups:
                    backup_url = f"{self.url}{backup}"
                    future_to_file[executor.submit(self.check_backup_file, backup_url, None)] = backup_url


                    # Skip URLs and empty paths
                    if not file_path or file_path.startswith(('http://', 'https://', '//')):
                        continue

                    file_name = os.path.basename(file_path)
                    file_path = file_path if file_path.startswith('/') else f"/{file_path}"

                    for ext in backup_extensions:
                        backup_url = f"{self.url}{file_path}{ext}"
                        original_url = f"{self.url}{file_path}"
                        future_to_file[executor.submit(self.check_backup_file, backup_url, original_url)] = backup_url

            # Also check common backup files in root

        except RequestException as e:
            print(f"  {Fore.RED}[!] Error fetching page to check for backup files: {str(e)}{Style.RESET_ALL}")

    def check_backup_file(self, backup_url, original_url=None):
        """Check if a backup file exists"""
        try:
            backup_response = requests.head(backup_url, timeout=self.timeout)
            if backup_response.status_code == 200:
                # If we have the original URL, compare content lengths
                if original_url:
                    try:
                        original_response = requests.head(original_url, timeout=self.timeout)
                        if original_response.status_code == 200:
                            if backup_response.headers.get('Content-Length') != original_response.headers.get('Content-Length'):
                                print(f"  {Fore.GREEN}[✓] Found backup: {backup_url}{Style.RESET_ALL}")
                                self.results["backup_files"].append({
                                    "url": backup_url,
                                    "size": backup_response.headers.get('Content-Length', 0)
                                })
                    except RequestException:
                        # If can't fetch original, just report backup
                        print(f"  {Fore.GREEN}[✓] Found possible backup: {backup_url}{Style.RESET_ALL}")
                        self.results["backup_files"].append({
                            "url": backup_url,
                            "size": backup_response.headers.get('Content-Length', 0)
                        })
                else:
                    # No original to compare with, just report backup
                    print(f"  {Fore.GREEN}[✓] Found possible backup: {backup_url}{Style.RESET_ALL}")
                    self.results["backup_files"].append({
                        "url": backup_url,
                        "size": backup_response.headers.get('Content-Length', 0)
                    })
        except RequestException:
            pass

    def check_api_endpoints(self):
        """Check for API endpoints and documentation"""
        print(f"\n{Fore.CYAN}[+] Checking API endpoints...{Style.RESET_ALL}")

        api_paths = [
            "api",
            "api/v1",
            "api/v2",
            "api-docs",
            "swagger",
            "swagger-ui",
            "swagger-ui.html",
            "swagger/index.html",
            "docs",
            "graphql",
            "graphiql",
            "v1",
            "v2"
        ]

        for path in api_paths:
            try:
                url = f"{self.url}{path}"
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    print(f"  {Fore.GREEN}[✓] Found API endpoint: {url} ({response.status_code}){Style.RESET_ALL}")

                    # Check if it's JSON
                    try:
                        if 'application/json' in response.headers.get('Content-Type', ''):
                            json_data = response.json()
                            self.results["api_endpoints"][path] = {
                                "url": url,
                                "status": response.status_code,
                                "content_type": response.headers.get('Content-Type', ''),
                                "is_json": True
                            }
                            print(f"  {Fore.YELLOW}[-] Endpoint returns JSON data{Style.RESET_ALL}")
                        else:
                            self.results["api_endpoints"][path] = {
                                "url": url,
                                "status": response.status_code,
                                "content_type": response.headers.get('Content-Type', ''),
                                "is_json": False
                            }
                    except ValueError:
                        self.results["api_endpoints"][path] = {
                            "url": url,
                            "status": response.status_code,
                            "content_type": response.headers.get('Content-Type', ''),
                            "is_json": False
                        }
            except RequestException:
                pass

    def create_site_map(self):
        """Create a tree map of scripts and files"""
        print(f"\n{Fore.CYAN}[+] Creating site map...{Style.RESET_ALL}")

        try:
            response = requests.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Get all scripts, stylesheets, images, links, iframes, websockets
            resources = {
                'scripts': [script.get('src') for script in soup.find_all('script', src=True)],
                'stylesheets': [link.get('href') for link in soup.find_all('link', rel='stylesheet')],
                'images': [img.get('src') for img in soup.find_all('img', src=True)],
                'links': [a.get('href') for a in soup.find_all('a', href=True)],
                'iframes': [iframe.get('src') for iframe in soup.find_all('iframe', src=True)],
            }

            # Check for websocket connections in JavaScript
            websocket_pattern = re.compile(r'(wss?:\/\/[^\s\'"]+)', re.IGNORECASE)
            script_tags = soup.find_all('script')
            websockets = []

            for script in script_tags:
                if script.string:  # Only if the script has content
                    matches = websocket_pattern.findall(script.string)
                    websockets.extend(matches)

            resources['websockets'] = websockets

            # Clean up and format resources
            for resource_type, urls in resources.items():
                # Remove None values and empty strings
                urls = [u for u in urls if u]

                # Convert relative URLs to absolute
                for i, url in enumerate(urls):
                    if url.startswith('//'):
                        urls[i] = f"{self.scheme}:{url}"
                    elif not url.startswith(('http://', 'https://', 'ws://', 'wss://')):
                        if url.startswith('/'):
                            urls[i] = f"{self.scheme}://{self.base_url}{url}"
                        else:
                            urls[i] = f"{self.url}{url}"

                resources[resource_type] = list(set(urls))  # Deduplicate

            # Store in results
            self.results["site_map"] = resources

            # Print summary
            for resource_type, urls in resources.items():
                if urls:
                    print(f"  {Fore.YELLOW}[-] {resource_type.capitalize()}: {len(urls)} found{Style.RESET_ALL}")
                    # Print first 5 as examples
                    for url in urls[:5]:
                        print(f"    - {url}")
                    if len(urls) > 5:
                        print(f"    - ... and {len(urls) - 5} more")

        except RequestException as e:
            print(f"  {Fore.RED}[!] Error creating site map: {str(e)}{Style.RESET_ALL}")

    def download_site(self):
        """Download the website locally and search for flags"""
        if not self.flag_format:
            print(f"\n{Fore.YELLOW}[!] Flag format not specified, skipping local download and search{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}[+] Downloading site locally and searching for flags...{Style.RESET_ALL}")

        # Create temp directory for site files
        download_dir = f"webrecon_{self.base_url.replace(':', '_')}"
        os.makedirs(download_dir, exist_ok=True)

        # Use wget to mirror the site
        try:
            print(f"  {Fore.YELLOW}[-] Downloading site to {download_dir}...{Style.RESET_ALL}")
            wget_cmd = [
                'wget',
                '--mirror',
                '--convert-links',
                '--adjust-extension',
                '--page-requisites',
                '--no-parent',
                '--directory-prefix=' + download_dir,
                '--no-verbose',
                '--timeout=5',
                '--tries=2',
                self.url
            ]

            wget_process = subprocess.Popen(
                wget_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = wget_process.communicate()

            if wget_process.returncode != 0:
                print(f"  {Fore.RED}[!] Error downloading site: {stderr.decode()}{Style.RESET_ALL}")
                return

            # Search for flags
            print(f"  {Fore.YELLOW}[-] Searching for flags with pattern: {self.flag_format}{Style.RESET_ALL}")

            grep_cmd = [
                'grep',
                '-r',
                '-n',  # Show line numbers
                '-o',  # Show only the matching part
                '-E',  # Extended regex
                self.flag_format,
                download_dir
            ]

            grep_process = subprocess.Popen(
                grep_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = grep_process.communicate()

            # Process and display results
            if stdout:
                stdout_text = stdout.decode()
                found_flags = stdout_text.strip().split('\n')
                print(f"  {Fore.GREEN}[✓] Found {len(found_flags)} potential flags!{Style.RESET_ALL}")

                for flag in found_flags:
                    print(f"    {Fore.GREEN}- {flag}{Style.RESET_ALL}")

                self.results["local_files"]["flags"] = found_flags
            else:
                print(f"  {Fore.YELLOW}[-] No flags found with the specified pattern{Style.RESET_ALL}")

            self.results["local_files"]["download_path"] = os.path.abspath(download_dir)

        except FileNotFoundError:
            print(f"  {Fore.RED}[!] wget or grep command not found. Please install them.{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}[!] Error in site download/search: {str(e)}{Style.RESET_ALL}")

    def run_nmap(self):
        """Run nmap on the target to check for open ports"""
        print(f"\n{Fore.CYAN}[+] Running nmap scan on {self.base_url}...{Style.RESET_ALL}")

        try:
            # Extract hostname/IP from URL
            parsed_url = urlparse(self.url)
            host = parsed_url.netloc.split(':')[0]  # Remove port if present

            # Run basic nmap scan
            nmap_cmd = [
                'nmap',
                '-sS',  # SYN scan
                '-sV',  # Version detection
                '--open',  # Only show open ports
                '-oG', '-',  # Greppable output to stdout
                host
            ]

            print(f"  {Fore.YELLOW}[-] Running: {' '.join(nmap_cmd)}{Style.RESET_ALL}")

            nmap_process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = nmap_process.communicate()

            if nmap_process.returncode != 0:
                print(f"  {Fore.RED}[!] Error running nmap: {stderr.decode()}{Style.RESET_ALL}")
                return

            # Process and display results
            nmap_output = stdout.decode()
            print(f"  {Fore.GREEN}[✓] Nmap scan completed{Style.RESET_ALL}")
            print(f"\n{nmap_output}\n")

            self.results["nmap_results"] = nmap_output

        except FileNotFoundError:
            print(f"  {Fore.RED}[!] nmap command not found. Please install nmap.{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}[!] Error running nmap: {str(e)}{Style.RESET_ALL}")

    def save_results(self):
        """Save results to a JSON file"""
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
                print(f"\n{Fore.GREEN}[✓] Results saved to {self.output_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")

    def summarize_results(self):
        """Print a summary of all findings"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════╗")
        print(f"║      {Fore.GREEN}WEB RECONNAISSANCE SUMMARY{Fore.CYAN}      ║")
        print(f"╚══════════════════════════════════════╝{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Target: {self.url}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[+] Common Files:{Style.RESET_ALL}")
        if self.results["common_files"]:
            for file, data in self.results["common_files"].items():
                if isinstance(data, dict):
                    print(f"  - {file}: {data['status']} ({data['size']} bytes)")
        else:
            print("  No common files found")

        print(f"\n{Fore.CYAN}[+] Directory Discovery:{Style.RESET_ALL}")
        if self.results["directory_discovery"]:
            print(f"  {len(self.results['directory_discovery'])} endpoints found")
            # Show top 5 by response size
            top_endpoints = sorted(
                self.results["directory_discovery"],
                key=lambda x: x.get('size', 0),
                reverse=True
            )[:5]
            for endpoint in top_endpoints:
                print(f"  - {endpoint['url']}: {endpoint['status']} ({endpoint['size']} bytes)")
        else:
            print("  No directories found")

        print(f"\n{Fore.CYAN}[+] HTTP Methods:{Style.RESET_ALL}")
        if self.results["http_methods"]:
            if "allowed" in self.results["http_methods"]:
                print(f"  - Allowed: {', '.join(self.results['http_methods']['allowed'])}")

            for method, data in self.results["http_methods"].items():
                if method != "allowed" and isinstance(data, dict):
                    print(f"  - {method}: {data['status']} ({data['size']} bytes)")
        else:
            print("  No HTTP methods information")

        print(f"\n{Fore.CYAN}[+] Backup Files:{Style.RESET_ALL}")
        if self.results["backup_files"]:
            for backup in self.results["backup_files"]:
                print(f"  - {backup['url']} ({backup['size']} bytes)")
        else:
            print("  No backup files found")

        print(f"\n{Fore.CYAN}[+] API Endpoints:{Style.RESET_ALL}")
        if self.results["api_endpoints"]:
            for path, data in self.results["api_endpoints"].items():
                print(f"  - {path}: {data['url']} ({data['content_type']})")
        else:
            print("  No API endpoints found")

        print(f"\n{Fore.CYAN}[+] Site Map Summary:{Style.RESET_ALL}")
        if self.results["site_map"]:
            for resource_type, urls in self.results["site_map"].items():
                if urls:
                    print(f"  - {resource_type.capitalize()}: {len(urls)} found")
        else:
            print("  No site map information")

        if self.flag_format:
            print(f"\n{Fore.CYAN}[+] Flag Search Results:{Style.RESET_ALL}")
            if "flags" in self.results.get("local_files", {}):
                for flag in self.results["local_files"]["flags"]:
                    print(f"  - {flag}")
            else:
                print("  No flags found")

        if self.results["nmap_results"]:
            print(f"\n{Fore.CYAN}[+] Nmap Scan:{Style.RESET_ALL}")
            print(f"  See above for details")

        print(f"\n{Fore.GREEN}[✓] Reconnaissance completed!{Style.RESET_ALL}")
        if self.output_file:
            print(f"{Fore.YELLOW}Full results saved to {self.output_file}{Style.RESET_ALL}")

    def run_all(self):
        """Run all reconnaissance steps"""
        self.print_banner()

        try:
            # Check if the target is accessible
            try:
                r = requests.get(self.url, timeout=self.timeout)
                print(f"  {Fore.GREEN}[✓] Target is accessible ({r.status_code}){Style.RESET_ALL}")
            except RequestException as e:
                print(f"  {Fore.RED}[!] Unable to access target: {str(e)}{Style.RESET_ALL}")
                return

            # Run all checks
            self.check_common_files()
            self.directory_discovery()
            self.check_http_methods()
            self.check_backup_files()
            self.check_api_endpoints()
            self.create_site_map()

            if self.flag_format:
                self.download_site()

            self.run_nmap()

            # Save and summarize results
            self.save_results()
            self.summarize_results()

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Reconnaissance interrupted by user{Style.RESET_ALL}")
            self.save_results()
            self.summarize_results()
        except Exception as e:
            print(f"\n{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")
            self.save_results()

def main():
    parser = argparse.ArgumentParser(description='th0rnRecon - CTF Web Challenge Reconnaissance Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-w', '--wordlist', default='common.txt', help='Wordlist for directory discovery (default: common.txt)')
    parser.add_argument('-f', '--flag-format', help='Flag format regex for searching (e.g., "flag{.*}")')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')

    args = parser.parse_args()

    # Create and run the tool
    tool = WebReconTool(
        url=args.url,
        wordlist=args.wordlist,
        flag_format=args.flag_format,
        threads=args.threads,
        output=args.output,
        timeout=args.timeout
    )

    tool.run_all()

if __name__ == '__main__':
    main()
