#!/usr/bin/env python3
"""
Simple-Finder - Advanced Subdomain Discovery Tool
Created by: cyber_specterz
"""

import os
import sys
import json
import time
import asyncio
import argparse
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse

# Third-party imports
try:
    import dns.resolver
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    from pyfiglet import Figlet
    from termcolor import colored
    from tqdm import tqdm
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    import aiohttp
    import asyncio
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install requirements: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Import config
from config import Config

console = Console()

class Banner:
    """Display fancy banners"""
    
    @staticmethod
    def show_main_banner():
        """Display main tool banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        f = Figlet(font='slant')
        banner_text = f.renderText('SIMPLE-FINDER')
        
        # Create colored banner
        lines = banner_text.split('\n')
        colored_banner = ""
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        
        for i, line in enumerate(lines):
            color = colors[i % len(colors)]
            colored_banner += color + line + "\n"
        
        # Tool info
        info = f"""
        {Fore.WHITE}╔══════════════════════════════════════════════════════════╗
        {Fore.WHITE}║ {Fore.CYAN}Advanced Subdomain Discovery & Reconnaissance Tool     {Fore.WHITE}  ║
        {Fore.WHITE}║ {Fore.YELLOW}Created by: cyber_specterz                              {Fore.WHITE} ║
        {Fore.WHITE}║ {Fore.GREEN}Version: 2.0.0 | Multi-Platform                         {Fore.WHITE} ║
        {Fore.WHITE}╚══════════════════════════════════════════════════════════╝
        """
        
        print(colored_banner)
        print(info)
    
    @staticmethod
    def show_method_banner(method: str):
        """Display banner for specific method"""
        console.print(Panel.fit(
            f"[bold cyan]{method.upper()} SCAN[/bold cyan]",
            border_style="yellow"
        ))

class SubdomainFinder:
    """Main subdomain finder class with multiple discovery methods"""
    
    def __init__(self, domain: str, output_dir: str = "results"):
        self.domain = domain.strip().lower()
        self.output_dir = output_dir
        self.found_subdomains: Set[str] = set()
        self.resolvable_subdomains: Set[str] = set()
        self.discovery_stats: Dict[str, int] = {}
        
        # Create output directory
        Path(output_dir).mkdir(exist_ok=True)
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = Config.REQUEST_TIMEOUT
        self.resolver.lifetime = Config.REQUEST_TIMEOUT
        
        # Status tracking
        self.scan_start_time = None
        self.total_discovered = 0
        
    async def check_dns_resolution(self, subdomain: str) -> bool:
        """Check if subdomain resolves to an IP"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: self.resolver.resolve(full_domain, 'A')
            )
            if answers:
                self.resolvable_subdomains.add(full_domain)
                return True
        except Exception:
            pass
        return False
    
    def passive_discovery(self) -> Set[str]:
        """Passive discovery using search engines and APIs"""
        Banner.show_method_banner("Passive Discovery")
        discovered = set()
        
        methods = [
            self._crt_sh_search,
            self._hackertarget_query,
            self._threatcrowd_search,
            self._alienvault_otx,
            self._bufferover_run,
            self._urlscan_io,
            self._dnsdumpster,
            self._rapiddns_search,
            self._securitytrails_api,
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Running passive discovery...", total=len(methods))
            
            for method in methods:
                try:
                    result = method()
                    if result:
                        discovered.update(result)
                        progress.update(task, advance=1, 
                                      description=f"[cyan]Found {len(discovered)} subdomains...")
                except Exception as e:
                    console.print(f"[yellow]Warning in {method.__name__}: {str(e)}")
                    continue
        
        self.discovery_stats['passive'] = len(discovered)
        return discovered
    
    def _crt_sh_search(self) -> Set[str]:
        """Search crt.sh certificate database"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and self.domain in subdomain:
                            subdomains.add(subdomain)
        except Exception:
            pass
        return subdomains
    
    def _hackertarget_query(self) -> Set[str]:
        """Query Hackertarget API"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain:
                            subdomains.add(subdomain)
        except Exception:
            pass
        return subdomains
    
    def _threatcrowd_search(self) -> Set[str]:
        """Search ThreatCrowd API"""
        subdomains = set()
        try:
            url = f"https://threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for sub in data['subdomains']:
                        subdomains.add(sub.strip().lower())
        except Exception:
            pass
        return subdomains
    
    def _alienvault_otx(self) -> Set[str]:
        """Query AlienVault OTX"""
        subdomains = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if 'passive_dns' in data:
                    for entry in data['passive_dns']:
                        hostname = entry.get('hostname', '').strip().lower()
                        if hostname:
                            subdomains.add(hostname)
        except Exception:
            pass
        return subdomains
    
    def _bufferover_run(self) -> Set[str]:
        """Query BufferOver.run DNS API"""
        subdomains = set()
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if 'FDNS_A' in data:
                    for entry in data['FDNS_A']:
                        parts = entry.split(',')
                        if len(parts) > 1:
                            subdomain = parts[1].strip().lower()
                            if subdomain:
                                subdomains.add(subdomain)
        except Exception:
            pass
        return subdomains
    
    def _urlscan_io(self) -> Set[str]:
        """Query urlscan.io"""
        subdomains = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if 'results' in data:
                    for result in data['results']:
                        domain = result.get('task', {}).get('domain', '')
                        if domain:
                            subdomains.add(domain.strip().lower())
        except Exception:
            pass
        return subdomains
    
    def _dnsdumpster(self) -> Set[str]:
        """Query DNSDumpster"""
        subdomains = set()
        try:
            # First get the CSRF token
            response = self.session.get('https://dnsdumpster.com/', 
                                       timeout=Config.REQUEST_TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']
            
            # Make the search request
            headers = {
                'Referer': 'https://dnsdumpster.com/',
                'Cookie': f'csrftoken={csrf_token}'
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain
            }
            
            response = self.session.post('https://dnsdumpster.com/', 
                                        data=data, headers=headers,
                                        timeout=Config.REQUEST_TIMEOUT)
            
            # Parse results (simplified)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if self.domain in href and 'http' in href:
                    parsed = urlparse(href)
                    if parsed.netloc:
                        subdomains.add(parsed.netloc.strip().lower())
                        
        except Exception:
            pass
        return subdomains
    
    def _rapiddns_search(self) -> Set[str]:
        """Search RapidDNS"""
        subdomains = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                table = soup.find('table')
                if table:
                    for row in table.find_all('tr')[1:]:
                        cols = row.find_all('td')
                        if len(cols) > 0:
                            domain = cols[0].text.strip().lower()
                            if domain:
                                subdomains.add(domain)
        except Exception:
            pass
        return subdomains
    
    def _securitytrails_api(self) -> Set[str]:
        """Query SecurityTrails API (requires API key)"""
        subdomains = set()
        if Config.SECURITYTRAILS_API_KEY == "YOUR_SECURITYTRAILS_API_KEY":
            return subdomains
        
        try:
            headers = {
                'APIKEY': Config.SECURITYTRAILS_API_KEY,
                'Content-Type': 'application/json'
            }
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            response = self.session.get(url, headers=headers, 
                                       timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for sub in data['subdomains']:
                        full_domain = f"{sub}.{self.domain}"
                        subdomains.add(full_domain)
        except Exception:
            pass
        return subdomains
    
    async def dns_bruteforce(self, wordlist_path: str = None) -> Set[str]:
        """Brute force DNS subdomains"""
        Banner.show_method_banner("DNS Bruteforce")
        
        if wordlist_path is None:
            wordlist_path = Config.DEFAULT_WORDLIST
        
        discovered = set()
        tasks = []
        
        # Load wordlist
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found: {wordlist_path}[/red]")
            return discovered
        
        console.print(f"[cyan]Loaded {len(words)} words from wordlist[/cyan]")
        
        # Create async tasks
        semaphore = asyncio.Semaphore(Config.CONCURRENT_REQUESTS)
        
        async def check_subdomain(word: str, semaphore):
            async with semaphore:
                if await self.check_dns_resolution(word):
                    return f"{word}.{self.domain}"
            return None
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Bruteforcing DNS...", total=len(words))
            
            for word in words:
                tasks.append(check_subdomain(word, semaphore))
            
            # Process results
            for future in asyncio.as_completed(tasks):
                result = await future
                if result:
                    discovered.add(result)
                    progress.update(task, advance=1, 
                                  description=f"[cyan]Found {len(discovered)} subdomains...")
                else:
                    progress.update(task, advance=1)
        
        self.discovery_stats['bruteforce'] = len(discovered)
        return discovered
    
    def web_archive_discovery(self) -> Set[str]:
        """Discover subdomains from Wayback Machine"""
        Banner.show_method_banner("Web Archive Discovery")
        subdomains = set()
        
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    url = entry[0]
                    parsed = urlparse(url)
                    if parsed.netloc:
                        subdomains.add(parsed.netloc.strip().lower())
        except Exception:
            pass
        
        self.discovery_stats['web_archive'] = len(subdomains)
        return subdomains
    
    def dns_zone_transfer(self) -> Set[str]:
        """Attempt DNS zone transfer"""
        Banner.show_method_banner("DNS Zone Transfer")
        subdomains = set()
        
        # Common DNS servers to try
        dns_servers = [
            'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2',
            'ns', 'dns', 'ns01', 'ns02', 'ns03', 'ns04'
        ]
        
        for ns in dns_servers:
            try:
                ns_server = f"{ns}.{self.domain}"
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [str(dns.resolver.resolve(ns_server, 'A')[0])]
                
                answers = resolver.query(self.domain, 'AXFR')
                for answer in answers:
                    if answer.to_text().endswith(self.domain):
                        subdomains.add(answer.to_text().rstrip('.'))
            except Exception:
                continue
        
        self.discovery_stats['zone_transfer'] = len(subdomains)
        return subdomains
    
    def google_search_discovery(self) -> Set[str]:
        """Search Google for subdomains (simulated)"""
        Banner.show_method_banner("Search Engine Discovery")
        subdomains = set()
        
        # This is a simplified version. In practice, you'd need to handle
        # Google's anti-bot measures and use proper API if available
        
        search_queries = [
            f"site:*.{self.domain}",
            f"inurl:*.{self.domain}",
            f"*.{self.domain}"
        ]
        
        # Note: Actual Google scraping requires proper handling of rate limiting
        # and legal considerations. Consider using official API.
        
        self.discovery_stats['search_engine'] = len(subdomains)
        return subdomains
    
    async def certificate_transparency(self) -> Set[str]:
        """Check Certificate Transparency logs"""
        Banner.show_method_banner("Certificate Transparency")
        subdomains = set()
        
        # Additional CT log sources
        ct_sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://ct.googleapis.com/logs/argon2022/ct/v1/get-entries",
            f"https://ct.cloudflare.com/logs/nimbus2022/ct/v1/get-entries"
        ]
        
        for source in ct_sources:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(source, timeout=Config.REQUEST_TIMEOUT) as response:
                        if response.status == 200:
                            data = await response.json()
                            # Parse certificates and extract domains
                            # Implementation depends on the specific CT log format
                            pass
            except Exception:
                continue
        
        self.discovery_stats['cert_transparency'] = len(subdomains)
        return subdomains
    
    def permute_subdomains(self, discovered: Set[str]) -> Set[str]:
        """Generate permutations of discovered subdomains"""
        Banner.show_method_banner("Subdomain Permutation")
        permutations = set()
        
        common_prefixes = ['dev', 'staging', 'test', 'prod', 'api', 'admin',
                          'secure', 'portal', 'mail', 'webmail', 'blog', 'forum']
        common_suffixes = ['-dev', '-test', '-staging', '-prod', '-old', '-new',
                          '-backup', '-temp', '-api', '-admin']
        
        for subdomain in discovered:
            # Remove domain part
            base = subdomain.replace(f".{self.domain}", "")
            
            # Add prefixes
            for prefix in common_prefixes:
                permutations.add(f"{prefix}.{base}.{self.domain}")
                permutations.add(f"{prefix}{base}.{self.domain}")
            
            # Add suffixes
            for suffix in common_suffixes:
                permutations.add(f"{base}{suffix}.{self.domain}")
        
        # Check which permutations resolve
        resolvable = set()
        for perm in permutations:
            if self.check_dns_resolution_sync(perm.replace(f".{self.domain}", "")):
                resolvable.add(perm)
        
        self.discovery_stats['permutations'] = len(resolvable)
        return resolvable
    
    def check_dns_resolution_sync(self, subdomain: str) -> bool:
        """Synchronous DNS resolution check"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = self.resolver.resolve(full_domain, 'A')
            return bool(answers)
        except Exception:
            return False
    
    def reverse_ip_lookup(self) -> Set[str]:
        """Perform reverse IP lookup"""
        Banner.show_method_banner("Reverse IP Lookup")
        subdomains = set()
        
        try:
            # Get IP addresses of main domain
            answers = self.resolver.resolve(self.domain, 'A')
            ips = [str(answer) for answer in answers]
            
            # Check each IP
            for ip in ips:
                # YouView reverse IP lookup
                url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
                response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    table = soup.find('table', {'border': '1'})
                    if table:
                        for row in table.find_all('tr')[1:]:
                            cols = row.find_all('td')
                            if len(cols) > 0:
                                domain = cols[0].text.strip().lower()
                                if self.domain in domain:
                                    subdomains.add(domain)
        except Exception:
            pass
        
        self.discovery_stats['reverse_ip'] = len(subdomains)
        return subdomains
    
    def validate_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """Validate subdomains by checking HTTP/HTTPS response"""
        validated = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Validating subdomains...", total=len(subdomains))
            
            for subdomain in subdomains:
                try:
                    # Try HTTP
                    response = self.session.get(f"http://{subdomain}", 
                                              timeout=Config.REQUEST_TIMEOUT,
                                              allow_redirects=True)
                    if response.status_code < 500:
                        validated.add(subdomain)
                    else:
                        # Try HTTPS
                        response = self.session.get(f"https://{subdomain}", 
                                                  timeout=Config.REQUEST_TIMEOUT,
                                                  allow_redirects=True)
                        if response.status_code < 500:
                            validated.add(subdomain)
                except Exception:
                    pass
                
                progress.update(task, advance=1)
        
        return validated
    
    def save_results(self, filename: str = None):
        """Save discovered subdomains to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.output_dir}/{self.domain}_{timestamp}"
        
        # Save all subdomains
        all_file = f"{filename}_all.txt"
        with open(all_file, 'w') as f:
            for subdomain in sorted(self.found_subdomains):
                f.write(f"{subdomain}\n")
        
        # Save resolvable subdomains
        resolvable_file = f"{filename}_resolvable.txt"
        with open(resolvable_file, 'w') as f:
            for subdomain in sorted(self.resolvable_subdomains):
                f.write(f"{subdomain}\n")
        
        # Save JSON with metadata
        json_file = f"{filename}_metadata.json"
        metadata = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'total_found': len(self.found_subdomains),
            'resolvable': len(self.resolvable_subdomains),
            'discovery_stats': self.discovery_stats,
            'subdomains': list(self.found_subdomains),
            'resolvable_subdomains': list(self.resolvable_subdomains)
        }
        
        with open(json_file, 'w') as f:
            json.dump(metadata, f, indent=4)
        
        console.print(f"\n[green]Results saved to:[/green]")
        console.print(f"  [cyan]{all_file}[/cyan]")
        console.print(f"  [cyan]{resolvable_file}[/cyan]")
        console.print(f"  [cyan]{json_file}[/cyan]")
    
    def display_results_table(self):
        """Display results in a formatted table"""
        table = Table(title=f"Discovered Subdomains for {self.domain}", show_lines=True)
        table.add_column("No.", style="cyan", justify="right")
        table.add_column("Subdomain", style="green")
        table.add_column("Status", justify="center")
        
        for i, subdomain in enumerate(sorted(self.found_subdomains), 1):
            status = "✓" if subdomain in self.resolvable_subdomains else "?"
            table.add_row(str(i), subdomain, status)
        
        console.print(table)
        
        # Display statistics
        stats_table = Table(title="Discovery Statistics", show_header=True)
        stats_table.add_column("Method", style="cyan")
        stats_table.add_column("Found", style="green", justify="right")
        
        for method, count in self.discovery_stats.items():
            if count > 0:
                stats_table.add_row(method.replace('_', ' ').title(), str(count))
        
        stats_table.add_row("TOTAL", str(len(self.found_subdomains)), style="bold yellow")
        console.print(stats_table)
    
    async def run_full_scan(self, methods: List[str], wordlist: str = None):
        """Run comprehensive subdomain scan"""
        self.scan_start_time = datetime.now()
        console.print(f"\n[bold cyan]Starting full scan for:[/bold cyan] {self.domain}")
        
        # Run selected methods
        if 'passive' in methods:
            passive_results = self.passive_discovery()
            self.found_subdomains.update(passive_results)
        
        if 'bruteforce' in methods:
            brute_results = await self.dns_bruteforce(wordlist)
            self.found_subdomains.update(brute_results)
        
        if 'webarchive' in methods:
            archive_results = self.web_archive_discovery()
            self.found_subdomains.update(archive_results)
        
        if 'zonetransfer' in methods:
            zone_results = self.dns_zone_transfer()
            self.found_subdomains.update(zone_results)
        
        if 'reverseip' in methods:
            reverse_results = self.reverse_ip_lookup()
            self.found_subdomains.update(reverse_results)
        
        if 'permutation' in methods and self.found_subdomains:
            perm_results = self.permute_subdomains(self.found_subdomains)
            self.found_subdomains.update(perm_results)
        
        # Validate all found subdomains
        console.print("\n[cyan]Validating discovered subdomains...[/cyan]")
        validation_tasks = []
        for subdomain in self.found_subdomains:
            base = subdomain.replace(f".{self.domain}", "")
            validation_tasks.append(self.check_dns_resolution(base))
        
        # Wait for all validation tasks
        await asyncio.gather(*validation_tasks)
        
        # Calculate scan duration
        scan_duration = datetime.now() - self.scan_start_time
        
        # Display results
        console.print("\n" + "="*60)
        console.print("[bold green]SCAN COMPLETED[/bold green]")
        console.print("="*60)
        
        self.display_results_table()
        
        console.print(f"\n[cyan]Scan Duration:[/cyan] {scan_duration}")
        console.print(f"[green]Total Subdomains Found:[/green] {len(self.found_subdomains)}")
        console.print(f"[green]Resolvable Subdomains:[/green] {len(self.resolvable_subdomains)}")
        
        # Save results
        if Config.SAVE_RESULTS:
            self.save_results()

class SimpleFinderCLI:
    """Command Line Interface for Simple-Finder"""
    
    def __init__(self):
        self.parser = self.create_parser()
    
    def create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='Simple-Finder - Advanced Subdomain Discovery Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --all
  %(prog)s example.com -m passive bruteforce
  %(prog)s example.com -w custom_wordlist.txt -o results/
  %(prog)s example.com --validate --save-json
            """
        )
        
        parser.add_argument('domain', help='Target domain to scan')
        
        parser.add_argument('-m', '--methods', nargs='+',
                          choices=['all', 'passive', 'bruteforce', 'webarchive',
                                  'zonetransfer', 'reverseip', 'permutation',
                                  'search', 'cert'],
                          default=['passive', 'bruteforce'],
                          help='Discovery methods to use')
        
        parser.add_argument('-w', '--wordlist',
                          default=Config.DEFAULT_WORDLIST,
                          help='Wordlist for bruteforce (default: %(default)s)')
        
        parser.add_argument('-o', '--output',
                          default='results',
                          help='Output directory (default: %(default)s)')
        
        parser.add_argument('-t', '--threads',
                          type=int,
                          default=Config.CONCURRENT_REQUESTS,
                          help='Number of concurrent threads (default: %(default)s)')
        
        parser.add_argument('--validate',
                          action='store_true',
                          help='Validate subdomains with HTTP requests')
        
        parser.add_argument('--save-json',
                          action='store_true',
                          help='Save results in JSON format')
        
        parser.add_argument('--no-banner',
                          action='store_true',
                          help='Don\'t display banner')
        
        parser.add_argument('-v', '--verbose',
                          action='store_true',
                          help='Verbose output')
        
        parser.add_argument('--version',
                          action='version',
                          version='Simple-Finder 2.0.0 by cyber_specterz')
        
        return parser
    
    def print_help_menu(self):
        """Display help menu with styling"""
        help_text = """
╔══════════════════════════════════════════════════════════╗
║                 SIMPLE-FINDER HELP MENU                  ║
╚══════════════════════════════════════════════════════════╝

[bold cyan]Basic Usage:[/bold cyan]
  simple-finder example.com
  simple-finder example.com --all
  simple-finder example.com -m passive bruteforce webarchive

[bold cyan]Discovery Methods:[/bold cyan]
  • [green]passive[/green]      - Use search engines and APIs
  • [green]bruteforce[/green]   - DNS bruteforce with wordlist
  • [green]webarchive[/green]   - Wayback Machine archives
  • [green]zonetransfer[/green] - DNS zone transfer attempts
  • [green]reverseip[/green]    - Reverse IP lookup
  • [green]permutation[/green]  - Generate subdomain permutations
  • [green]search[/green]       - Search engine scraping
  • [green]cert[/green]        - Certificate transparency logs

[bold cyan]Advanced Options:[/bold cyan]
  • Use custom wordlists: [yellow]-w /path/to/wordlist.txt[/yellow]
  • Increase threads: [yellow]-t 100[/yellow]
  • Save JSON output: [yellow]--save-json[/yellow]
  • Validate with HTTP: [yellow]--validate[/yellow]

[bold yellow]Quick Start Examples:[/bold yellow]
  1. Full scan: [cyan]simple-finder target.com --all[/cyan]
  2. Fast scan: [cyan]simple-finder target.com -m passive[/cyan]
  3. Comprehensive: [cyan]simple-finder target.com -m all -t 150[/cyan]

[bold red]Note:[/bold red] Some methods may require API keys in config.py
        """
        console.print(Panel.fit(help_text, title="Help", border_style="cyan"))
    
    async def run(self):
        """Run the CLI"""
        args = self.parser.parse_args()
        
        # Show banner
        if not args.no_banner:
            Banner.show_main_banner()
        
        # Handle 'all' methods
        if 'all' in args.methods:
            args.methods = ['passive', 'bruteforce', 'webarchive',
                           'zonetransfer', 'reverseip', 'permutation',
                           'search', 'cert']
        
        # Update config
        Config.CONCURRENT_REQUESTS = args.threads
        
        # Initialize finder
        finder = SubdomainFinder(args.domain, args.output)
        
        # Run scan
        await finder.run_full_scan(args.methods, args.wordlist)
        
        # Additional validation if requested
        if args.validate:
            console.print("\n[cyan]Performing HTTP validation...[/cyan]")
            validated = finder.validate_subdomains(finder.found_subdomains)
            console.print(f"[green]Valid subdomains:[/green] {len(validated)}")
        
        # Save JSON if requested
        if args.save_json:
            finder.save_results()

def check_dependencies():
    """Check if all dependencies are installed"""
    required = ['dns', 'requests', 'bs4', 'colorama', 'pyfiglet', 
                'termcolor', 'tqdm', 'rich', 'aiohttp']
    
    missing = []
    for dep in required:
        try:
            __import__(dep)
        except ImportError:
            missing.append(dep)
    
    if missing:
        console.print("[red]Missing dependencies:[/red]")
        for dep in missing:
            console.print(f"  [yellow]{dep}[/yellow]")
        console.print("\n[cyan]Install with:[/cyan] pip install -r requirements.txt")
        return False
    
    return True

def create_default_wordlist():
    """Create default wordlist if it doesn't exist"""
    wordlist_dir = Path("wordlists")
    wordlist_dir.mkdir(exist_ok=True)
    
    wordlist_path = wordlist_dir / "subdomains.txt"
    
    if not wordlist_path.exists():
        default_words = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "ns2", "cpanel", "whm", "webdisk", "admin", "email", "blog", "dev",
            "stage", "test", "api", "secure", "portal", "shop", "store", "forum",
            "support", "help", "docs", "wiki", "status", "git", "svn", "m",
            "mobile", "app", "apps", "demo", "beta", "staging", "old", "new",
            "backup", "mx", "imap", "static", "media", "cdn", "assets", "img",
            "images", "js", "css", "download", "uploads", "vpn", "ssh", "db",
            "database", "internal", "private", "public", "share", "files",
            "video", "music", "photo", "photos", "cast", "stream", "live",
            "tv", "radio", "news", "weather", "search", "maps", "drive",
            "docs", "sites", "play", "apps", "accounts", "login", "signin",
            "auth", "oauth", "profile", "user", "users", "account", "billing",
            "pay", "payment", "checkout", "cart", "shop", "store", "buy",
            "sell", "market", "marketplace", "trade", "trading", "invest",
            "investment", "bank", "banking", "finance", "financial", "money",
            "cash", "wallet", "coin", "crypto", "bitcoin", "ethereum", "blockchain",
            "token", "nft", "metaverse", "web3", "defi", "game", "games",
            "gaming", "play", "player", "players", "score", "scores", "leaderboard",
            "tournament", "tournaments", "match", "matches", "contest", "contests",
            "prize", "prizes", "reward", "rewards", "loyalty", "points", "credit",
            "credits", "gift", "gifts", "card", "cards", "voucher", "vouchers",
            "coupon", "coupons", "deal", "deals", "offer", "offers", "discount",
            "discounts", "sale", "sales", "clearance", "outlet", "factory",
            "warehouse", "storage", "logistics", "supply", "chain", "network",
            "networking", "connect", "connection", "connections", "link", "links",
            "node", "nodes", "hub", "hubs", "center", "centre", "central",
            "headquarters", "hq", "office", "offices", "branch", "branches",
            "location", "locations", "place", "places", "venue", "venues",
            "event", "events", "meeting", "meetings", "conference", "conferences",
            "summit", "summits", "forum", "forums", "board", "boards", "community",
            "communities", "group", "groups", "team", "teams", "crew", "crews",
            "staff", "employee", "employees", "worker", "workers", "member",
            "members", "partner", "partners", "affiliate", "affiliates", "reseller",
            "resellers", "distributor", "distributors", "dealer", "dealers",
            "agent", "agents", "broker", "brokers", "consultant", "consultants",
            "advisor", "advisors", "coach", "coaches", "mentor", "mentors",
            "trainer", "trainers", "educator", "educators", "teacher", "teachers",
            "professor", "professors", "student", "students", "learner", "learners",
            "alumni", "alumnus", "graduate", "graduates", "academy", "academies",
            "school", "schools", "college", "colleges", "university", "universities",
            "institute", "institutes", "research", "laboratory", "laboratories",
            "lab", "labs", "experiment", "experiments", "test", "tests", "trial",
            "trials", "study", "studies", "analysis", "analytics", "data", "dataset",
            "datasets", "database", "databases", "warehouse", "warehouses", "lake",
            "lakes", "stream", "streams", "pipeline", "pipelines", "etl", "elt",
            "transform", "transformation", "load", "loading", "extract", "extraction",
            "process", "processing", "compute", "computation", "server", "servers",
            "service", "services", "microservice", "microservices", "api", "apis",
            "gateway", "gateways", "router", "routers", "switch", "switches",
            "firewall", "firewalls", "proxy", "proxies", "vpn", "vpns", "tunnel",
            "tunnels", "bridge", "bridges", "mesh", "meshes", "cloud", "clouds",
            "edge", "edges", "fog", "mist", "dew", "rain", "storm", "storms",
            "hurricane", "hurricanes", "typhoon", "typhoons", "cyclone", "cyclones",
            "tornado", "tornados", "earthquake", "earthquakes", "tsunami", "tsunamis",
            "volcano", "volcanoes", "fire", "fires", "flood", "floods", "drought",
            "droughts", "famine", "famines", "pandemic", "pandemics", "epidemic",
            "epidemics", "virus", "viruses", "bacteria", "bacterium", "fungus",
            "fungi", "parasite", "parasites", "pathogen", "pathogens", "disease",
            "diseases", "illness", "illnesses", "sickness", "sicknesses", "health",
            "wellness", "fitness", "exercise", "exercises", "workout", "workouts",
            "yoga", "meditation", "mindfulness", "therapy", "therapies", "treatment",
            "treatments", "cure", "cures", "medicine", "medicines", "drug", "drugs",
            "pharmacy", "pharmacies", "hospital", "hospitals", "clinic", "clinics",
            "doctor", "doctors", "nurse", "nurses", "patient", "patients", "care",
            "cares", "love", "loves", "peace", "peaceful", "harmony", "harmonious",
            "balance", "balanced", "equilibrium", "symmetric", "asymmetric",
            "parallel", "perpendicular", "orthogonal", "diagonal", "horizontal",
            "vertical", "circular", "spherical", "cubic", "pyramid", "cone",
            "cylinder", "prism", "polygon", "polygons", "triangle", "triangles",
            "square", "squares", "pentagon", "pentagons", "hexagon", "hexagons",
            "octagon", "octagons", "circle", "circles", "ellipse", "ellipses",
            "parabola", "parabolas", "hyperbola", "hyperbolas", "sine", "cosine",
            "tangent", "cotangent", "secant", "cosecant", "arcsin", "arccos",
            "arctan", "sinh", "cosh", "tanh", "exp", "log", "ln", "sqrt", "root",
            "power", "exponent", "factorial", "permutation", "combination",
            "probability", "statistics", "mean", "median", "mode", "variance",
            "deviation", "correlation", "regression", "classification", "cluster",
            "clustering", "neural", "network", "networks", "deep", "learning",
            "machine", "machines", "artificial", "intelligence", "natural",
            "language", "processing", "computer", "vision", "speech", "recognition",
            "synthesis", "translation", "generation", "summarization", "sentiment",
            "analysis", "topic", "modeling", "embedding", "embeddings", "vector",
            "vectors", "matrix", "matrices", "tensor", "tensors", "gradient",
            "gradients", "derivative", "derivatives", "integral", "integrals",
            "calculus", "algebra", "geometry", "topology", "number", "theory",
            "set", "sets", "group", "groups", "ring", "rings", "field", "fields",
            "module", "modules", "vector", "space", "spaces", "manifold", "manifolds",
            "curve", "curves", "surface", "surfaces", "volume", "volumes", "area",
            "areas", "length", "width", "height", "depth", "radius", "diameter",
            "circumference", "perimeter", "angle", "angles", "degree", "degrees",
            "radian", "radians", "minute", "minutes", "second", "seconds", "time",
            "times", "date", "dates", "calendar", "calendars", "clock", "clocks",
            "watch", "watches", "timer", "timers", "stopwatch", "chronometer",
            "hourglass", "sundial", "timezone", "timezones", "daylight", "saving",
            "summer", "winter", "spring", "autumn", "fall", "season", "seasons",
            "year", "years", "month", "months", "week", "weeks", "day", "days",
            "hour", "hours", "minute", "minutes", "second", "seconds", "millisecond",
            "milliseconds", "microsecond", "microseconds", "nanosecond", "nanoseconds",
            "picosecond", "picoseconds", "femtosecond", "femtoseconds", "attosecond",
            "attoseconds", "zeptosecond", "zeptoseconds", "yoctosecond", "yoctoseconds",
            "planck", "time", "eternity", "infinity", "forever", "always", "never",
            "sometimes", "often", "rarely", "frequently", "occasionally", "periodically",
            "randomly", "chaotically", "deterministically", "stochastically",
            "probabilistically", "statistically", "significantly", "insignificantly",
            "marginally", "substantially", "considerably", "moderately", "slightly",
            "greatly", "hugely", "enormously", "immensely", "vastly", "extremely",
            "exceedingly", "exceptionally", "remarkably", "notably", "particularly",
            "especially", "specifically", "generally", "usually", "normally",
            "typically", "commonly", "ordinarily", "regularly", "routinely",
            "habitually", "customarily", "traditionally", "conventionally",
            "standardly", "basically", "fundamentally", "essentially", "intrinsically",
            "inherently", "naturally", "organically", "biologically", "chemically",
            "physically", "mathematically", "logically", "philosophically",
            "psychologically", "sociologically", "anthropologically", "historically",
            "geographically", "politically", "economically", "culturally",
            "religiously", "spiritually", "morally", "ethically", "legally",
            "juridically", "constitutionally", "democratically", "republicanly",
            "monarchically", "aristocratically", "oligarchically", "plutocratically",
            "technocratically", "bureaucratically", "autocratically", "dictatorially",
            "totalitarianly", "authoritarianly", "liberally", "conservatively",
            "progressively", "radically", "moderately", "centristly", "extremely",
            "left", "right", "center", "up", "down", "north", "south", "east",
            "west", "northeast", "northwest", "southeast", "southwest", "forward",
            "backward", "upward", "downward", "inward", "outward", "clockwise",
            "counterclockwise", "sunwise", "widdershins", "deasil", "deosil",
            "tuathal", "corporeal", "incorporeal", "material", "immaterial",
            "physical", "metaphysical", "spiritual", "supernatural", "paranormal",
            "normal", "abnormal", "regular", "irregular", "ordinary", "extraordinary",
            "common", "uncommon", "rare", "scarce", "plentiful", "abundant",
            "copious", "ample", "sufficient", "insufficient", "adequate",
            "inadequate", "satisfactory", "unsatisfactory", "acceptable",
            "unacceptable", "tolerable", "intolerable", "bearable", "unbearable",
            "endurable", "unendurable", "sustainable", "unsustainable", "renewable",
            "nonrenewable", "finite", "infinite", "limited", "unlimited", "bound",
            "boundless", "restricted", "unrestricted", "constrained", "unconstrained",
            "free", "bound", "obligated", "compelled", "forced", "coerced",
            "pressured", "influenced", "persuaded", "convinced", "motivated",
            "inspired", "encouraged", "discouraged", "deterred", "prevented",
            "hindered", "impeded", "obstructed", "blocked", "barred", "banned",
            "prohibited", "forbidden", "allowed", "permitted", "authorized",
            "sanctioned", "approved", "disapproved", "rejected", "denied",
            "refused", "accepted", "received", "taken", "given", "offered",
            "presented", "displayed", "shown", "exhibited", "demonstrated",
            "illustrated", "exemplified", "represented", "depicted", "portrayed",
            "described", "narrated", "told", "said", "spoken", "written",
            "printed", "published", "released", "issued", "distributed",
            "circulated", "disseminated", "broadcast", "televised", "streamed",
            "webcast", "podcast", "vodcast", "screencast", "telecast", "radiocast",
            "newscast", "sportscast", "weathercast", "forecast", "prediction",
            "prophecy", "prognostication", "divination", "augury", "omen",
            "sign", "signal", "indication", "evidence", "proof", "confirmation",
            "verification", "validation", "authentication", "certification",
            "accreditation", "endorsement", "recommendation", "suggestion",
            "advice", "counsel", "guidance", "direction", "instruction",
            "education", "training", "coaching", "mentoring", "tutoring",
            "teaching", "learning", "studying", "researching", "investigating",
            "exploring", "discovering", "inventing", "creating", "designing",
            "engineering", "building", "constructing", "manufacturing", "producing",
            "making", "fabricating", "assembling", "composing", "writing",
            "painting", "drawing", "sculpting", "carving", "molding", "casting",
            "forging", "welding", "soldering", "brazing", "riveting", "bolting",
            "nailing", "screwing", "gluing", "adhering", "bonding", "joining",
            "connecting", "linking", "coupling", "pairing", "matching", "mating",
            "breeding", "reproducing", "generating", "procreating", "multiplying",
            "dividing", "adding", "subtracting", "multiplying", "dividing",
            "calculating", "computing", "processing", "analyzing", "parsing",
            "tokenizing", "lemmatizing", "stemming", "tagging", "labeling",
            "classifying", "categorizing", "grouping", "clustering", "sorting",
            "ordering", "arranging", "organizing", "structuring", "formatting",
            "styling", "designing", "theming", "skinning", "customizing",
            "personalizing", "tailoring", "adapting", "adjusting", "modifying",
            "changing", "altering", "transforming", "converting", "translating",
            "interpreting", "explaining", "clarifying", "simplifying", "complicating",
            "obfuscating", "encrypting", "decrypting", "encoding", "decoding",
            "compressing", "decompressing", "archiving", "extracting", "packing",
            "unpacking", "wrapping", "unwrapping", "boxing", "unboxing", "crating",
            "uncrating", "palletizing", "depalletizing", "loading", "unloading",
            "shipping", "receiving", "delivering", "distributing", "dispatching",
            "transporting", "moving", "relocating", "transferring", "transmitting",
            "sending", "receiving", "accepting", "rejecting", "returning",
            "exchanging", "refunding", "compensating", "reimbursing", "paying",
            "charging", "billing", "invoicing", "quoting", "estimating", "pricing",
            "valuing", "assessing", "evaluating", "appraising", "rating", "ranking",
            "scoring", "grading", "marking", "labeling", "tagging", "flagging",
            "bookmarking", "favoriting", "liking", "disliking", "loving", "hating",
            "admiring", "despising", "respecting", "disrespecting", "honoring",
            "dishonoring", "praising", "criticizing", "complimenting", "insulting",
            "flattering", "offending", "pleasing", "displeasing", "satisfying",
            "dissatisfying", "gratifying", "frustrating", "encouraging", "discouraging",
            "inspiring", "depressing", "uplifting", "demoralizing", "motivating",
            "demotivating", "stimulating", "sedating", "exciting", "calming",
            "arousing", "soothing", "agitating", "pacifying", "provoking",
            "appeasing", "challenging", "supporting", "opposing", "resisting",
            "yielding", "surrendering", "persisting", "enduring", "withstanding",
            "surviving", "thriving", "flourishing", "prospering", "succeeding",
            "failing", "winning", "losing", "drawing", "tying", "beating",
            "defeating", "conquering", "overcoming", "mastering", "dominating",
            "controlling", "commanding", "leading", "following", "guiding",
            "directing", "managing", "administering", "governing", "ruling",
            "reigning", "presiding", "overseeing", "supervising", "monitoring",
            "observing", "watching", "looking", "seeing", "viewing", "reading",
            "listening", "hearing", "feeling", "touching", "tasting", "smelling",
            "sensing", "perceiving", "detecting", "recognizing", "identifying",
            "naming", "calling", "addressing", "greeting", "welcoming", "farewelling",
            "parting", "separating", "dividing", "splitting", "merging", "joining",
            "uniting", "combining", "mixing", "blending", "stirring", "shaking",
            "whisking", "beating", "whipping", "folding", "kneading", "rolling",
            "cutting", "chopping", "slicing", "dicing", "mincing", "grating",
            "shredding", "peeling", "paring", "coring", "seeding", "stemming",
            "washing", "rinsing", "draining", "drying", "moistening", "wetting",
            "soaking", "steeping", "brewing", "fermenting", "distilling",
            "evaporating", "condensing", "freezing", "melting", "thawing",
            "heating", "cooling", "warming", "chilling", "refrigerating",
            "freezing", "defrosting", "cooking", "baking", "roasting", "grilling",
            "broiling", "frying", "sautéing", "simmering", "boiling", "steaming",
            "poaching", "braising", "stewing", "barbecuing", "smoking", "curing",
            "pickling", "preserving", "canning", "jarring", "bottling", "packaging",
            "wrapping", "sealing", "labeling", "dating", "coding", "tracking",
            "tracing", "following", "pursuing", "chasing", "hunting", "stalking",
            "tracking", "trailing", "shadowing", "monitoring", "surveilling",
            "spying", "eavesdropping", "wiretapping", "bugging", "tapping",
            "intercepting", "jamming", "blocking", "filtering", "censoring",
            "moderating", "editing", "reviewing", "approving", "publishing",
            "sharing", "posting", "blogging", "tweeting", "retweeting", "liking",
            "sharing", "commenting", "replying", "mentioning", "tagging",
            "hashtagging", "trending", "viral", "viralizing", "spreading",
            "propagating", "disseminating", "broadcasting", "narrowcasting",
            "multicasting", "anycasting", "unicasting", "broadcasting", "streaming",
            "downloading", "uploading", "syncing", "backing", "restoring",
            "recovering", "retrieving", "fetching", "pulling", "pushing",
            "committing", "merging", "branching", "forking", "cloning", "copying",
            "pasting", "cutting", "deleting", "undoing", "redoing", "saving",
            "loading", "exporting", "importing", "migrating", "transferring",
            "converting", "translating", "compiling", "interpreting", "executing",
            "running", "debugging", "testing", "verifying", "validating",
            "authenticating", "authorizing", "logging", "monitoring", "alerting",
            "notifying", "informing", "updating", "upgrading", "downgrading",
            "installing", "uninstalling", "configuring", "setting", "adjusting",
            "tuning", "optimizing", "maximizing", "minimizing", "scaling",
            "resizing", "zooming", "panning", "rotating", "flipping", "mirroring",
            "inverting", "reversing", "forwarding", "rewinding", "playing",
            "pausing", "stopping", "recording", "capturing", "streaming",
            "broadcasting", "narrowcasting", "multicasting", "anycasting",
            "unicasting", "broadcasting", "streaming", "downloading", "uploading",
            "syncing", "backing", "restoring", "recovering", "retrieving",
            "fetching", "pulling", "pushing", "committing", "merging", "branching",
            "forking", "cloning", "copying", "pasting", "cutting", "deleting",
            "undoing", "redoing", "saving", "loading", "exporting", "importing",
            "migrating", "transferring", "converting", "translating", "compiling",
            "interpreting", "executing", "running", "debugging", "testing",
            "verifying", "validating", "authenticating", "authorizing", "logging",
            "monitoring", "alerting", "notifying", "informing", "updating",
            "upgrading", "downgrading", "installing", "uninstalling", "configuring",
            "setting", "adjusting", "tuning", "optimizing", "maximizing",
            "minimizing", "scaling", "resizing", "zooming", "panning", "rotating",
            "flipping", "mirroring", "inverting", "reversing", "forwarding",
            "rewinding", "playing", "pausing", "stopping", "recording", "capturing",
            "streaming", "broadcasting", "narrowcasting", "multicasting", "anycasting",
            "unicasting", "broadcasting", "streaming", "downloading", "uploading",
            "syncing", "backing", "restoring", "recovering", "retrieving",
            "fetching", "pulling", "pushing", "committing", "merging", "branching",
            "forking", "cloning", "copying", "pasting", "cutting", "deleting",
            "undoing", "redoing", "saving", "loading", "exporting", "importing",
            "migrating", "transferring", "converting", "translating", "compiling",
            "interpreting", "executing", "running", "debugging", "testing",
            "verifying", "validating", "authenticating", "authorizing", "logging",
            "monitoring", "alerting", "notifying", "informing", "updating",
            "upgrading", "downgrading", "installing", "uninstalling", "configuring",
            "setting", "adjusting", "tuning", "optimizing", "maximizing",
            "minimizing", "scaling", "resizing", "zooming", "panning", "rotating",
            "flipping", "mirroring", "inverting", "reversing", "forwarding",
            "rewinding", "playing", "pausing", "stopping", "recording", "capturing"
        ]
        
        with open(wordlist_path, 'w') as f:
            for word in default_words:
                f.write(f"{word}\n")
        
        console.print(f"[green]Created default wordlist:[/green] {wordlist_path}")

async def main():
    """Main function"""
    try:
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)
        
        # Create default wordlist if needed
        create_default_wordlist()
        
        # Show banner
        Banner.show_main_banner()
        
        # Parse arguments
        if len(sys.argv) == 1:
            cli = SimpleFinderCLI()
            cli.print_help_menu()
            sys.exit(0)
        
        # Run CLI
        cli = SimpleFinderCLI()
        await cli.run()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Check if running on Termux
    if os.path.exists('/data/data/com.termux/files/usr'):
        console.print("[yellow]Termux detected - optimizing settings...[/yellow]")
        Config.CONCURRENT_REQUESTS = 20  # Lower concurrency for Termux
    
    # Run the tool
    asyncio.run(main())