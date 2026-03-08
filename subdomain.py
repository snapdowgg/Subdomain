import requests
import sys
import json
import os
import re
import random
from concurrent.futures import ThreadPoolExecutor
import urllib3

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainScanner:
    def __init__(self):
        self.subdomains = set()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
        })

    def load_existing(self, filename):
        if os.path.exists(filename):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    for line in f:
                        self.subdomains.add(line.strip().lower())
            except: pass

    def save_subdomain(self, subdomain, output_file):
        if not subdomain: return
        subdomain = subdomain.strip().lower()
        subdomain = subdomain.replace('*.', '')
        
        if subdomain.startswith('http://'): subdomain = subdomain[7:]
        if subdomain.startswith('https://'): subdomain = subdomain[8:]
        if '/' in subdomain: subdomain = subdomain.split('/')[0]
        
        if subdomain and subdomain not in self.subdomains:
            self.subdomains.add(subdomain)
            print(f"{GREEN}[+]{RESET} Found: {WHITE}{subdomain}{RESET}")
            try:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(subdomain + '\n')
                return True
            except:
                pass
        return False

    def scan_crtsh(self, domain, output_file):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = self.session.get(url, timeout=30)
            if r.status_code == 200 and r.text.strip():
                try:
                    data = json.loads(r.text)
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        names = name_value.replace("<BR>", "\n").replace("<br>", "\n").split("\n")
                        for name in names:
                            self.save_subdomain(name, output_file)
                except: pass
        except Exception as e:
            print(f"{RED}[-]{RESET} crt.sh Error: {e}")

    def scan_hackertarget(self, domain, output_file):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            r = self.session.get(url, timeout=20)
            if "API count exceeded" in r.text:
                print(f"{RED}[-]{RESET} HackerTarget API limit exceeded")
                return
            for line in r.text.splitlines():
                sub = line.split(',')[0]
                self.save_subdomain(sub, output_file)
        except Exception as e:
            print(f"{RED}[-]{RESET} HackerTarget Error: {e}")

    def scan_rapiddns(self, domain, output_file):
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            r = self.session.get(url, timeout=25)
            subs = re.findall(r'[\w\.-]+\.' + re.escape(domain), r.text)
            for sub in subs:
                self.save_subdomain(sub, output_file)
        except Exception as e:
            print(f"{RED}[-]{RESET} RapidDNS Error: {e}")

    def scan_alienvault(self, domain, output_file):
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            r = self.session.get(url, timeout=25)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname')
                    self.save_subdomain(hostname, output_file)
        except Exception as e:
            print(f"{RED}[-]{RESET} AlienVault Error: {e}")

    def scan_urlscan(self, domain, output_file):
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            r = self.session.get(url, timeout=20)
            data = r.json()
            for result in data.get('results', []):
                page_domain = result.get('page', {}).get('domain')
                if page_domain and domain in page_domain:
                    self.save_subdomain(page_domain, output_file)
        except Exception as e:
            print(f"{RED}[-]{RESET} URLScan Error: {e}")

    def scan_anubis(self, domain, output_file):
        try:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            r = self.session.get(url, timeout=25)
            if r.status_code == 200:
                data = r.json()
                for sub in data:
                    self.save_subdomain(sub, output_file)
        except Exception as e:
            print(f"{RED}[-]{RESET} Anubis Error: {e}")

    def run(self, domain, output_file):
        print(f"{BLUE}[*]{RESET} Starting Subdomain Scanner for: {CYAN}{domain}{RESET}")
        
        self.load_existing(output_file)
        initial_count = len(self.subdomains)
        
        sources = [
            self.scan_crtsh, self.scan_hackertarget, self.scan_rapiddns,
            self.scan_alienvault, self.scan_urlscan, self.scan_anubis
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(source, domain, output_file) for source in sources]
            for future in futures:
                future.result()

        new_found = len(self.subdomains) - initial_count
        print(f"\n{YELLOW}[*]{RESET} Total subdomains: {WHITE}{len(self.subdomains)}{RESET}")
        print(f"{GREEN}[+]{RESET} New found: {WHITE}{new_found}{RESET}")
        print(f"{GREEN}[+]{RESET} Saved to {CYAN}{output_file}{RESET}")

def get_user_input():
    print(f"\n{CYAN}[1]{RESET} Single Target")
    print(f"{CYAN}[2]{RESET} Massive Scan (List)")
    
    choice = input(f"\n{YELLOW}[?]{RESET} Pilih Mode: ").strip()
    
    targets = []
    if choice == '1':
        domain = input(f"{YELLOW}[?]{RESET} Masukkan Domain (contoh: google.com): ").strip().lower()
        if not domain:
            print(f"{RED}[-]{RESET} Domain tidak boleh kosong.")
            return None, None
        targets.append(domain)
        
    elif choice == '2':
        list_file = input(f"{YELLOW}[?]{RESET} Masukkan path file list: ").strip()
        if not os.path.exists(list_file):
            print(f"{RED}[-]{RESET} File tidak ditemukan.")
            return None, None
            
        try:
            with open(list_file, 'r', encoding='utf-8', errors='ignore') as f:
                targets = [line.strip().lower() for line in f if line.strip()]
            if not targets:
                print(f"{RED}[-]{RESET} File kosong.")
                return None, None
        except Exception as e:
            print(f"{RED}[-]{RESET} Error membaca file: {e}")
            return None, None
            
    else:
        print(f"{RED}[-]{RESET} Pilihan tidak valid.")
        return None, None

    output_file = input(f"{YELLOW}[?]{RESET} Masukkan nama file output (default: subdomains.txt): ").strip()
    if not output_file:
        output_file = "subdomains.txt"
        
    return targets, output_file

if __name__ == "__main__":
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    
    targets, output_file = get_user_input()

    if targets:
        scanner = SubdomainScanner()
        print(f"\n{YELLOW}[*]{RESET} Total targets loaded: {WHITE}{len(targets)}{RESET}")
        for domain in targets:
            scanner.run(domain, output_file)
