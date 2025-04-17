from core.base import VulnCheck
from colorama import Fore
from urllib.parse import urljoin
from constants import COMMON_DIRECTORIES, COMMON_FILES
import re

class DirectoryFileEnumeration(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Starting comprehensive directory and file enumeration...")
        
        # Additional checks for directory listing vulnerabilities
        self.check_directory_listing()
        
        # Check common directories
        found_items = []
        for directory in COMMON_DIRECTORIES:
            url = urljoin(self.scanner.base_url, directory)
            try:
                response = self.scanner.session.get(url, verify=False, timeout=15)
                if response.status_code == 200:
                    content_length = int(response.headers.get('Content-Length', 0))
                    if content_length > 0:  # Ignore empty responses
                        found_items.append({
                            'type': 'Directory Listing',
                            'url': url,
                            'details': f"Status: {response.status_code}, Size: {content_length} bytes"
                        })
                        print(Fore.RED + f"[!] Found accessible directory: {url}")
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error checking {url}: {str(e)}")
                continue

        # Check common files
        for filename in COMMON_FILES:
            url = urljoin(self.scanner.base_url, filename)
            try:
                response = self.scanner.session.get(url, verify=False, timeout=15)
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if any(x in content_type for x in ['text', 'json', 'xml']):
                        snippet = response.text[:100].replace('\n', ' ').strip()
                        found_items.append({
                            'type': 'Sensitive File Exposure',
                            'url': url,
                            'details': f"Type: {content_type}, Snippet: {snippet}"
                        })
                        print(Fore.RED + f"[!] Found sensitive file: {url}")
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error checking {url}: {str(e)}")
                continue

        # Add findings to vulnerabilities
        for item in found_items:
            self.scanner.vulnerabilities.append({
                'type': item['type'],
                'location': item['url'],
                'example': item['details'],
                'severity': 'High' if item['type'] == 'Sensitive File Exposure' else 'Medium',
                'solution': 'Restrict access to sensitive directories and files',
                'references': ['CWE-548']
            })

        if not found_items:
            print(Fore.GREEN + "[+] No common sensitive directories or files found")

    def check_directory_listing(self):
        """Check for directory listing vulnerabilities"""
        test_dirs = ['images/', 'assets/', 'uploads/', 'static/']
        for test_dir in test_dirs:
            url = urljoin(self.scanner.base_url, test_dir)
            try:
                response = self.scanner.session.get(url, verify=False, timeout=15)
                if response.status_code == 200:
                    if any(x in response.text.lower() for x in ['index of', 'directory listing', '<title>directory of']):
                        self.scanner.vulnerabilities.append({
                            'type': 'Directory Listing Enabled',
                            'location': url,
                            'example': 'Directory contents are publicly accessible',
                            'severity': 'Medium',
                            'solution': 'Disable directory listing in server configuration',
                            'references': ['CWE-548']
                        })
                        print(Fore.RED + f"[!] Directory listing enabled at: {url}")
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error checking directory listing at {url}: {str(e)}")