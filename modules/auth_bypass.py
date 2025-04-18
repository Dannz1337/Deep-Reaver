from core.base import VulnCheck
from colorama import Fore
from urllib.parse import urljoin

class AuthBypassCheck(VulnCheck):
    def __init__(self, scanner=None):
        super().__init__(scanner)  # Initialize the parent class with scanner
        # Define indicators as instance variables
        self.login_indicators = ["login", "username", "password", "signin", "authentication", "auth"]
        self.protected_indicators = ["admin", "dashboard", "profile", "settings", "user", "private", "manage", "config"]

    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for broken access control (auth bypass)...")

        protected_paths = [
            "/admin", "/dashboard", "/cpanel", "/account", "/settings",
            "/user/1", "/user/1/edit", "/profile", "/manage", "/private",
            "/confidential", "/secure", "/hidden", "/config", "/internal",
            "/api/admin", "/wp-admin", "/administrator"
        ]

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; PentestBot/1.0)",
            "X-Original-URL": "/admin"  # Test for header-based bypass
        }

        for path in protected_paths:
            url = urljoin(self.scanner.base_url, path)
            try:
                # Test normal access
                response = self.scanner.session.get(url, headers=headers, verify=False, timeout=10)
                
                # Test with various bypass techniques
                bypass_headers = [
                    {"X-Forwarded-For": "127.0.0.1"},
                    {"X-Rewrite-URL": path},
                    {"Referer": url}
                ]
                
                for bypass_header in bypass_headers:
                    bypass_response = self.scanner.session.get(url, headers={**headers, **bypass_header}, verify=False, timeout=5)
                    self._check_response(bypass_response, url, "header bypass")
                
                # Test HTTP methods
                for method in ['POST', 'PUT', 'DELETE']:
                    method_response = self.scanner.session.request(method, url, headers=headers, verify=False, timeout=5)
                    self._check_response(method_response, url, f"{method} method access")
                
                self._check_response(response, url, "direct access")
                
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error checking {url}: {str(e)}")
    
    def _check_response(self, response, url, technique):
        content = response.text.lower()
        login_required = any(indicator in content for indicator in self.login_indicators)
        protected_content = any(keyword in content for keyword in self.protected_indicators)
        
        if response.status_code == 200 and not login_required and protected_content:
            severity = "High"
            if any(x in url for x in ["config", "internal", "admin"]):
                severity = "Critical"
            
            self.scanner.vulnerabilities.append({
                'type': 'Broken Access Control',
                'location': url,
                'example': f"Unauthenticated access via {technique}: {url}",
                'severity': severity,
                'solution': 'Implement proper authorization checks, role-based access control, and secure HTTP methods.'
            })
            print(Fore.RED + f"[!] Possible auth bypass ({technique}) at: {url}")