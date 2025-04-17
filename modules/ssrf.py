from core.base import VulnCheck
from colorama import Fore

class SSRFCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for SSRF vulnerabilities...")
        test_params = ["url", "redirect", "next", "data", "load", "path"]
        internal_targets = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"]

        for param in test_params:
            for target in internal_targets:
                test_url = f"{self.scanner.base_url}/?{param}={target}"
                try:
                    resp = self.scanner.session.get(test_url, timeout=10, verify=False)
                    if resp.status_code == 200 and any(t in resp.text for t in ["EC2", "root:x", "localhost"]):
                        self.scanner.vulnerabilities.append({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'location': test_url,
                            'example': test_url,
                            'severity': 'Critical',
                            'solution': 'Validate and sanitize user input that accepts URLs.'
                        })
                        print(Fore.RED + f"[!] Potential SSRF found: {test_url}")
                except Exception as e:
                    print(Fore.YELLOW + f"[?] Error on SSRF check: {e}")