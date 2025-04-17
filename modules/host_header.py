from core.base import VulnCheck
from colorama import Fore

class HostHeaderInjectionCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for Host Header Injection...")
        headers = {
            "Host": "evil.com",
            "X-Forwarded-Host": "evil.com",
            "X-Host": "evil.com"
        }

        try:
            response = self.scanner.session.get(self.scanner.base_url, headers=headers, verify=False, timeout=10)
            snippet = response.text[:300].replace("\n", " ").replace("\r", " ").strip()

            if "evil.com" in response.text or "http://evil.com" in response.text:
                self.scanner.vulnerabilities.append({
                    'type': 'Host Header Injection',
                    'location': self.scanner.base_url,
                    'example': f"Header: Host: evil.com\nResponse snippet: {snippet}",
                    'severity': 'Critical',
                    'references': ['CWE-138', 'CWE-20'],
            'solution': 'Do not trust Host headers from client-side requests'
                })
                print(Fore.RED + "[!] Host Header Injection vulnerability detected!")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error during Host Header Injection check: {str(e)}")