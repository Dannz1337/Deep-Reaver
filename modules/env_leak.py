from core.base import VulnCheck
from colorama import Fore

class EnvLeakCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for leaked .env files...")
        paths = ["/.env", "/config/.env", "/backend/.env"]

        for path in paths:
            url = self.scanner.base_url + path
            try:
                resp = self.scanner.session.get(url, timeout=10, verify=False, timeout=10)
                if resp.status_code == 200 and "APP_KEY" in resp.text:
                    self.scanner.vulnerabilities.append({
                        'type': 'Exposed .env File',
                        'location': url,
                        'example': url,
                        'severity': 'Critical',
                        'solution': 'Remove .env files from public directories or restrict access.'
                    })
                    print(Fore.RED + f"[!] Leaked .env found: {url}")
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error accessing {url}: {e}")