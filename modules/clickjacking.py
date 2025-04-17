from core.base import VulnCheck
from colorama import Fore

class ClickjackingCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for clickjacking vulnerability...")
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            if 'X-Frame-Options' not in response.headers:
                self.scanner.vulnerabilities.append({
                    'type': 'Clickjacking',
                    'location': 'Missing X-Frame-Options',
                    'example': "Page can be iframed",
                    'severity': 'Medium',
                    'solution': 'Add X-Frame-Options header'
                })
                print(Fore.RED + "[!] Clickjacking possible - X-Frame-Options missing")
            else:
                print(Fore.GREEN + "[+] X-Frame-Options header present")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking clickjacking: {str(e)}")