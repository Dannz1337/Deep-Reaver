from core.base import VulnCheck
from colorama import Fore
import re

class JSONPCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for JSONP endpoints...")
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            scripts = re.findall(r'src=["\'](.*?\.js.*?)["\']', response.text)

            for script_url in scripts:
                if "callback=" in script_url or "jsonp=" in script_url:
                    self.scanner.vulnerabilities.append({
                        'type': 'JSONP Endpoint Exposure',
                        'location': script_url,
                        'example': f"{script_url}",
                        'severity': 'High',
                        'solution': 'Avoid using JSONP or validate allowed callback domains strictly'
                    })
                    print(Fore.RED + f"[!] Potential JSONP vulnerability found: {script_url}")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking JSONP: {str(e)}")