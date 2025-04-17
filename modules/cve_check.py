from core.base import VulnCheck
from colorama import Fore

class CVECheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for exposed versions and CVEs...")
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            headers = response.headers

            server = headers.get('Server', '').lower()
            powered_by = headers.get('X-Powered-By', '').lower()

            known_cves = {
                'apache/2.4.49': 'CVE-2021-41773',
                'php/5.4': 'Multiple CVEs',
                'nginx/1.6.0': 'CVE-2014-6278',
                'iis/7.5': 'CVE-2015-1635'
            }

            for banner in [server, powered_by]:
                for sig, cve in known_cves.items():
                    if sig in banner:
                        self.scanner.vulnerabilities.append({
                            'type': 'Outdated Software Detected',
                            'location': self.scanner.base_url,
                            'example': f"Header matched: {sig} → CVE: {cve}",
                            'severity': 'High',
                            'references': ['CVE-2021-41773', 'CWE-94'],
            'solution': 'Update to the latest software version'
                        })
                        print(Fore.RED + f"[!] Outdated version detected: {sig} - {cve}")
        except Exception as e:
            print(Fore.YELLOW + f"[?] CVE check failed: {str(e)}")