from core.base import VulnCheck
from colorama import Fore
from constants import WAF_SIGNATURES

class WAFCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for WAF presence...")
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            headers = response.headers
            server = headers.get('server', '').lower()
            x_powered_by = headers.get('x-powered-by', '').lower()

            for waf_name, signature in WAF_SIGNATURES.items():
                if signature in server or signature in x_powered_by or signature in response.text.lower():
                    self.scanner.vulnerabilities.append({
                        'type': 'WAF Detected',
                        'location': 'HTTP Headers',
                        'example': f"{waf_name} detected",
                        'severity': 'Info',
                        'solution': 'Configure WAF rules properly'
                    })
                    print(Fore.YELLOW + f"[!] WAF detected: {waf_name}")
                    return

            test_payload = "<script>alert(1)</script>"
            test_response = self.scanner.session.get(f"{self.scanner.base_url}?test={test_payload}", verify=False, timeout=10)

            if any(x in test_response.text.lower() for x in ['blocked', 'forbidden', 'security', 'waf']):
                self.scanner.vulnerabilities.append({
                    'type': 'WAF Detected',
                    'location': 'Blocked Response',
                    'example': "WAF blocked malicious payload",
                    'severity': 'Info',
                    'solution': 'Configure WAF rules properly'
                })
                print(Fore.YELLOW + "[!] WAF detected (blocked malicious payload)")
            else:
                print(Fore.GREEN + "[+] No WAF detected")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking WAF: {str(e)}")