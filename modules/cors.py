from core.base import VulnCheck
from colorama import Fore

class CORSCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for CORS misconfigurations...")
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            response = self.scanner.session.get(self.scanner.base_url, headers=headers, verify=False, timeout=10)

            if 'Access-Control-Allow-Origin' in response.headers:
                origin = response.headers['Access-Control-Allow-Origin']
                if origin == '*':
                    self.scanner.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'location': 'Access-Control-Allow-Origin',
                        'example': "CORS allows all origins (*)",
                        'severity': 'Medium',
                        'solution': 'Restrict allowed origins'
                    })
                    print(Fore.RED + "[!] Insecure CORS policy - allows all origins (*)")
                elif 'evil.com' in origin:
                    self.scanner.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'location': 'Access-Control-Allow-Origin',
                        'example': "CORS reflects arbitrary origin",
                        'severity': 'High',
                        'solution': 'Validate origin headers'
                    })
                    print(Fore.RED + "[!] CORS reflects arbitrary origin")
            else:
                print(Fore.GREEN + "[+] No CORS misconfigurations detected")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking CORS: {str(e)}")