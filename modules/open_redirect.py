from core.base import VulnCheck
from urllib.parse import urlparse, parse_qs, quote
from colorama import Fore

class OpenRedirectCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for open redirect vulnerabilities...")
        test_params = ['url', 'redirect', 'next', 'target']
        test_redirect = "https://evil.com"

        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            parsed = urlparse(response.url)
            query_params = parse_qs(parsed.query)

            for param in query_params:
                if param.lower() in test_params:
                    test_url = response.url.replace(
                        f"{param}={query_params[param][0]}", 
                        f"{param}={test_redirect}"
                    )
                    test_response = self.scanner.session.get(test_url, verify=False, timeout=10)
                    if test_response.status_code in [301, 302] and test_redirect in test_response.headers.get('location', ''):
                        self.scanner.vulnerabilities.append({
                            'type': 'Open Redirect',
                            'location': f"Parameter: {param}",
                            'example': test_url,
                            'severity': 'Medium',
                            'solution': 'Validate redirect URLs'
                        })
                        print(Fore.RED + f"[!] Open redirect found in parameter: {param}")
                        break
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking open redirects: {str(e)}")