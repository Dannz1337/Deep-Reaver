from core.base import VulnCheck
from urllib.parse import urlparse, parse_qs, quote
from colorama import Fore

class SSTICheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for Server-Side Template Injection (SSTI)...")
        payloads = {
            "{{7*7}}": "49",
            "${7*7}": "49",
            "<%= 7*7 %>": "49"
        }

        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            parsed = urlparse(response.url)
            query_params = parse_qs(parsed.query)

            if not query_params:
                print(Fore.YELLOW + "[!] No URL parameters found to test SSTI.")
                return

            for param in query_params:
                for payload, expected in payloads.items():
                    test_url = response.url.replace(
                        f"{param}={query_params[param][0]}",
                        f"{param}={quote(payload)}"
                    )
                    test_response = self.scanner.session.get(test_url, verify=False, timeout=10)

                    if expected in test_response.text:
                        snippet = test_response.text[:100].replace("\n", " ")
                        self.scanner.vulnerabilities.append({
                            'type': 'Server-Side Template Injection',
                            'location': f"Parameter: {param}",
                            'example': f"Payload: {payload} → Response: {snippet}",
                            'severity': 'Critical',
                            'references': ['CWE-94'],
            'solution': 'Sanitize template inputs or use safe rendering methods'
                        })
                        print(Fore.RED + f"[!] SSTI vulnerability found in parameter: {param}")
                        return
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking SSTI: {str(e)}")