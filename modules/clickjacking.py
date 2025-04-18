from core.base import VulnCheck
from colorama import Fore

class ClickjackingCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for UI redress attacks...")
        
        test_urls = [
            self.scanner.base_url,
            urljoin(self.scanner.base_url, "/account"),
            urljoin(self.scanner.base_url, "/admin")
        ]
        
        for url in test_urls:
            try:
                response = self.scanner.session.get(url, verify=False, timeout=10)
                headers = response.headers
                
                vulnerabilities = []
                
                # Check X-Frame-Options
                if 'X-Frame-Options' not in headers:
                    vulnerabilities.append('Missing X-Frame-Options header')
                else:
                    xfo = headers['X-Frame-Options'].upper()
                    if xfo not in ['DENY', 'SAMEORIGIN']:
                        vulnerabilities.append(f'Weak X-Frame-Options value: {xfo}')
                
                # Check Content-Security-Policy frame-ancestors
                csp = headers.get('Content-Security-Policy', '').lower()
                if 'frame-ancestors' not in csp:
                    vulnerabilities.append('Missing frame-ancestors in CSP')
                
                if vulnerabilities:
                    self.scanner.vulnerabilities.append({
                        'type': 'Clickjacking',
                        'location': url,
                        'example': ", ".join(vulnerabilities),
                        'severity': 'Medium',
                        'solution': 'Add proper X-Frame-Options header (DENY or SAMEORIGIN) and/or Content-Security-Policy with frame-ancestors directive.'
                    })
                    print(Fore.RED + f"[!] Clickjacking vulnerabilities at {url}: {', '.join(vulnerabilities)}")
                else:
                    print(Fore.GREEN + f"[+] Secure framing headers found at {url}")
                    
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error checking {url} for clickjacking: {str(e)}")