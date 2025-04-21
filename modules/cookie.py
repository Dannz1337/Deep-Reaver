from core.base import VulnCheck
from colorama import Fore
from urllib.parse import urlparse

class CookieSecurityCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking cookie security flags...")
        try:
            # Check both base URL and a sample POST request if available
            urls_to_check = [self.scanner.base_url]
            if hasattr(self.scanner, 'test_urls'):
                urls_to_check.extend(self.scanner.test_urls[:2])  # Check up to 2 additional URLs

            all_cookies = set()
            for url in urls_to_check:
                try:
                    response = self.scanner.session.get(url, verify=False, timeout=10)
                    all_cookies.update(response.cookies)
                    
                    # Also check POST requests if login URL is known
                    if hasattr(self.scanner, 'login_url') and url == self.scanner.login_url:
                        login_data = getattr(self.scanner, 'login_data', {'username': 'test', 'password': 'test'})
                        response = self.scanner.session.post(url, data=login_data, verify=False, timeout=10)
                        all_cookies.update(response.cookies)
                except Exception as e:
                    print(Fore.YELLOW + f"[?] Error checking cookies for {url}: {str(e)}")
                    continue

            if not all_cookies:
                print(Fore.GREEN + "[+] No cookies found")
                return

            domain = urlparse(self.scanner.base_url).netloc
            base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain

            for cookie in all_cookies:
                issues = []
                if not cookie.secure and urlparse(self.scanner.base_url).scheme == 'https':
                    issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("HttpOnly flag missing")
                if cookie.domain:
                    if cookie.domain.startswith('.'):
                        issues.append("Overly broad domain scope")
                    elif not cookie.domain.endswith(base_domain):
                        issues.append(f"Cross-domain cookie (domain: {cookie.domain})")
                if cookie.expires and cookie.expires > 365*24*60*60:  # > 1 year
                    issues.append("Excessively long lifespan")

                if issues:
                    self.scanner.vulnerabilities.append({
                        'type': 'Cookie Security Issue',
                        'location': f"Cookie: {cookie.name}",
                        'example': ", ".join(issues),
                        'severity': 'Medium',
                        'solution': 'Set Secure and HttpOnly flags; restrict domain and lifespan',
                        'references': ['OWASP-010', 'CWE-614']
                    })
                    print(Fore.RED + f"[!] Insecure cookie: {cookie.name} - {', '.join(issues)}")

            if not any(v['type'] == 'Cookie Security Issue' for v in self.scanner.vulnerabilities):
                print(Fore.GREEN + "[+] All cookies have proper security flags")

        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking cookies: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })