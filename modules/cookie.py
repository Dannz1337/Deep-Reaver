from core.base import VulnCheck
from colorama import Fore

class CookieSecurityCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking cookie security flags...")
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=10)
            cookies = response.cookies

            for cookie in cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("HttpOnly flag missing")
                if cookie.domain and cookie.domain.startswith('.'):
                    issues.append("Overly broad domain scope")

                if issues:
                    self.scanner.vulnerabilities.append({
                        'type': 'Cookie Security Issue',
                        'location': f"Cookie: {cookie.name}",
                        'example': ", ".join(issues),
                        'severity': 'Medium',
                        'solution': 'Set Secure and HttpOnly flags'
                    })
                    print(Fore.RED + f"[!] Insecure cookie: {cookie.name} - {', '.join(issues)}")

            if not cookies:
                print(Fore.GREEN + "[+] No cookies found")
            elif not any(v['type'] == 'Cookie Security Issue' for v in self.scanner.vulnerabilities):
                print(Fore.GREEN + "[+] All cookies have proper security flags")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking cookies: {str(e)}")