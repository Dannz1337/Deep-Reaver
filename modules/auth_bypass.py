from core.base import VulnCheck
from colorama import Fore

class AuthBypassCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for broken access control (auth bypass)...")

        protected_paths = [
            "/admin", "/dashboard", "/cpanel", "/account", "/settings",
            "/user/1", "/user/1/edit", "/profile", "/manage", "/private",
            "/confidential", "/secure", "/hidden", "/config", "/internal"
        ]

        login_indicators = ["login", "username", "password", "signin", "authentication"]

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; PentestBot/1.0)"
        }

        for path in protected_paths:
            url = self.scanner.base_url + path
            try:
                response = self.scanner.session.get(url, headers=headers, verify=False, timeout=10)

                content = response.text.lower()
                if (
                    response.status_code == 200 and
                    not any(indicator in content for indicator in login_indicators) and
                    any(keyword in content for keyword in ["admin", "dashboard", "profile", "settings", "user"])
                ):
                    severity = "High"
                    if "config" in url or "internal" in url:
                        severity = "Critical"

                    self.scanner.vulnerabilities.append({
                        'type': 'Broken Access Control',
                        'location': url,
                        'example': f"Unauthenticated access to: {url}",
                        'severity': severity,
                        'solution': 'Implement proper authorization checks for protected routes and role-based access control.'
                    })
                    print(Fore.RED + f"[!] Possible auth bypass at: {url}")
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error checking {url}: {str(e)}")