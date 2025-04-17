from core.base import VulnCheck
from colorama import Fore

class BruteForceLoginCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Testing common login credentials...")
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'toor'),
            ('test', 'test'),
            ('user', '123456')
        ]

        login_urls = [
            f"{self.scanner.base_url}/login",
            f"{self.scanner.base_url}/admin",
            f"{self.scanner.base_url}/wp-login.php"
        ]

        for login_url in login_urls:
            try:
                response = self.scanner.session.get(login_url, verify=False, timeout=10)
                if response.status_code == 200 and any(x in response.text.lower() for x in ['login', 'username', 'password']):
                    for username, password in common_creds:
                        data = {'username': username, 'password': password, 'submit': 'Login'}
                        login_response = self.scanner.session.post(login_url, data=data, verify=False, timeout=10)
                        if "logout" in login_response.text.lower() or "welcome" in login_response.text.lower():
                            self.scanner.vulnerabilities.append({
                                'type': 'Weak Credentials',
                                'location': login_url,
                                'example': f"Successful login with {username}:{password}",
                                'severity': 'High',
                                'solution': 'Enforce strong password policies'
                            })
                            print(Fore.RED + f"[!] Successful login with {username}:{password} at {login_url}")
                            break
            except:
                continue