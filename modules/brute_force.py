from core.base import VulnCheck
from colorama import Fore
from urllib.parse import urljoin

class BruteForceLoginCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Testing for weak authentication mechanisms...")
        
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'toor'),
            ('test', 'test'),
            ('user', '123456'),
            ('administrator', ''),
            ('guest', 'guest'),
            ('admin', 'admin123'),
            ('root', 'root'),
            ('admin', '1234')
        ]

        login_urls = [
            "/login",
            "/admin",
            "/wp-login.php",
            "/admin/login",
            "/account/login",
            "/auth",
            "/signin"
        ]

        for login_path in login_urls:
            login_url = urljoin(self.scanner.base_url, login_path)
            try:
                # Check if login page exists
                response = self.scanner.session.get(login_url, verify=False, timeout=10)
                if response.status_code != 200:
                    continue
                    
                # Detect login form fields
                content = response.text.lower()
                if not any(x in content for x in ['login', 'username', 'password', 'email']):
                    continue
                    
                # Try to identify form parameters
                username_field = 'username' if 'username' in content else 'email'
                password_field = 'password'
                
                # Check for CSRF token
                csrf_token = self._extract_csrf_token(content)
                login_data = {
                    username_field: '',
                    password_field: '',
                    'submit': 'Login'
                }
                if csrf_token:
                    login_data['csrf_token'] = csrf_token
                
                # Test common credentials
                for username, password in common_creds:
                    login_data[username_field] = username
                    login_data[password_field] = password
                    
                    login_response = self.scanner.session.post(
                        login_url, 
                        data=login_data, 
                        verify=False, 
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    if self._is_login_successful(login_response):
                        self.scanner.vulnerabilities.append({
                            'type': 'Weak Credentials',
                            'location': login_url,
                            'example': f"Successful login with {username}:{password}",
                            'severity': 'High',
                            'solution': 'Enforce strong password policies, implement account lockout, and enable multi-factor authentication.'
                        })
                        print(Fore.RED + f"[!] Successful login with {username}:{password} at {login_url}")
                        break
                        
            except Exception as e:
                print(Fore.YELLOW + f"[?] Error testing {login_url}: {str(e)}")
                continue
    
    def _extract_csrf_token(self, content):
        # Simple CSRF token extraction
        if 'csrf' in content or 'token' in content:
            # This would need to be implemented based on actual page parsing
            return 'dummy_token'
        return None
    
    def _is_login_successful(self, response):
        # Check for redirect to authenticated page
        if response.status_code in [301, 302]:
            return True
            
        # Check for success indicators in response
        content = response.text.lower()
        return any(x in content for x in ['logout', 'welcome', 'dashboard', 'my account'])