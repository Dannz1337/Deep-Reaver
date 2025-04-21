from core.base import VulnCheck
from colorama import Fore
from urllib.parse import urlparse

class CORSCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for CORS misconfigurations...")
        try:
            test_origins = [
                'https://evil.com',
                'http://evil.com',
                'null',
                'https://' + urlparse(self.scanner.base_url).netloc.replace('www.', 'attacker.')
            ]
            
            methods_to_test = ['GET', 'POST', 'DELETE']
            vulnerable = False
            
            for origin in test_origins:
                for method in methods_to_test:
                    headers = {
                        'Origin': origin,
                        'Access-Control-Request-Method': method
                    }
                    
                    # Test OPTIONS first (pre-flight)
                    try:
                        options_resp = self.scanner.session.options(
                            self.scanner.base_url,
                            headers=headers,
                            verify=False,
                            timeout=10
                        )
                        self._check_cors_response(options_resp, origin, method, "OPTIONS")
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error with OPTIONS request for {origin}: {str(e)}")
                    
                    # Test actual method
                    try:
                        if method == 'GET':
                            resp = self.scanner.session.get(
                                self.scanner.base_url,
                                headers={'Origin': origin},
                                verify=False,
                                timeout=10
                            )
                        elif method == 'POST':
                            resp = self.scanner.session.post(
                                self.scanner.base_url,
                                headers={'Origin': origin},
                                data={'test': 'value'},
                                verify=False,
                                timeout=10
                            )
                        elif method == 'DELETE':
                            resp = self.scanner.session.delete(
                                self.scanner.base_url,
                                headers={'Origin': origin},
                                verify=False,
                                timeout=10
                            )
                        
                        if self._check_cors_response(resp, origin, method, method):
                            vulnerable = True
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error with {method} request for {origin}: {str(e)}")
            
            if not vulnerable:
                print(Fore.GREEN + "[+] No CORS misconfigurations detected")
                
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking CORS: {str(e)}")
            if hasattr(self.scanner, 'errors'):
                self.scanner.errors.append({
                    'module': self.__class__.__name__,
                    'error': str(e)
                })

    def _check_cors_response(self, response, origin, method, req_type):
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if not acao:
            return False
            
        if acao == '*':
            if req_type != 'OPTIONS' and 'Access-Control-Allow-Credentials' in response.headers:
                self._log_cors_vuln(
                    "CORS allows all origins with credentials",
                    "High",
                    "Access-Control-Allow-Origin: * with credentials",
                    "Restrict allowed origins and disable credentials for wildcard"
                )
                return True
            else:
                self._log_cors_vuln(
                    "CORS allows all origins",
                    "Medium",
                    "Access-Control-Allow-Origin: *",
                    "Restrict allowed origins"
                )
                return True
        elif acao == origin:
            if acac.lower() == 'true':
                self._log_cors_vuln(
                    "CORS reflects origin with credentials",
                    "High",
                    f"Access-Control-Allow-Origin: {acao} with credentials",
                    "Validate origin headers and restrict credentials"
                )
                return True
            else:
                self._log_cors_vuln(
                    "CORS reflects origin",
                    "Medium",
                    f"Access-Control-Allow-Origin: {acao}",
                    "Validate origin headers"
                )
                return True
        return False
    
    def _log_cors_vuln(self, issue, severity, example, solution):
        self.scanner.vulnerabilities.append({
            'type': 'CORS Misconfiguration',
            'location': 'Access-Control-Allow-Origin',
            'example': example,
            'severity': severity,
            'solution': solution,
            'references': ['OWASP-010', 'CWE-942']
        })
        print(Fore.RED + f"[!] {issue}: {example}")