from core.base import VulnCheck
from urllib.parse import urlparse, parse_qs, quote, urljoin
from colorama import Fore
import time

class RCEDetection(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for Remote Code Execution vulnerabilities...")
        
        # Comprehensive RCE test payloads
        test_payloads = [
            (';echo RCE_TEST_$(whoami)', 'Unix Command Injection'),
            ('|echo RCE_TEST_$(id)', 'Unix Command Injection'),
            ('&&echo RCE_TEST_$(pwd)', 'Unix Command Injection'),
            ('`echo RCE_TEST_$(uname -a)`', 'Unix Command Injection'),
            ('&echo RCE_TEST_%USERNAME%', 'Windows Command Injection'),
            ('%0Aecho RCE_TEST_%CD%', 'Windows Newline Injection'),
            ('$(sleep 5)', 'Time-based Unix Command Injection'),
            ('%26%26sleep%205', 'Time-based Unix Command Injection (encoded)'),
            ('|ping -c 5 127.0.0.1', 'Network-based Unix Command Injection'),
            ('&ping -n 5 127.0.0.1', 'Network-based Windows Command Injection')
        ]
        
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=15)
            parsed = urlparse(response.url)
            query_params = parse_qs(parsed.query)
            
            vulnerable_params = []
            
            for param in query_params:
                original_value = query_params[param][0]
                
                for payload, vuln_type in test_payloads:
                    try:
                        test_url = response.url.replace(
                            f"{param}={original_value}",
                            f"{param}={quote(payload)}"
                        )
                        
                        start_time = time.time()
                        test_response = self.scanner.session.get(test_url, verify=False, timeout=15)
                        elapsed = time.time() - start_time
                        
                        # Check for command output
                        test_string = payload.split(" ")[-1].strip(';').split(")")[0]
                        if test_string in test_response.text:
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': vuln_type,
                                'url': test_url
                            })
                            print(Fore.RED + f"[!] RCE vulnerability found ({vuln_type}) in parameter: {param}")
                            break
                            
                        # Check for time delays
                        if ('sleep' in payload or 'ping' in payload) and elapsed > 4:
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': f"Time-based {vuln_type}",
                                'url': test_url,
                                'delay': f"{elapsed:.2f}s"
                            })
                            print(Fore.RED + f"[!] Time-based RCE detected ({elapsed:.2f}s delay) in parameter: {param}")
                            break
                            
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing RCE payload on {param}: {str(e)}")
                        continue
            
            # Add findings to vulnerabilities
            for vuln in vulnerable_params:
                self.scanner.vulnerabilities.append({
                    'type': 'Remote Code Execution',
                    'location': f"Parameter: {vuln['param']}",
                    'example': f"Payload: {vuln['payload']} | Type: {vuln['type']}",
                    'severity': 'Critical',
                    'solution': 'Sanitize all user input and disable dangerous functions',
                    'references': ['CWE-78', 'OWASP-A1']
                })
            
            if not vulnerable_params:
                print(Fore.GREEN + "[+] No obvious RCE vulnerabilities detected")
                
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error during RCE check: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })