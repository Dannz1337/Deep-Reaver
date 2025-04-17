from core.base import VulnCheck
from colorama import Fore
from urllib.parse import urlparse, parse_qs, quote, urljoin
import re
import time

class RCEParamCheck(VulnCheck):
    def __init__(self, scanner):
        super().__init__(scanner)
        
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for possible RCE via parameters...")
        
        # Extended list of suspicious parameters
        params = ["cmd", "exec", "command", "run", "call", "system", "query", 
                 "function", "request", "eval", "execute", "payload", "input",
                 "code", "script", "operation", "handler"]
        
        # More comprehensive payloads with time-based detection
        payloads = [
            (";id", r"uid=\d+\(.+?\)\s+gid=\d+\(.+?\)", False),
            ("&& whoami", r"root|admin|user|www-data", False),
            ("| uname -a", r"Linux|Darwin|Windows", False),
            ("`id`", r"uid=\d+\(.+?\)\s+gid=\d+\(.+?\)", False),
            ("$(whoami)", r"root|admin|user|www-data", False),
            ("%0Aid", r"uid=\d+\(.+?\)\s+gid=\d+\(.+?\)", False),
            (";sleep 5", r"", True),
            ("&& sleep 5", r"", True),
            ("| ping -c 5 127.0.0.1", r"", True),
            ("`sleep 5`", r"", True),
            ("$(sleep 5)", r"", True)
        ]
        
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=20)
            parsed = urlparse(response.url)
            query_params = parse_qs(parsed.query)
            
            vulnerable_params = []
            
            # Test existing URL parameters first
            for param in query_params:
                original_value = query_params[param][0]
                
                for payload, pattern, is_time_based in payloads:
                    try:
                        test_url = response.url.replace(
                            f"{param}={original_value}",
                            f"{param}={quote(payload)}"
                        )
                        
                        start_time = time.time()
                        resp = self.scanner.session.get(test_url, timeout=25 if is_time_based else 15, verify=False)
                        elapsed = time.time() - start_time
                        
                        # Time-based detection
                        if is_time_based and elapsed > 4:
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': 'Time-based RCE',
                                'evidence': f"Delayed response ({elapsed:.2f}s)"
                            })
                            break
                            
                        # Pattern-based detection
                        elif not is_time_based and re.search(pattern, resp.text, re.IGNORECASE):
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': 'Immediate RCE',
                                'evidence': f"Command output in response"
                            })
                            break
                            
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing {param} with {payload}: {str(e)}")
                        continue
            
            # Test default parameters if no vulnerable params found
            if not vulnerable_params and not query_params:
                for param in params:
                    for payload, pattern, is_time_based in payloads:
                        try:
                            test_url = f"{self.scanner.base_url}?{param}={quote(payload)}"
                            
                            start_time = time.time()
                            resp = self.scanner.session.get(test_url, timeout=25 if is_time_based else 15, verify=False)
                            elapsed = time.time() - start_time
                            
                            if is_time_based and elapsed > 4:
                                vulnerable_params.append({
                                    'param': param,
                                    'payload': payload,
                                    'type': 'Time-based RCE',
                                    'evidence': f"Delayed response ({elapsed:.2f}s)"
                                })
                                break
                                
                            elif not is_time_based and re.search(pattern, resp.text, re.IGNORECASE):
                                vulnerable_params.append({
                                    'param': param,
                                    'payload': payload,
                                    'type': 'Immediate RCE',
                                    'evidence': f"Command output in response"
                                })
                                break
                                
                        except Exception as e:
                            print(Fore.YELLOW + f"[?] Error testing {param} with {payload}: {str(e)}")
                            continue
            
            # Report findings
            if vulnerable_params:
                for vuln in vulnerable_params:
                    self.scanner.vulnerabilities.append({
                        'type': 'Remote Code Execution',
                        'location': f"Parameter: {vuln['param']}",
                        'example': f"Payload: {vuln['payload']} | {vuln['evidence']}",
                        'severity': 'Critical',
                        'solution': 'Implement input validation and use secure command APIs',
                        'references': ['CWE-78', 'OWASP-A1']
                    })
                    print(Fore.RED + f"[!] RCE found in {vuln['param']} ({vuln['type']})")
            else:
                print(Fore.GREEN + "[+] No RCE vulnerabilities detected")
                
        except Exception as e:
            error_msg = f"Error during RCE check: {str(e)}"
            print(Fore.YELLOW + f"[?] {error_msg}")
            if hasattr(self.scanner, 'errors'):
                self.scanner.errors.append({
                    'module': self.__class__.__name__,
                    'error': error_msg
                })