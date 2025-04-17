from core.base import VulnCheck
from urllib.parse import urlparse, parse_qs, quote, urljoin
from colorama import Fore
import re

class XSSCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for Cross-Site Scripting (XSS) vulnerabilities...")
        
        # Comprehensive XSS test payloads
        test_payloads = [
            ("<script>alert(document.domain)</script>", "Basic script tag"),
            ("\" onfocus=alert(document.domain) autofocus=\"", "Event handler"),
            ("'><img src=x onerror=alert(document.domain)>", "Image error handler"),
            ("javascript:alert(document.domain)", "JavaScript URI"),
            ("{{constructor.constructor('alert(document.domain)')()}}", "Template injection"),
            ("<svg onload=alert(document.domain)>", "SVG handler"),
            ("<iframe src=javascript:alert(document.domain)>", "Iframe injection"),
            ("<body onload=alert(document.domain)>", "Body handler"),
            ("<a href=javascript:alert(document.domain)>click</a>", "Anchor tag"),
            ("%3Cscript%3Ealert(document.domain)%3C/script%3E", "URL encoded")
        ]
        
        # Context-specific payloads
        context_payloads = {
            'html': "<script>alert(document.domain)</script>",
            'attribute': "\" onmouseover=alert(document.domain) \"",
            'javascript': "';alert(document.domain);//",
            'url': "javascript:alert(document.domain)"
        }
        
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=15)
            parsed = urlparse(response.url)
            query_params = parse_qs(parsed.query)
            
            vulnerable_params = []
            
            for param in query_params:
                original_value = query_params[param][0]
                
                for payload, payload_type in test_payloads:
                    try:
                        test_url = response.url.replace(
                            f"{param}={original_value}",
                            f"{param}={quote(payload)}"
                        )
                        
                        test_response = self.scanner.session.get(test_url, verify=False, timeout=15)
                        
                        # Check if payload appears in response
                        if payload.replace('document.domain', '') in test_response.text:
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': payload_type,
                                'url': test_url
                            })
                            print(Fore.RED + f"[!] XSS vulnerability found ({payload_type}) in parameter: {param}")
                            break
                            
                        # Check for DOM-based XSS
                        if "document.domain" in payload and "document.domain" in test_response.text:
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': f"DOM-based {payload_type}",
                                'url': test_url
                            })
                            print(Fore.RED + f"[!] DOM-based XSS detected ({payload_type}) in parameter: {param}")
                            break
                            
                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing XSS payload on {param}: {str(e)}")
                        continue
            
            # Add findings to vulnerabilities
            for vuln in vulnerable_params:
                self.scanner.vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'location': f"Parameter: {vuln['param']}",
                    'example': f"Payload: {vuln['payload']} | Type: {vuln['type']}",
                    'severity': 'High',
                    'solution': 'Implement proper input sanitization and Content Security Policy (CSP)',
                    'references': ['CWE-79', 'OWASP-A3']
                })
            
            if not vulnerable_params:
                print(Fore.GREEN + "[+] No obvious XSS vulnerabilities detected")
                
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error during XSS check: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })