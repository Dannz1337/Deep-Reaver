from core.base import VulnCheck
from colorama import Fore
import re
from urllib.parse import urljoin

class SensitiveDataCheck(VulnCheck):
    def __init__(self, scanner):
        super().__init__(scanner)
        self.whitelist_domains = ['example.com', 'test.com']
        self.plugin_id = 1048576
        self.plugin_name = "Sensitive Information Disclosure Check"
        self.plugin_family = "Web Servers"
        self.plugin_type = "remote"
        self.plugin_version = "1.2"
        self.plugin_modification_date = "2024-01-15"
        self.risk_factor = "High"
        self.cvss_base_score = 7.5
        self.cvss_vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

    def run(self):
        print(Fore.MAGENTA + f"[*] Running plugin {self.plugin_id}: {self.plugin_name}")
        print(Fore.CYAN + "\n[+] Checking for sensitive data exposure...")

        try:
            urls_to_check = [
                self.scanner.base_url,
                urljoin(self.scanner.base_url, "api/"),
                urljoin(self.scanner.base_url, "v1/"),
                urljoin(self.scanner.base_url, "graphql"),
                urljoin(self.scanner.base_url, "rest/"),
                urljoin(self.scanner.base_url, "admin/"),
                urljoin(self.scanner.base_url, "config/"),
                urljoin(self.scanner.base_url, "env"),
                urljoin(self.scanner.base_url, "actuator/env")
            ]

            sensitive_patterns = {
                "Email Address Exposure": {
                    "pattern": r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,6}",
                    "severity": "Medium",
                    "cvss": 5.3,
                    "cwe": "CWE-200",
                    "filter": lambda x: not any(domain in x.lower() for domain in self.whitelist_domains),
                    "description": "Email addresses were found exposed in the application response.",
                    "solution": "Remove email addresses from client-side code and responses."
                },
                # (Pattern lainnya tetap seperti semula...)
            }

            found_data = []

            for url in urls_to_check:
                try:
                    response = self.scanner.session.get(url, verify=False, timeout=15)
                    if response.status_code == 200:
                        content = response.text

                        for data_type, config in sensitive_patterns.items():
                            pattern = config["pattern"]
                            severity = config["severity"]
                            filter_fn = config["filter"]

                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                snippet = match.group(0)
                                if not filter_fn(snippet):
                                    continue
                                if len(snippet) > 100:
                                    snippet = snippet[:100] + "..."
                                found_data.append({
                                    'type': data_type,
                                    'url': url,
                                    'severity': severity,
                                    'cvss': config["cvss"],
                                    'cwe': config["cwe"],
                                    'description': config["description"],
                                    'solution': config["solution"],
                                    'snippet': snippet,
                                    'response_code': response.status_code
                                })
                                print(Fore.RED + f"[!] {data_type} found at {url}: {snippet}")

                        # Enhanced potential secret detection
                        potential_secrets = re.findall(r"[a-zA-Z0-9\-_]{20,}", content)
                        for secret in potential_secrets:
                            lower_secret = secret.lower()
                            false_positive_keywords = [
                                'whatsapp', 'image', 'slug', 'artikel', 'kominfo', 'widget',
                                'header', 'footer', 'lumajang', '.jpg', '.jpeg', '.png', '.gif', '.webp'
                            ]

                            if (
                                len(secret) > 30 and
                                not any(x in lower_secret for x in ['http', 'https', 'www']) and
                                not re.match(r'^[0-9]+$', secret) and
                                not any(d in lower_secret for d in self.whitelist_domains) and
                                not any(fp in lower_secret for fp in false_positive_keywords)
                            ):
                                found_data.append({
                                    'type': 'Potential Secret',
                                    'url': url,
                                    'severity': 'High',
                                    'cvss': 7.5,
                                    'cwe': 'CWE-200',
                                    'description': 'A potential secret or token was found exposed.',
                                    'solution': 'Investigate and remove any exposed secrets.',
                                    'snippet': secret[:50] + "...",
                                    'response_code': response.status_code
                                })
                                print(Fore.RED + f"[!] Potential secret found at {url}: {secret[:50]}...")

                except Exception as e:
                    print(Fore.YELLOW + f"[?] Error checking {url}: {str(e)}")
                    continue

            unique_findings = []
            seen = set()
            for item in found_data:
                key = (item['type'], item['snippet'])
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(item)

            for finding in unique_findings:
                self.scanner.vulnerabilities.append({
                    'plugin_id': self.plugin_id,
                    'plugin_name': self.plugin_name,
                    'plugin_family': self.plugin_family,
                    'type': 'Sensitive Data Exposure',
                    'location': finding['url'],
                    'description': finding['description'],
                    'risk': finding['severity'],
                    'cvss_base_score': finding.get('cvss', self.cvss_base_score),
                    'cvss_vector': self.cvss_vector,
                    'cwe': finding.get('cwe', 'CWE-200'),
                    'evidence': f"{finding['type']} → {finding['snippet']}",
                    'solution': finding['solution'],
                    'references': ['CWE-200', 'OWASP-A3', 'PCI-DSS'],
                    'response_code': finding.get('response_code', 200)
                })

            if not unique_findings:
                print(Fore.GREEN + "[+] No sensitive data exposures detected")
                self.scanner.vulnerabilities.append({
                    'plugin_id': self.plugin_id,
                    'plugin_name': self.plugin_name,
                    'plugin_family': self.plugin_family,
                    'type': 'Sensitive Data Exposure',
                    'location': self.scanner.base_url,
                    'description': 'No sensitive data exposures were detected.',
                    'risk': 'None',
                    'cvss_base_score': 0.0,
                    'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
                    'cwe': 'CWE-200',
                    'evidence': 'No sensitive data patterns found in responses',
                    'solution': 'Continue to follow security best practices for data handling.',
                    'references': ['CWE-200', 'OWASP-A3'],
                    'response_code': 200
                })

        except Exception as e:
            print(Fore.YELLOW + f"[?] Error during sensitive data scan: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'plugin_id': self.plugin_id,
                'error': str(e)
            })
