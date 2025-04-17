from core.base import VulnCheck
from colorama import Fore
import requests
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class FileUploadCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for file upload vulnerabilities...")

        try:
            res = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=15)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form', enctype=re.compile("multipart/form-data", re.IGNORECASE))

            if not forms:
                print(Fore.BLUE + "[i] No file upload forms found")
                return

            for form in forms:
                file_input = form.find('input', {'type': 'file'})
                if not file_input:
                    continue

                action = form.get('action', '')
                method = form.get('method', 'post').lower()
                upload_url = urljoin(self.scanner.base_url, action)

                # Test with various malicious file types
                test_files = [
                    ('shell.php', b'<?php echo "Vulnerable"; ?>', 'application/x-php'),
                    ('test.html', b'<script>alert(1)</script>', 'text/html'),
                    ('test.jpg.php', b'<?php echo "Vulnerable"; ?>', 'image/jpeg'),
                    ('test.php%00.jpg', b'<?php echo "Vulnerable"; ?>', 'image/jpeg')
                ]

                form_data = {}
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    if name and input_tag.get('type') != 'file':
                        form_data[name] = input_tag.get('value', 'test')

                for filename, content, content_type in test_files:
                    test_file = {'file': (filename, content, content_type)}
                    
                    try:
                        if method == 'get':
                            response = self.scanner.session.get(upload_url, params=form_data, files=test_file, verify=False, timeout=15)
                        else:
                            response = self.scanner.session.post(upload_url, data=form_data, files=test_file, verify=False, timeout=15)

                        # Check response for successful upload indicators
                        if response.status_code in [200, 201, 202]:
                            # Try to locate the uploaded file
                            potential_paths = [
                                urljoin(upload_url, filename),
                                urljoin(self.scanner.base_url, 'uploads/' + filename),
                                urljoin(self.scanner.base_url, filename),
                                urljoin(response.url, filename)
                            ]

                            for path in potential_paths:
                                try:
                                    check = self.scanner.session.get(path, verify=False, timeout=10)
                                    if "Vulnerable" in check.text or "<script>alert(1)" in check.text:
                                        self.scanner.vulnerabilities.append({
                                            'type': 'Unrestricted File Upload',
                                            'location': upload_url,
                                            'example': f"Uploaded {filename} accessible at: {path}",
                                            'severity': 'Critical',
                                            'solution': 'Restrict file types, validate content server-side, use random filenames, and store outside webroot',
                                            'references': ['CWE-434', 'OWASP-A1']
                                        })
                                        print(Fore.RED + f"[!] File upload vulnerability found: {filename} accessible at {path}")
                                        return
                                except:
                                    continue

                    except Exception as e:
                        print(Fore.YELLOW + f"[?] Error testing file upload with {filename}: {str(e)}")

            print(Fore.GREEN + "[+] No obvious file upload vulnerabilities detected")

        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking file upload: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })