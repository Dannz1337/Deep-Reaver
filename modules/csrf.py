from core.base import VulnCheck
from colorama import Fore
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class CSRFCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for CSRF protection...")
        
        try:
            # Check multiple pages if available
            urls_to_check = [self.scanner.base_url]
            if hasattr(self.scanner, 'test_urls'):
                urls_to_check.extend(self.scanner.test_urls[:3])  # Check up to 3 additional URLs
            
            vulnerable_forms = []
            csrf_protected = False
            
            for url in urls_to_check:
                try:
                    response = self.scanner.session.get(url, verify=False, timeout=15)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    if not forms:
                        print(Fore.BLUE + f"[i] No forms found on {url}")
                        continue
                        
                    for form in forms:
                        form_id = form.get('id', 'N/A')
                        form_action = form.get('action', url)
                        
                        # Check for common CSRF token names
                        csrf_token = (
                            form.find('input', {'name': 'csrf_token'}) or
                            form.find('input', {'name': 'csrfmiddlewaretoken'}) or
                            form.find('input', {'name': '_token'}) or
                            form.find('input', {'name': 'authenticity_token'}) or
                            form.find('input', {'name': 'anticsrf'}) or
                            form.find('input', {'name': '__RequestVerificationToken'})
                        )
                        
                        # Also check for custom headers
                        custom_headers = response.request.headers
                        csrf_header = any(
                            h.lower() in ['x-csrf-token', 'x-xsrf-token', 'x-csrf-protection'] 
                            for h in custom_headers
                        )
                        
                        if csrf_token or csrf_header:
                            csrf_protected = True
                            continue
                            
                        # Skip if form action is external
                        if form_action.startswith(('http://', 'https://')):
                            form_domain = urlparse(form_action).netloc
                            current_domain = urlparse(url).netloc
                            if form_domain != current_domain:
                                print(Fore.BLUE + f"[i] Skipping external form (ID: {form_id}, Action: {form_action})")
                                continue
                        
                        vulnerable_forms.append({
                            'url': url,
                            'form_id': form_id,
                            'action': form_action
                        })
                        print(Fore.RED + f"[!] Form without CSRF protection found at {url} (ID: {form_id}, Action: {form_action})")
                        
                except Exception as e:
                    print(Fore.YELLOW + f"[?] Error checking forms at {url}: {str(e)}")
                    continue
            
            if vulnerable_forms:
                for form in vulnerable_forms:
                    self.scanner.vulnerabilities.append({
                        'type': 'Missing CSRF Protection',
                        'location': f"Form at {form['url']} (ID: {form['form_id']}, Action: {form['action']})",
                        'example': "Form submission without CSRF token or header",
                        'severity': 'High',
                        'solution': 'Implement CSRF tokens in all forms or use SameSite cookies; validate server-side',
                        'references': ['OWASP-010', 'CWE-352']
                    })
            elif csrf_protected:
                print(Fore.GREEN + "[+] All forms appear to have CSRF protection")
            else:
                print(Fore.BLUE + "[i] No forms with CSRF protection requirements found")
                
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking CSRF protection: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })