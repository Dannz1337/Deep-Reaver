from core.base import VulnCheck
from colorama import Fore
from bs4 import BeautifulSoup

class CSRFCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Checking for CSRF protection...")
        
        try:
            response = self.scanner.session.get(self.scanner.base_url, verify=False, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                print(Fore.BLUE + "[i] No forms found on the page")
                return
                
            vulnerable_forms = []
            for form in forms:
                form_id = form.get('id', 'N/A')
                form_action = form.get('action', 'N/A')
                
                csrf_token = (
                    form.find('input', {'name': 'csrf_token'}) or
                    form.find('input', {'name': 'csrfmiddlewaretoken'}) or
                    form.find('input', {'name': '_token'}) or
                    form.find('input', {'name': 'authenticity_token'})
                )
                
                if not csrf_token:
                    vulnerable_forms.append({
                        'form_id': form_id,
                        'action': form_action
                    })
                    print(Fore.RED + f"[!] Form without CSRF token found (ID: {form_id}, Action: {form_action})")
            
            if vulnerable_forms:
                for form in vulnerable_forms:
                    self.scanner.vulnerabilities.append({
                        'type': 'Missing CSRF Protection',
                        'location': f"Form (ID: {form['form_id']}, Action: {form['action']})",
                        'example': "Form submission without CSRF token",
                        'severity': 'High',
                        'solution': 'Implement CSRF tokens in all forms and validate them server-side',
                        'references': ['CWE-352']
                    })
            else:
                print(Fore.GREEN + "[+] All forms appear to have CSRF protection")
                
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error checking CSRF protection: {str(e)}")
            self.scanner.errors.append({
                'module': self.__class__.__name__,
                'error': str(e)
            })