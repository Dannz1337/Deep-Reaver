from core.base import VulnCheck
from colorama import Fore

class CMSDetectCheck(VulnCheck):
    def run(self):
        print(Fore.MAGENTA + "[*] Running module: " + self.__class__.__name__)
        print(Fore.CYAN + "\n[+] Detecting CMS...")

        cms_signatures = {
            "WordPress": ["/wp-login.php", "/wp-content/", "wordpress"],
            "Joomla": ["/administrator/", "joomla"],
            "Drupal": ["/sites/default/", "drupal"],
            "Magento": ["/mage/", "magento"],
            "Laravel": ["/vendor/laravel", "laravel"]
        }

        try:
            resp = self.scanner.session.get(self.scanner.base_url, timeout=10, verify=False)
            html = resp.text.lower()
            detected = []

            for cms, signs in cms_signatures.items():
                if any(sign in html or sign in resp.url.lower() for sign in signs):
                    detected.append(cms)

            if detected:
                for cms in detected:
                    self.scanner.vulnerabilities.append({
                        'type': 'CMS Detection',
                        'location': self.scanner.base_url,
                        'example': f"{cms} detected",
                        'severity': 'Info',
                        'solution': f"Ensure {cms} is up-to-date and unnecessary info is hidden."
                    })
                    print(Fore.YELLOW + f"[!] CMS detected: {cms}")
            else:
                print(Fore.GREEN + "[+] No CMS fingerprint detected.")
        except Exception as e:
            print(Fore.YELLOW + f"[?] Error during CMS detection: {e}")