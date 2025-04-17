from ai_assistant import AIAssistant
import time
import sys
import requests
import urllib3
from urllib.parse import urlparse
from datetime import datetime
from colorama import init, Fore, Back, Style
import pyfiglet
from tqdm import tqdm
from tabulate import tabulate
import logging
import inspect
import os

# Import all your vulnerability check modules
from modules.xss import XSSCheck
from modules.sqli import SQLiCheck
from modules.xxe import XXECheck
from modules.csrf import CSRFCheck
from modules.rce import RCEDetection
from modules.rce_param_check import RCEParamCheck
from modules.file_upload import FileUploadCheck
from modules.open_redirect import OpenRedirectCheck
from modules.clickjacking import ClickjackingCheck
from modules.cors import CORSCheck
from modules.cookie import CookieSecurityCheck
from modules.enumeration import DirectoryFileEnumeration
from modules.brute_force import BruteForceLoginCheck
from modules.waf import WAFCheck
from modules.auth_bypass import AuthBypassCheck
from modules.ssti import SSTICheck
from modules.host_header import HostHeaderInjectionCheck
from modules.jsonp_scan import JSONPCheck
from modules.cms_detect import CMSDetectCheck
from modules.ssrf import SSRFCheck
from modules.lfi_rfi import LFI_RFIDetection
from modules.sensitive_data import SensitiveDataCheck
from modules.cve_check import CVECheck
from core.reporter import Reporter

# Initialize logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class VulnerabilityScanner:
    def __init__(self, target, mode='full', delay=0.5):
        self.target = target
        self.mode = mode
        self.delay = delay
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.base_url = self.get_base_url()
        self.report = {
            'target': self.target,
            'base_url': self.base_url,
            'vulnerabilities': [],
            'scan_summary': {
                'risk_score': 0
            }
        }

    def get_base_url(self):
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'http://' + self.target
        parsed = urlparse(self.target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def add_vulnerability(self, vulnerability_data):
        """Add a vulnerability with proper validation and defaults"""
        required_fields = ['type', 'severity']
        if not all(field in vulnerability_data for field in required_fields):
            logging.warning(f"Invalid vulnerability data: {vulnerability_data}")
            return False

        # Add module source if not present
        if 'module' not in vulnerability_data:
            # Try to get module name from stack trace
            for frame in inspect.stack():
                if 'modules' in frame.filename:
                    module_name = os.path.basename(frame.filename).split('.')[0]
                    vulnerability_data['module'] = module_name
                    break
            else:
                vulnerability_data['module'] = 'Unknown'

        vulnerability_data.setdefault('url', self.base_url)
        vulnerability_data.setdefault('description', 'No description provided')
        vulnerability_data.setdefault('confidence', 'Medium')
        vulnerability_data.setdefault('location', 'Not specified')
        vulnerability_data.setdefault('example', 'Not available')
        vulnerability_data.setdefault('solution', 'No solution provided')
        
        self.vulnerabilities.append(vulnerability_data)
        return True

    def print_banner(self):
        """Print the scanner banner"""
        banner_text = pyfiglet.figlet_format("DeepScan", font="slant")
        print(Fore.CYAN + banner_text)
        print(Fore.YELLOW + " " * 20 + "Hunt Deep. Strike Silent.")
        print(Fore.WHITE + "-" * 80)
        print(Fore.GREEN + f" Target: {self.target}")
        print(Fore.GREEN + f" Mode: {self.mode.upper()}")
        print(Fore.GREEN + f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.WHITE + "-" * 80 + "\n")

    def print_scan_progress(self, module_name, status, message=""):
        """Print formatted scan progress messages"""
        status_colors = {
            "STARTED": Fore.BLUE,
            "RUNNING": Fore.CYAN,
            "COMPLETED": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SKIPPED": Fore.MAGENTA,
            "FOUND": Fore.RED,
            "NOT FOUND": Fore.GREEN
        }
        
        status_text = status_colors.get(status, Fore.WHITE) + f"[{status}]"
        module_text = Fore.MAGENTA + f"{module_name: <30}"
        message_text = Fore.WHITE + message
        
        print(f"{status_text} {module_text} {message_text}")

    def print_summary(self):
        """Print the scan summary with vulnerabilities"""
        print("\n" + Fore.WHITE + "-" * 80)
        print(Fore.CYAN + " SCAN SUMMARY ".center(80, "-"))
        print(Fore.WHITE + "-" * 80)
        
        summary_data = [
            ["Total Vulnerabilities", len(self.vulnerabilities)],
            ["Critical", sum(1 for v in self.vulnerabilities if v.get('severity') == 'Critical')],
            ["High", sum(1 for v in self.vulnerabilities if v.get('severity') == 'High')],
            ["Medium", sum(1 for v in self.vulnerabilities if v.get('severity') == 'Medium')],
            ["Low", sum(1 for v in self.vulnerabilities if v.get('severity') == 'Low')],
            ["Informational", sum(1 for v in self.vulnerabilities if v.get('severity') == 'Info')]
        ]
        
        print(tabulate(summary_data, tablefmt="grid"))
        
        if self.vulnerabilities:
            print("\n" + Fore.CYAN + " TOP FINDINGS ".center(80, "-"))
            top_findings = sorted(
                [v for v in self.vulnerabilities if v.get('severity') in ['Critical', 'High']],
                key=lambda x: {'Critical': 0, 'High': 1}.get(x.get('severity'), 2),
                reverse=False
            )[:5]
            
            if top_findings:
                findings_data = []
                for finding in top_findings:
                    severity = finding.get('severity', 'Unknown')
                    severity_color = Fore.RED if severity == 'Critical' else Fore.YELLOW
                    url = finding.get('url', 'N/A')
                    truncated_url = (url[:47] + '...') if len(url) > 50 else url
                    
                    findings_data.append([
                        severity_color + severity,
                        finding.get('type', 'Unknown'),
                        truncated_url
                    ])
                
                print(tabulate(findings_data, headers=["Severity", "Type", "URL"], tablefmt="grid"))
            else:
                print(Fore.GREEN + "No critical or high severity vulnerabilities found.")
        
        print(Fore.WHITE + "-" * 80 + "\n")

    def run_scan(self):
        """Run the complete vulnerability scan"""
        self.print_banner()
        
        checks = [
            XSSCheck(self), SSTICheck(self), SQLiCheck(self), XXECheck(self),
            CSRFCheck(self), OpenRedirectCheck(self), ClickjackingCheck(self),
            CORSCheck(self), CookieSecurityCheck(self), DirectoryFileEnumeration(self),
            WAFCheck(self), AuthBypassCheck(self), HostHeaderInjectionCheck(self),
            JSONPCheck(self), CMSDetectCheck(self), SSRFCheck(self), RCEParamCheck(self),
            RCEDetection(self), BruteForceLoginCheck(self), FileUploadCheck(self),
            LFI_RFIDetection(self), SensitiveDataCheck(self), CVECheck(self)
        ]

        print(Fore.CYAN + " INITIALIZING SCAN ".center(80, "-") + "\n")
        
        with tqdm(total=len(checks), bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Fore.RESET)) as pbar:
            for check in checks:
                module_name = check.__class__.__name__
                self.print_scan_progress(module_name, "STARTED")
                pbar.set_description(f"Scanning: {module_name}")
                
                try:
                    if self.mode == 'stealth' and hasattr(check, 'is_noisy') and check.is_noisy:
                        self.print_scan_progress(module_name, "SKIPPED", "Skipped in stealth mode")
                        continue
                        
                    check.run()
                    # Count vulnerabilities by module source or type containing module name
                    found = len([v for v in self.vulnerabilities 
                               if v.get('module') == module_name or 
                               any(module_name.lower() in t.lower() 
                                   for t in v.get('type', '').split(','))])
                    
                    if found > 0:
                        self.print_scan_progress(module_name, "FOUND", f"Found {found} vulnerabilities")
                    else:
                        self.print_scan_progress(module_name, "NOT FOUND", "No vulnerabilities detected")
                except Exception as e:
                    self.print_scan_progress(module_name, "ERROR", str(e))
                    logging.error(f"Error in {module_name}: {str(e)}", exc_info=True)
                
                time.sleep(self.delay)
                pbar.update(1)

        self.report['vulnerabilities'] = self.vulnerabilities
        self.report['scan_summary'] = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': sum(1 for v in self.vulnerabilities if v.get('severity') == 'Critical'),
            'high': sum(1 for v in self.vulnerabilities if v.get('severity') == 'High'),
            'medium': sum(1 for v in self.vulnerabilities if v.get('severity') == 'Medium'),
            'low': sum(1 for v in self.vulnerabilities if v.get('severity') == 'Low'),
            'info': sum(1 for v in self.vulnerabilities if v.get('severity') == 'Info'),
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        print("\n" + Fore.CYAN + " ANALYZING RESULTS ".center(80, "-") + "\n")
        self.print_scan_progress("AI Analysis", "RUNNING")
        try:
            ai_analysis = AIAssistant().generate_summary(self.vulnerabilities)
            if ai_analysis:
                self.report['ai_analysis'] = ai_analysis
                self.print_scan_progress("AI Analysis", "COMPLETED", "Analysis added to report")
            else:
                self.print_scan_progress("AI Analysis", "WARNING", "No analysis generated")
        except Exception as e:
            self.print_scan_progress("AI Analysis", "ERROR", str(e))
            logging.error(f"AI Analysis failed: {str(e)}", exc_info=True)

        print("\n" + Fore.CYAN + " GENERATING REPORT ".center(80, "-") + "\n")
        self.print_scan_progress("Report Generator", "RUNNING")
        try:
            Reporter(self).generate_report()
            Reporter(self).save_report()
            self.print_scan_progress("Report Generator", "COMPLETED", "Report saved successfully")
        except Exception as e:
            self.print_scan_progress("Report Generator", "ERROR", str(e))
            logging.error(f"Report generation failed: {str(e)}", exc_info=True)

        self.print_summary()

def print_help():
    """Print help information"""
    help_text = (
        f"{Fore.CYAN}DeepScan Vulnerability Scanner{Fore.RESET}\n\n"
        f"{Fore.YELLOW}Usage:{Fore.RESET}\n"
        "  python3 scanner.py <target> [options]\n\n"
        f"{Fore.YELLOW}Options:{Fore.RESET}\n"
        "  --mode stealth|full    Scan mode (default: full)\n"
        "  --delay SECONDS       Delay between requests (default: 0.5)\n"
        "  --help                Show this help message\n\n"
        f"{Fore.YELLOW}Examples:{Fore.RESET}\n"
        "  python3 scanner.py example.com\n"
        "  python3 scanner.py https://example.com --mode stealth\n"
        "  python3 scanner.py 192.168.1.1 --delay 1.0"
    )
    print(help_text)

if __name__ == "__main__":
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        sys.exit(0)
    
    target = sys.argv[1]
    mode = 'full'
    delay = 0.5
    
    if "--mode" in sys.argv:
        try:
            mode_index = sys.argv.index("--mode") + 1
            mode = sys.argv[mode_index]
        except IndexError:
            print(Fore.RED + "Error: --mode requires an argument (stealth|full)")
            sys.exit(1)
    
    if "--delay" in sys.argv:
        try:
            delay_index = sys.argv.index("--delay") + 1
            delay = float(sys.argv[delay_index])
        except (IndexError, ValueError):
            print(Fore.RED + "Error: --delay requires a numeric argument")
            sys.exit(1)
    
    scanner = VulnerabilityScanner(target, mode=mode, delay=delay)
    scanner.run_scan()