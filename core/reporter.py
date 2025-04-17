from datetime import datetime
import json
from colorama import Fore
from urllib.parse import urlparse

class Reporter:
    def __init__(self, scanner):
        self.scanner = scanner

    def generate_report(self):
        report = self.scanner.report
        print("\n" + "="*50)
        print(Fore.YELLOW + "VULNERABILITY SCAN REPORT")
        print("="*50)
        print(Fore.CYAN + f"Target: {report['target']}")
        print(Fore.CYAN + f"Base URL: {report['base_url']}")
        print(Fore.CYAN + f"Scan Time: {report['scan_summary']['scan_time']}")
        print("-"*50)
        print(Fore.RED + f"Critical: {report['scan_summary']['critical']}")
        print(Fore.YELLOW + f"High: {report['scan_summary']['high']}")
        print(Fore.BLUE + f"Medium: {report['scan_summary']['medium']}")
        print(Fore.GREEN + f"Low: {report['scan_summary']['low']}")
        print(Fore.WHITE + f"Info: {report['scan_summary']['info']}")
        print("="*50 + "\n")

        if report['vulnerabilities']:
            print(Fore.YELLOW + "DETAILED FINDINGS:")
            for vuln in report['vulnerabilities']:
                print("\n" + "-"*50)
                severity = vuln.get('severity', 'Unknown').upper()
                vuln_type = vuln.get('type', 'Unknown vulnerability')
                print(Fore.RED + f"[{severity}] {vuln_type}")
                print(Fore.CYAN + f"Location: {vuln.get('location', 'Not specified')}")
                print(Fore.WHITE + f"Example: {vuln.get('example', 'Not available')}")
                print(Fore.GREEN + f"Solution: {vuln.get('solution', 'No solution provided')}")
        else:
            print(Fore.GREEN + "No vulnerabilities found!")

    def save_report(self):
        report = self.scanner.report
        if not report['vulnerabilities']:
            return
        filename = f"vuln_scan_{urlparse(self.scanner.base_url).hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            print(Fore.CYAN + f"Report saved to {filename}")
        except Exception as e:
            print(Fore.RED + f"Error saving report: {str(e)}")