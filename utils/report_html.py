import json
from datetime import datetime

def generate_html_report(json_path, output_path="report.html"):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    target = data.get("target", "")
    base_url = data.get("base_url", "")
    summary = data.get("scan_summary", {})
    vulns = data.get("vulnerabilities", [])

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .critical {{ background-color: #f44336; color: white; }}
        .high {{ background-color: #ff9800; color: white; }}
        .medium {{ background-color: #ffeb3b; color: black; }}
        .low {{ background-color: #8bc34a; color: white; }}
        .info {{ background-color: #2196f3; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Base URL:</strong> {base_url}</p>
    <p><strong>Scan Time:</strong> {summary.get("scan_time", "")}</p>
    <p><strong>Total Vulnerabilities:</strong> {summary.get("total_vulnerabilities", 0)} | 
       <strong>Risk Score:</strong> {summary.get("risk_score", 0)}</p>
    <ul>
        <li>Critical: {summary.get("critical", 0)}</li>
        <li>High: {summary.get("high", 0)}</li>
        <li>Medium: {summary.get("medium", 0)}</li>
        <li>Low: {summary.get("low", 0)}</li>
        <li>Info: {summary.get("info", 0)}</li>
    </ul>
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Location</th>
            <th>Example</th>
            <th>Severity</th>
            <th>Solution</th>
        </tr>"""

    for vuln in vulns:
        severity_class = vuln["severity"].lower()
        html += f"""
        <tr class="{severity_class}">
            <td>{vuln["type"]}</td>
            <td>{vuln["location"]}</td>
            <td>{vuln["example"]}</td>
            <td>{vuln["severity"]}</td>
            <td>{vuln["solution"]}</td>
        </tr>"""

    html += """
    </table>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
