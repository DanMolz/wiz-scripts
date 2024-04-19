import sys
import json
from prettytable import PrettyTable
from colorama import Fore, Style

def sort_key(vulnerability):
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return severity_order.get(vulnerability['severity'], 99)

def print_vulnerability_summary(severity_totals):
    print("\nWiz Vulnerability Summary:")
    for severity, count in severity_totals.items():
        severity_color = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.YELLOW,
            "MEDIUM": Fore.CYAN,
            "LOW": Fore.GREEN,
            "INFORMATIONAL": Fore.MAGENTA,
        }.get(severity, Fore.WHITE)
        print(f"{severity_color}{severity} Count: {count}{Style.RESET_ALL}")

# Check if JSON data is provided as a command-line argument
if len(sys.argv) != 2:
    print("Usage: python wiz-scan-summary.py <json_data>")
    sys.exit(1)

json_data = sys.argv[1]

try:
    data = json.loads(json_data)
except json.JSONDecodeError as e:
    print(f"Error decoding JSON: {e}")
    sys.exit(1)

os_packages = data['result']['osPackages']

column_widths = {"Package": 0, "Package Version": 0, "Vulnerability": 0, "Severity": 0,
                 "Fixed Version": 0, "Source": 0, "CVSS Score": 0, "CVSS Exploitability Score": 0}

for package in os_packages:
    for vulnerability in package['vulnerabilities']:
        column_widths["Package"] = max(
            column_widths["Package"], len(package['name']))
        column_widths["Package Version"] = max(
            column_widths["Package Version"], len(str(package.get('version', ''))))
        column_widths["Vulnerability"] = max(
            column_widths["Vulnerability"], len(vulnerability['name']))
        column_widths["Severity"] = max(
            column_widths["Severity"], len(vulnerability['severity']))
        column_widths["Fixed Version"] = max(column_widths["Fixed Version"], len(
            str(vulnerability.get('fixedVersion', ''))))
        column_widths["Source"] = max(
            column_widths["Source"], len(vulnerability['source']))
        column_widths["CVSS Score"] = max(column_widths["CVSS Score"], 10)
        column_widths["CVSS Exploitability Score"] = max(
            column_widths["CVSS Exploitability Score"], 25)

table = PrettyTable()
table.field_names = ["Package", "Package Version", "Vulnerability",
                     "Severity", "Fixed Version", "Source", "CVSS Score", "CVSS Exploitability Score"]

for index, package in enumerate(os_packages):
    if index > 0:
        table.add_row(["-" * (width + 2) for width in column_widths.values()])
    table.add_row(
        [package['name'], f"{package.get('version', 'N/A')}", "", "", "", "", "", ""])

    vulnerabilities = sorted(package['vulnerabilities'], key=sort_key)
    for vulnerability in vulnerabilities:
        severity_color = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.YELLOW,
            "MEDIUM": Fore.CYAN,
            "LOW": Fore.GREEN,
            "INFORMATIONAL": Fore.MAGENTA,
        }.get(vulnerability['severity'], Fore.WHITE)

        fixed_version = vulnerability.get('fixedVersion', 'N/A')
        exploitability_score = vulnerability.get('exploitabilityScore', 'N/A')

        table.add_row([
            "", "", vulnerability['name'],
            f"{severity_color}{vulnerability['severity']}{Style.RESET_ALL}",
            fixed_version, vulnerability['source'], vulnerability['score'],
            exploitability_score
        ])

print(table)

severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
for package in os_packages:
    for vulnerability in package['vulnerabilities']:
      if vulnerability['severity'] in severity_totals:
        severity_totals[vulnerability['severity']] += 1

print_vulnerability_summary(severity_totals)

url = data.get('reportUrl', 'N/A')
link_html = f'"{url}"'
print("\nWiz Report URL:")
print(link_html)
