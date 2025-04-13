# vuln_modules/a06_vulnerable_components/assessment.py
import json
import re
import requests
import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from pathlib import Path
from colors import Colors
from .payloads import VulnerableComponentsPayloads

class VulnerableComponentsAssessment:
    def __init__(self):
        self.payload_size = "medium"
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Technology Detection",
                "description": "Identify technologies and check for outdated versions",
                "function": self.assess_technologies
            },
            "2": {
                "id": "2",
                "name": "Vulnerable Endpoints",
                "description": "Scan for exposed and vulnerable endpoints",
                "function": self.assess_endpoints
            },
            "3": {
                "id": "3",
                "name": "Comprehensive Scan",
                "description": "Run both technology detection and endpoint scanning",
                "function": self.assess_comprehensive
            }
        }
        self.results = []
        self.target = None
        self.verbose = False
        self.current_technique = None
        self.NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:/a:{}:{}"
        self.EXPLOIT_DB_URL = "https://www.exploit-db.com/search?cve={}"

    def set_payload_size(self, size):
        """Set the payload size (small, medium, large)"""
        self.payload_size = size.lower()
        if self.payload_size not in ["small", "medium", "large"]:
            self.payload_size = "medium"

    def show_techniques(self):
        """Display available techniques in a numbered list"""
        print(Colors.header("\nAvailable Techniques for A06:2021 - Vulnerable and Outdated Components:"))
        for tech_id, tech in sorted(self.techniques.items()):
            print(f" {Colors.success(tech_id)}.{tech['name']}")
        print()
        return True

    def get_techniques(self):
        """Return available techniques (compatibility method)"""
        return [f"{tech['id']}. {tech['name']}" for tech in self.techniques.values()]

    def use_technique(self, technique_id):
        """Select a technique to use"""
        if technique_id in self.techniques:
            self.current_technique = self.techniques[technique_id]
            print(Colors.success(f"\nSelected technique: {self.current_technique['name']}"))
            return True
        else:
            print(Colors.error(f"\nInvalid technique ID: {technique_id}"))
            return False

    def run_assessment(self, target, verbose=False, technique_id=None):
        """Run the specified assessment technique with multiple calling conventions"""
        # Handle both calling conventions:
        # 1. Framework calling with technique_id parameter
        # 2. Direct calling after use_technique()
        if technique_id:
            if technique_id not in self.techniques:
                print(Colors.error(f"Invalid technique ID: {technique_id}"))
                return
            self.current_technique = self.techniques[technique_id]
        
        if not self.current_technique:
            print(Colors.error("No technique selected. Use 'use <id>' first."))
            return

        self.target = target
        self.verbose = verbose
        
        # Print scan header
        print(Colors.header("\n" + "-" * 50))
        print(Colors.header(f" Running: {self.current_technique['name']}"))
        print(Colors.header(f" Target: {self.target}"))
        print(Colors.header(f" Payload size: {self.payload_size.capitalize()}"))
        print(Colors.header("-" * 50 + "\n"))

        try:
            self.current_technique["function"]()
            self._generate_report()
            
            save_report = input(Colors.prompt("\nSave Report? (y/n): ")).lower()
            if save_report in ['y', 'yes']:
                self.save_report_to_file()
                
        except Exception as e:
            print(Colors.error(f"\n[!] Assessment failed: {e}"))

    # ... [rest of the methods remain exactly the same as in previous version] ...

    def _make_request(self, url):
        """Helper method to make HTTP requests"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            return response.text, response.headers
        except requests.RequestException as e:
            if self.verbose:
                print(Colors.error(f"Request failed to {url}: {e}"))
            return None, None

    def _update_progress(self, current, total, message=""):
        """Display enhanced progress bar"""
        progress = int((current / total) * 100)
        filled = int(progress/5)
        bar = f"[{'#' * filled}{'-' * (20 - filled)}]"
        color = Colors.success if progress == 100 else Colors.info
        print(f"\r{color(f'{message} {bar} {progress}% Completed')}", end="")
        if current == total:
            print()

    def assess_technologies(self):
        """Detect technologies and check for outdated versions"""
        print(Colors.header("\n🔍 Scanning for technologies and versions..."))
        
        html_content, headers = self._make_request(self.target)
        if not html_content:
            return

        soup = BeautifulSoup(html_content, 'html.parser')
        tech_signatures = VulnerableComponentsPayloads.get_tech_signatures()
        total_tech = len(tech_signatures)
        
        for i, (tech, info) in enumerate(tech_signatures.items(), 1):
            version = None
            
            # Check in headers if specified
            if "header" in info:
                header_value = headers.get(info["header"], "")
                match = re.search(info["pattern"], header_value)
                if match:
                    version = match.group(1)
            
            # Check in HTML content
            if not version and "pattern" in info:
                match = re.search(info["pattern"], html_content)
                if match:
                    version = match.group(1)
            
            # Check specific URLs if needed
            if not version and "check_url" in info and info["check_url"]:
                sub_page, _ = self._make_request(urljoin(self.target, info["check_url"]))
                if sub_page and "version_pattern" in info:
                    match = re.search(info["version_pattern"], sub_page)
                    if match:
                        version = match.group(1)
            
            if version:
                cves = self._fetch_cve_data(tech.lower(), version)
                finding = {
                    "type": "Technology Detection",
                    "name": tech,
                    "version": version,
                    "cve_count": len(cves),
                    "severity": "High" if cves else "Low",
                    "cves": cves[:3]  # Store top 3 CVEs
                }
                self.results.append(finding)
            
            self._update_progress(i, total_tech, "Scanning technologies")

    def assess_endpoints(self):
        """Check for vulnerable endpoints"""
        print(Colors.header("\n🔍 Scanning for vulnerable endpoints..."))
        
        endpoints = VulnerableComponentsPayloads.get_endpoints(self.payload_size)
        total_endpoints = len(endpoints)
        
        for i, endpoint in enumerate(endpoints, 1):
            url = urljoin(self.target, endpoint)
            content, headers = self._make_request(url)
            
            if content or headers:
                status = "Found"
                if "Server" in headers:
                    status += f" (Server: {headers['Server']})"
                
                self.results.append({
                    "type": "Exposed Endpoint",
                    "name": endpoint,
                    "version": "N/A",
                    "severity": self._get_endpoint_severity(endpoint),
                    "status": status,
                    "url": url
                })
            
            self._update_progress(i, total_endpoints, "Checking endpoints")

    def assess_comprehensive(self):
        """Run both technology and endpoint scanning"""
        self.assess_technologies()
        self.assess_endpoints()

    def _fetch_cve_data(self, product, version):
        """Fetch CVE data from NVD database"""
        try:
            response = requests.get(self.NVD_API_URL.format(product, version), timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("result", {}).get("CVE_Items", [])
                return [
                    {
                        "id": vuln["cve"]["CVE_data_meta"]["ID"],
                        "description": vuln["cve"]["description"]["description_data"][0]["value"],
                        "severity": vuln["impact"].get("baseMetricV2", {}).get("severity", "UNKNOWN"),
                        "exploit_url": self.EXPLOIT_DB_URL.format(vuln["cve"]["CVE_data_meta"]["ID"])
                    }
                    for vuln in vulnerabilities[:3]  # Get top 3 CVEs
                ]
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"Error fetching CVEs: {e}"))
        return []

    def _get_endpoint_severity(self, endpoint):
        """Determine severity based on endpoint"""
        if endpoint in ['/.env', '/.git/', '/.aws/credentials']:
            return "Critical"
        elif endpoint in ['/phpmyadmin/', '/admin/', '/wp-admin/']:
            return "High"
        return "Medium"

    def _generate_report(self):
        """Generate a professional formatted report without recommendations"""
        if not self.results:
            print(Colors.success("\n✅ No vulnerabilities found!"))
            return
            
        # Categorize findings by type and severity
        tech_findings = [f for f in self.results if f["type"] == "Technology Detection"]
        endpoint_findings = [f for f in self.results if f["type"] == "Exposed Endpoint"]
        
        critical_findings = [f for f in endpoint_findings if f["severity"] == "Critical"]
        high_findings = [f for f in endpoint_findings if f["severity"] == "High"]
        medium_findings = [f for f in endpoint_findings if f["severity"] == "Medium"]
        low_findings = tech_findings  # Technology findings are considered Low severity

        # Print scan summary
        print(Colors.header("\nSCAN SUMMARY"))
        print(Colors.header("-" * 50))
        print(f" Target: {Colors.info(self.target)}")
        print(f" Total Findings: {Colors.info(len(self.results))}")
        print(f" - Critical: {Colors.error(len(critical_findings))}")
        print(f" - High: {Colors.error(len(high_findings))}")
        print(f" - Medium: {Colors.warning(len(medium_findings))}")
        print(f" - Low: {Colors.success(len(low_findings))}")
        print(Colors.header("-" * 50))

        # Print Critical Findings
        if critical_findings:
            print(Colors.error("\nCRITICAL FINDINGS"))
            print(Colors.error("-" * 50))
            for finding in critical_findings:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Severity: {Colors.error(finding['severity'])}\n")

        # Print High-Risk Findings
        if high_findings:
            print(Colors.error("\nHIGH-RISK FINDINGS"))
            print(Colors.error("-" * 50))
            for finding in high_findings:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Severity: {Colors.error(finding['severity'])}\n")

        # Print Medium Findings
        if medium_findings:
            print(Colors.warning("\nMEDIUM-RISK FINDINGS"))
            print(Colors.warning("-" * 50))
            for finding in medium_findings:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Severity: {Colors.warning(finding['severity'])}\n")

        # Print Technology Findings
        if tech_findings:
            print(Colors.info("\nTECHNOLOGY FINDINGS"))
            print(Colors.info("-" * 50))
            for finding in tech_findings:
                print(f" {finding['name']} {finding['version']}")
                print(f"   Severity: {Colors.info(finding['severity'])}")
                if finding.get('cves'):
                    print(f"   Known CVEs: {len(finding['cves'])}\n")

    def save_report_to_file(self):
        """Save the report to a JSON file"""
        if not self.results:
            print(Colors.error("No findings to save in report"))
            return
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_report_{timestamp}.json"
        
        report_data = {
            "scan_date": timestamp,
            "target": self.target,
            "payload_size": self.payload_size,
            "findings": self.results,
            "summary": {
                "total_findings": len(self.results),
                "critical_count": sum(1 for f in self.results if f["severity"] == "Critical"),
                "high_count": sum(1 for f in self.results if f["severity"] == "High"),
                "medium_count": sum(1 for f in self.results if f["severity"] == "Medium"),
                "low_count": sum(1 for f in self.results if f["severity"] == "Low")
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(Colors.success(f"\n✅ Report saved to {filename}"))
        except Exception as e:
            print(Colors.error(f"\n❌ Failed to save report: {e}"))