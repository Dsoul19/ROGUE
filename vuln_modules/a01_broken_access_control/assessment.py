# vuln_modules/a01_broken_access_control/assessment.py
import requests
from urllib.parse import urljoin
import logging
from bs4 import BeautifulSoup
from datetime import datetime
import json
import os
from typing import List
from colors import Colors
from .payloads import BrokenAccessControlPayloads

# Configure logging
# LOG_FILE = 'broken_access_control.log'
# if os.path.exists(LOG_FILE):
#     try:
#         os.remove(LOG_FILE)
#     except Exception as e:
#         print(Colors.error(f"[!] Failed to remove old log file: {e}"))

# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler(LOG_FILE),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger(__name__)

class BrokenAccessControlAssessment:
    def __init__(self):
        self.name = "Broken Access Control Assessment"
        self.techniques = {
            "1": {
                "id": "1",
                "name": "General Access Control Checks",
                "function": self.assess_general_access,
                "description": "Tests for common access control misconfigurations"
            },
            "2": {
                "id": "2",
                "name": "Insecure Direct Object References (IDOR)",
                "function": self.assess_idor,
                "description": "Tests for unauthorized access to resources via object references"
            },
            "3": {
                "id": "3",
                "name": "Privilege Escalation (Forced Browsing)",
                "function": self.assess_privilege_forced,
                "description": "Tests for vertical privilege escalation vulnerabilities"
            }
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) RogueSecurityScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate'
        })
        self.findings = []
        self.start_time = None
        self.payload_size = "medium"
        self.payloads = BrokenAccessControlPayloads()  # Initialize payloads instance
        self.current_payloads = self.payloads.PAYLOADS.get(self.payload_size, self.payloads.PAYLOADS["medium"])

    def get_techniques(self) -> List[str]:
        """Return available assessment technique names with IDs"""
        return [f"{id}. {tech['name']}" for id, tech in self.techniques.items()]

    def set_payload_size(self, size: str) -> bool:
        """Set the payload size to use for scans"""
        valid_sizes = ["small", "medium", "large"]
        if size.lower() in valid_sizes:
            self.payload_size = size.lower()
            self.current_payloads = self.payloads.PAYLOADS.get(self.payload_size, self.payloads.PAYLOADS["medium"])
            return True
        return False

    def run_assessment(self, technique_id: str, target: str, verbose: bool = False) -> None:
        """Run the selected assessment technique"""
        if technique_id not in [tech['id'] for tech in self.techniques.values()]:
            raise ValueError(f"Invalid technique ID: {technique_id}")

        technique = next(tech for tech in self.techniques.values() if tech['id'] == technique_id)
        self.start_time = datetime.now()
        self.findings = []
        
        print(Colors.header(f"\n[+] Starting {technique['name']} assessment on {target}"))
        print(Colors.info(f"[~] Payload size: {self.payload_size}"))
        # logger.info(f"Starting {technique['name']} assessment on {target} with {self.payload_size} payloads")
        
        try:
            technique["function"](target, verbose)
            
            if self.findings:
                print(Colors.error(f"\n[!] Found {len(self.findings)} potential vulnerabilities!"))
            else:
                print(Colors.success("\n[√] No vulnerabilities found"))
            
            if self._prompt_for_report():
                self._generate_report(target, technique['name'])
                
        except Exception as e:
            # logger.error(f"Assessment failed: {str(e)}", exc_info=True)
            print(Colors.error(f"\n[!] Assessment failed: {str(e)}"))
        finally:
            self.session.close()


    def assess_general_access(self, target: str, verbose: bool) -> None:
        """Check for general access control vulnerabilities"""
        print(Colors.info("\n[~] Checking for General Access Control Issues..."))
        # logger.info("Starting General Access Control checks")
        
        total_tests = len(self.current_payloads["admin_paths"]) + len(self.current_payloads.get("sensitive_paths", []))
        completed_tests = 0
        
        # Test admin paths
        for path in self.current_payloads["admin_paths"]:
            completed_tests += 1
            self._update_progress(completed_tests, total_tests)
            
            url = urljoin(target, path)
            if verbose:
                print(Colors.subtle(f"  Testing: {url}"))
                
            try:
                response = self.session.get(url, timeout=10)
                self._analyze_response(response, "Admin Access", url)
            except requests.RequestException as e:
                # logger.warning(f"Request failed for {url}: {str(e)}")
                if verbose:
                    print(Colors.error(f"  [!] Failed: {str(e)}"))
        
        # Test sensitive paths if available
        if "sensitive_paths" in self.current_payloads:
            for path in self.current_payloads["sensitive_paths"]:
                completed_tests += 1
                self._update_progress(completed_tests, total_tests)
                
                url = urljoin(target, path)
                if verbose:
                    print(Colors.subtle(f"  Testing: {url}"))
                    
                try:
                    response = self.session.get(url, timeout=10)
                    self._analyze_response(response, "Sensitive File Access", url)
                except requests.RequestException as e:
                    # logger.warning(f"Request failed for {url}: {str(e)}")
                    if verbose:
                        print(Colors.error(f"  [!] Failed: {str(e)}"))

        print(Colors.success("\n[√] General access control checks completed"))

    def assess_idor(self, target: str, verbose: bool) -> None:
        """Check for Insecure Direct Object References"""
        print(Colors.info("\n[~] Checking for IDOR Vulnerabilities..."))
        # logger.info("Starting IDOR checks")
        
        base_url = target.rstrip('/')
        total_tests = len(self.current_payloads["idor_params"])
        completed_tests = 0
        
        for param in self.current_payloads["idor_params"]:
            completed_tests += 1
            self._update_progress(completed_tests, total_tests)
            
            test_url = f"{base_url}/api/data?{param}" if "api" not in base_url else f"{base_url}?{param}"
            
            if verbose:
                print(Colors.subtle(f"  Testing: {test_url}"))
                
            try:
                response = self.session.get(test_url, timeout=10)
                self._analyze_response(response, "IDOR", test_url, f"Testing parameter: {param}")
            except requests.RequestException as e:
                # logger.warning(f"Request failed for {test_url}: {str(e)}")
                if verbose:
                    print(Colors.error(f"  [!] Failed: {str(e)}"))

        print(Colors.success("\n[√] IDOR checks completed"))

    def assess_privilege_forced(self, target: str, verbose: bool) -> None:
        """Check for privilege escalation via forced browsing"""
        print(Colors.info("\n[~] Checking for Privilege Escalation..."))
        # logger.info("Starting Privilege Escalation checks")
        
        if "privileged_actions" not in self.current_payloads:
            print(Colors.error("  [!] Privileged actions not available in current payload size"))
            return
            
        total_tests = len(self.current_payloads["privileged_actions"])
        completed_tests = 0
        
        for action in self.current_payloads["privileged_actions"]:
            completed_tests += 1
            self._update_progress(completed_tests, total_tests)
            
            url = urljoin(target, action)
            if verbose:
                print(Colors.subtle(f"  Testing: {url}"))
                
            try:
                response_get = self.session.get(url, timeout=10)
                self._analyze_response(response_get, "Privilege Escalation (GET)", url)
                
                response_post = self.session.post(url, data={"test": "payload"}, timeout=10)
                self._analyze_response(response_post, "Privilege Escalation (POST)", url)
            except requests.RequestException as e:
                # logger.warning(f"Request failed for {url}: {str(e)}")
                if verbose:
                    print(Colors.error(f"  [!] Failed: {str(e)}"))

        print(Colors.success("\n[√] Privilege escalation checks completed"))

    def _analyze_response(self, response: requests.Response, vulnerability_type: str, 
                         tested_url: str, description: str = "") -> None:
        """Analyze HTTP response for potential vulnerabilities"""
        status_code = response.status_code
        
        if 200 <= status_code < 300:
            content_type = response.headers.get('Content-Type', '')
            
            if any(ct in content_type for ct in ['image/', 'video/', 'audio/', 'font/']):
                return
                
            error_phrases = ['access denied', 'not authorized', 'login required', '403 forbidden']
            page_text = response.text.lower()
            
            if not any(phrase in page_text for phrase in error_phrases):
                finding = {
                    "type": vulnerability_type,
                    "url": tested_url,
                    "description": description,
                    "status_code": status_code,
                    "severity": "High",
                    "evidence": f"Unauthorized access (Status: {status_code})",
                    "timestamp": datetime.now().isoformat(),
                    "response_size": len(response.content),
                    "content_type": content_type
                }
                
                if 'text/html' in content_type:
                    try:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        if soup.title:
                            finding["page_title"] = soup.title.string
                    except:
                        pass
                
                self.findings.append(finding)
                # logger.warning(f"Potential {vulnerability_type} at {tested_url}")
                print(Colors.error(f"  [!] Potential {vulnerability_type} at {tested_url} (Status: {status_code})"))

    def _update_progress(self, current: int, total: int) -> None:
        """Update and display progress"""
        percent = (current / total) * 100
        print(f"\r{Colors.info('[~] Progress:')} {percent:.1f}% ({current}/{total})", end='', flush=True)

    def _prompt_for_report(self) -> bool:
        """Ask user if they want to generate a report"""
        print("\n")
        response = input(Colors.prompt("[?] Generate report? (y/n): ")).strip().lower()
        return response in ['y', 'yes']

    def _generate_report(self, target: str, technique: str) -> None:
        """Generate assessment report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"a01_broken_access_{technique.lower().replace(' ', '_')}_{timestamp}.json"
        
        report = {
            "metadata": {
                "assessment": "Broken Access Control",
                "technique": technique,
                "target": target,
                "payload_size": self.payload_size,
                "start_time": self.start_time.isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "scanner": "ROGUE Security Scanner"
            },
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "high_severity": sum(1 for f in self.findings if f['severity'] == "High"),
                "medium_severity": sum(1 for f in self.findings if f['severity'] == "Medium"),
                "low_severity": sum(1 for f in self.findings if f['severity'] == "Low")
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(Colors.success(f"\n[√] Report saved to {filename}"))
        
        print(Colors.header("\n[+] Assessment Summary:"))
        print(f"  Target: {target}")
        print(f"  Technique: {technique}")
        print(f"  Payload size: {self.payload_size}")
        print(f"  Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds")
        print(f"  Findings: {Colors.error(str(len(self.findings)))} total")
        print(f"    High severity: {Colors.error(str(report['summary']['high_severity']))}")
        
        if self.findings:
            print(Colors.header("\n[+] Critical Findings:"))
            for finding in self.findings:
                print(f"  {Colors.error('➜')} {finding['type']}")
                print(f"    URL: {finding['url']}")
                print(f"    Status: {finding['status_code']} | Severity: {finding['severity']}")
                if finding.get('description'):
                    print(f"    Description: {finding['description']}")
                print(f"    Evidence: {finding['evidence']}\n")