import json
import time
import requests
import re
from colors import Colors
from .payloads import SSRFPayloads

class SSRFAssessment:
    """Advanced SSRF vulnerability assessment module for ROGUE framework"""
    
    def __init__(self):
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Standard SSRF Tests",
                "description": "Basic SSRF, Cloud Metadata, and Protocol Handlers",
                "payload_categories": ["basic", "cloud_metadata", "protocols"]
            },
            "2": {
                "id": "2",
                "name": "Advanced SSRF Vectors", 
                "description": "Header Injection, Encoded Payloads, and API SSRF",
                "payload_categories": ["headers", "encoding", "graphql"]
            },
            "3": {
                "id": "3",
                "name": "Blind SSRF Detection",
                "description": "Out-of-Band (OOB) and Advanced Exploitation",
                "payload_categories": ["oob", "advanced"]
            }
        }
        self.payload_size = "medium"
        self.findings = []
        self.unique_hashes = set()
        self.target = None
        self.verbose = False

        # Response analysis patterns
        self.detection_patterns = {
            "local_ips": re.compile(r'(127\.|0\.|localhost|::1|0x7f|0177|2130706433)', re.I),
            "cloud_metadata": re.compile(r'(169\.254\.169\.254|metadata\.google|metadata\.nic)', re.I),
            "sensitive_data": re.compile(r'(root:|admin:|password:|secret_key|aws_access)', re.I),
            "error_leakage": re.compile(r'(error|exception|traceback|failed to connect)', re.I)
        }

    def get_techniques(self):
        """Return available techniques"""
        return [f"{tech['id']} - {tech['name']}" for tech in self.techniques.values()]

    def set_payload_size(self, size):
        """Set payload size (small, medium, large)"""
        if size.lower() in ["small", "medium", "large"]:
            self.payload_size = size.lower()
            return True
        return False

    def run_assessment(self, technique_id, target, verbose=False):
        """Execute the selected SSRF assessment technique"""
        if technique_id not in self.techniques:
            print(Colors.error(f"[!] Invalid technique ID: {technique_id}"))
            return False

        self.target = target.rstrip('/')
        self.verbose = verbose
        technique = self.techniques[technique_id]
        
        print(Colors.header(f"\n[*] Starting {technique['name']}"))
        print(Colors.info(f"[*] Target: {self.target}"))
        print(Colors.info(f"[*] Payload Size: {self.payload_size.title()}"))
        
        try:
            for category in technique["payload_categories"]:
                self._test_payload_category(category)
                
            self._report_findings()
            self._prompt_save_report()
            return True
            
        except Exception as e:
            print(Colors.error(f"[!] Assessment failed: {str(e)}"))
            return False

    def _test_payload_category(self, category):
        """Test all payloads in a specific category"""
        payloads = SSRFPayloads.PAYLOADS[self.payload_size].get(category, [])
        
        if not payloads:
            if self.verbose:
                print(Colors.warning(f"[!] No payloads for category: {category}"))
            return

        total = len(payloads)
        print(Colors.info(f"\n[*] Testing {total} {category.replace('_', ' ')} payloads"))
        
        for i, payload in enumerate(payloads, 1):
            if self.verbose:
                print(Colors.subtle(f"  Trying: {str(payload)[:100]}..."))
                
            print(f"\r[*] Progress: [{(i / total) * 100:.1f}%] ({i}/{total})", end="")
            
            try:
                if category == "headers":
                    self._test_header_payload(payload)
                elif category == "oob":
                    self._test_oob_payload(payload)
                elif category == "graphql":
                    self._test_graphql_payload(payload)
                else:
                    self._test_standard_payload(payload, category)
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(Colors.error(f"\n[!] Request failed: {str(e)}"))
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"\n[!] Error: {str(e)}"))

        print("\n" + Colors.success(f"[+] {category.replace('_', ' ')} testing complete"))

    def _test_standard_payload(self, payload, category):
        """Test standard GET/POST payloads"""
        params = {"url": payload} if category in ["basic", "cloud_metadata"] else {}
        
        res = requests.get(
            self.target,
            params=params,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        
        self._analyze_response(res, payload, category)

    def _test_header_payload(self, headers):
        """Test header-based SSRF payloads"""
        res = requests.get(
            self.target,
            headers=headers,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        self._analyze_response(res, str(headers), "header")

    def _test_graphql_payload(self, payload):
        """Test GraphQL API SSRF payloads"""
        headers = {"Content-Type": "application/json"}
        res = requests.post(
            self.target,
            data=payload,
            headers=headers,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        self._analyze_response(res, payload, "graphql")

    def _test_oob_payload(self, payload):
        """Test out-of-band SSRF payloads (simulated)"""
        try:
            requests.get(
                self.target,
                params={"url": payload},
                timeout=3  # Short timeout for OOB
            )
            finding = {
                "type": "Potential Blind SSRF",
                "payload": payload,
                "severity": "High",
                "description": "OOB payload triggered - requires manual verification",
                "confidence": "Low"
            }
            self._add_finding(finding)
        except requests.exceptions.Timeout:
            pass  # Expected for OOB
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"\n[!] OOB test error: {str(e)}"))

    def _analyze_response(self, response, payload, category):
        """Analyze server response for SSRF indicators"""
        findings = []
        response_text = response.text.lower()
        
        # Check response content for indicators
        for pattern_name, pattern in self.detection_patterns.items():
            if pattern.search(response_text):
                findings.append(pattern_name.replace('_', ' '))
                
        # Status code analysis
        if response.status_code in [200, 201, 202] and category != "oob":
            findings.append(f"suspicious {response.status_code} response")
            
        if findings:
            self._add_finding({
                "type": f"{category.upper()} SSRF",
                "payload": payload,
                "response_code": response.status_code,
                "severity": "High" if any(x in findings for x in ["local ips", "cloud metadata"]) else "Medium",
                "findings": findings,
                "confidence": "High" if len(findings) > 1 else "Medium"
            })

    def _add_finding(self, finding):
        """Add unique finding to results"""
        finding_hash = hash(frozenset({
            k: v for k, v in finding.items() 
            if k not in ['confidence', 'severity']
        }.items()))
        
        if finding_hash not in self.unique_hashes:
            self.unique_hashes.add(finding_hash)
            self.findings.append(finding)

    def _report_findings(self):
        """Display all findings to console"""
        if not self.findings:
            print(Colors.success("\n[+] No SSRF vulnerabilities detected"))
            return
            
        print(Colors.header("\n[+] SSRF Assessment Findings:"))
        for i, finding in enumerate(self.findings, 1):
            print(f"\n{Colors.info(f'Finding #{i}:')}")
            print(f"{Colors.info('Type:')} {finding['type']}")
            print(f"{Colors.info('Severity:')} {Colors.error(finding['severity']) if finding['severity'] == 'High' else Colors.warning(finding['severity'])}")
            print(f"{Colors.info('Confidence:')} {finding['confidence']}")
            print(f"{Colors.info('Response Code:')} {finding.get('response_code', 'N/A')}")
            
            if 'payload' in finding:
                print(f"{Colors.info('Payload:')} {Colors.subtle(str(finding['payload'])[:200])}")
                
            if 'findings' in finding:
                print(f"{Colors.info('Indicators:')}")
                for indicator in finding['findings']:
                    print(f"  - {indicator}")

    def _prompt_save_report(self):
        """Prompt user to save JSON report"""
        if not self.findings:
            return
            
        choice = input(Colors.info("\n[?] Save report to JSON file? (y/n): ")).lower()
        if choice in ('y', 'yes'):
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"ssrf_report_{timestamp}.json"
            
            report = {
                "target": self.target,
                "date": timestamp,
                "payload_size": self.payload_size,
                "findings": [
                    {k: v for k, v in f.items() if k != 'confidence'} 
                    for f in self.findings
                ]
            }
            
            try:
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2)
                print(Colors.success(f"[+] Report saved to {filename}"))
            except Exception as e:
                print(Colors.error(f"[!] Failed to save report: {str(e)}"))