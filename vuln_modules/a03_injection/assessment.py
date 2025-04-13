# vuln_modules/a03_injection/assessment.py
import requests
import re
import os
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import List, Dict
from colors import Colors
from .payloads import InjectionPayloads

class InjectionAssessment:
    def __init__(self):
        self.name = "Injection Assessment"
        self.techniques = {
            "1": {
                "id": "1",
                "name": "SQL Injection",
                "function": self.assess_sql_injection,
                "description": "Tests for SQL injection vulnerabilities in input parameters"
            },
            "2": {
                "id": "2",
                "name": "Command Injection",
                "function": self.assess_command_injection,
                "description": "Tests for OS command injection vulnerabilities"
            },
            "3": {
                "id": "3",
                "name": "Cross-Site Scripting (XSS)",
                "function": self.assess_xss,
                "description": "Tests for XSS vulnerabilities in input parameters"
            },
            "4": {
                "id": "4",
                "name": "NoSQL Injection",
                "function": self.assess_nosql_injection,
                "description": "Tests for NoSQL injection vulnerabilities"
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
        self.payloads = InjectionPayloads()
        self.current_payloads = self.payloads.get_payloads(self.payload_size)
        self.scan_active = False
        self.base_url = None

    def get_techniques(self) -> List[str]:
        """Return available assessment technique names with IDs"""
        return [f"{id}. {tech['name']}" for id, tech in self.techniques.items()]

    def set_payload_size(self, size: str) -> bool:
        """Set the payload size to use for scans"""
        valid_sizes = ["small", "medium", "large"]
        if size.lower() in valid_sizes:
            self.payload_size = size.lower()
            self.current_payloads = self.payloads.get_payloads(self.payload_size)
            return True
        return False

    def run_assessment(self, technique_id: str, target: str, verbose: bool = False) -> None:
        """Run the selected assessment technique"""
        if technique_id not in [tech['id'] for tech in self.techniques.values()]:
            raise ValueError(f"Invalid technique ID: {technique_id}")

        # Parse base URL
        parsed = urlparse(target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        technique = next(tech for tech in self.techniques.values() if tech['id'] == technique_id)
        self.start_time = datetime.now()
        self.findings = []
        self.scan_active = True
        
        print(Colors.header(f"\n[+] Starting {technique['name']} assessment"))
        print(Colors.info(f"[~] Target: {target}"))
        print(Colors.info(f"[~] Payload size: {self.payload_size}"))
        
        try:
            technique["function"](target, verbose)
            
            if self.findings:
                print(Colors.error(f"\n[!] Found {len(self.findings)} potential vulnerabilities!"))
                self._print_findings_summary()
            else:
                print(Colors.success("\n[√] No vulnerabilities found"))
            
            if self._prompt_for_report():
                self._generate_report(target, technique['name'])
                
        except KeyboardInterrupt:
            print(Colors.error("\n[!] Scan interrupted by user"))
        except Exception as e:
            print(Colors.error(f"\n[!] Assessment failed: {str(e)}"))
        finally:
            self.scan_active = False
            self.session.close()

    def assess_sql_injection(self, target: str, verbose: bool) -> None:
        """Check for SQL injection vulnerabilities"""
        if not self.scan_active:
            return
            
        print(Colors.info("\n[~] Checking for SQL Injection vulnerabilities..."))
        
        # Get all input points from the target
        input_points = self._get_input_points(target)
        
        if not input_points:
            print(Colors.error("  [!] No input points found for testing"))
            return
            
        total_tests = len(input_points) * len(self.current_payloads["sql"])
        completed_tests = 0
        
        for input_point in input_points:
            for payload in self.current_payloads["sql"]:
                if not self.scan_active:
                    return
                    
                completed_tests += 1
                self._update_progress(completed_tests, total_tests)
                
                if verbose:
                    print(Colors.subtle(f"  Testing {input_point['type']} {input_point['name']} with payload: {payload}"))
                
                try:
                    if input_point['type'] == 'form':
                        response = self._test_form_input(target, input_point, payload)
                    elif input_point['type'] == 'url':
                        response = self._test_url_input(target, input_point, payload)
                    elif input_point['type'] == 'header':
                        response = self._test_header_input(target, input_point, payload)
                    else:
                        continue
                    
                    self._analyze_sql_response(response, payload, input_point)
                except Exception as e:
                    if verbose:
                        print(Colors.error(f"    [!] Test failed: {str(e)}"))
                    continue
        
        print(Colors.success("\n[√] SQL Injection checks completed"))

    def assess_command_injection(self, target: str, verbose: bool) -> None:
        """Check for command injection vulnerabilities"""
        if not self.scan_active:
            return
            
        print(Colors.info("\n[~] Checking for Command Injection vulnerabilities..."))
        
        input_points = self._get_input_points(target)
        
        if not input_points:
            print(Colors.error("  [!] No input points found for testing"))
            return
            
        total_tests = len(input_points) * len(self.current_payloads["command"])
        completed_tests = 0
        
        for input_point in input_points:
            for payload in self.current_payloads["command"]:
                if not self.scan_active:
                    return
                    
                completed_tests += 1
                self._update_progress(completed_tests, total_tests)
                
                if verbose:
                    print(Colors.subtle(f"  Testing {input_point['type']} {input_point['name']} with payload: {payload}"))
                
                try:
                    if input_point['type'] == 'form':
                        response = self._test_form_input(target, input_point, payload)
                    elif input_point['type'] == 'url':
                        response = self._test_url_input(target, input_point, payload)
                    else:
                        continue
                    
                    self._analyze_command_response(response, payload, input_point)
                except Exception as e:
                    if verbose:
                        print(Colors.error(f"    [!] Test failed: {str(e)}"))
                    continue
        
        print(Colors.success("\n[√] Command Injection checks completed"))

    def assess_xss(self, target: str, verbose: bool) -> None:
        """Check for XSS vulnerabilities"""
        if not self.scan_active:
            return
            
        print(Colors.info("\n[~] Checking for XSS vulnerabilities..."))
        
        input_points = self._get_input_points(target)
        
        if not input_points:
            print(Colors.error("  [!] No input points found for testing"))
            return
            
        total_tests = len(input_points) * len(self.current_payloads["xss"])
        completed_tests = 0
        
        for input_point in input_points:
            for payload in self.current_payloads["xss"]:
                if not self.scan_active:
                    return
                    
                completed_tests += 1
                self._update_progress(completed_tests, total_tests)
                
                if verbose:
                    print(Colors.subtle(f"  Testing {input_point['type']} {input_point['name']} with payload: {payload}"))
                
                try:
                    if input_point['type'] == 'form':
                        response = self._test_form_input(target, input_point, payload)
                    elif input_point['type'] == 'url':
                        response = self._test_url_input(target, input_point, payload)
                    else:
                        continue
                    
                    self._analyze_xss_response(response, payload, input_point)
                except Exception as e:
                    if verbose:
                        print(Colors.error(f"    [!] Test failed: {str(e)}"))
                    continue
        
        print(Colors.success("\n[√] XSS checks completed"))

    def assess_nosql_injection(self, target: str, verbose: bool) -> None:
        """Check for NoSQL injection vulnerabilities"""
        if not self.scan_active:
            return
            
        if self.payload_size == "small":
            print(Colors.error("\n  [!] This technique requires at least medium payload size"))
            return
            
        print(Colors.info("\n[~] Checking for NoSQL Injection vulnerabilities..."))
        
        input_points = self._get_input_points(target, json_input=True)
        
        if not input_points:
            print(Colors.error("  [!] No JSON input points found for testing"))
            return
            
        total_tests = len(input_points) * len(self.current_payloads["nosql"])
        completed_tests = 0
        
        for input_point in input_points:
            for payload in self.current_payloads["nosql"]:
                if not self.scan_active:
                    return
                    
                completed_tests += 1
                self._update_progress(completed_tests, total_tests)
                
                if verbose:
                    print(Colors.subtle(f"  Testing {input_point['type']} {input_point['name']} with payload: {payload}"))
                
                try:
                    response = self._test_json_input(target, input_point, payload)
                    self._analyze_nosql_response(response, payload, input_point)
                except Exception as e:
                    if verbose:
                        print(Colors.error(f"    [!] Test failed: {str(e)}"))
                    continue
        
        print(Colors.success("\n[√] NoSQL Injection checks completed"))

    def _get_input_points(self, target: str, json_input: bool = False) -> List[Dict]:
        """Extract all input points (forms, URL params, etc.) from target"""
        input_points = []
        
        try:
            response = self.session.get(target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all forms and their inputs
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                form_url = urljoin(self.base_url, form_action) if form_action else target
                
                # Get all input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', '').lower()
                    input_name = input_tag.get('name', '')
                    
                    if not input_name:
                        continue
                        
                    # Skip certain input types
                    if input_type in ['submit', 'button', 'image', 'reset']:
                        continue
                        
                    input_points.append({
                        'type': 'form',
                        'method': form_method,
                        'action': form_url,
                        'name': input_name,
                        'tag': input_tag.name,
                        'input_type': input_type
                    })
            
            # Extract URL parameters if not looking specifically for JSON inputs
            if not json_input and '?' in target:
                query_string = target.split('?')[1]
                for param in query_string.split('&'):
                    if '=' in param:
                        name = param.split('=')[0]
                        input_points.append({
                            'type': 'url',
                            'name': name,
                            'value': param.split('=')[1] if len(param.split('=')) > 1 else ''
                        })
            
            # Extract potential API endpoints if looking for JSON inputs
            if json_input:
                # Check common API endpoints
                api_endpoints = [
                    urljoin(self.base_url, 'api'),
                    urljoin(self.base_url, 'graphql'),
                    urljoin(self.base_url, 'rest'),
                    urljoin(self.base_url, 'json')
                ]
                
                for endpoint in api_endpoints:
                    try:
                        response = self.session.get(endpoint, timeout=5)
                        if 'application/json' in response.headers.get('Content-Type', ''):
                            input_points.append({
                                'type': 'json',
                                'name': endpoint,
                                'value': ''
                            })
                    except:
                        continue
        
        except Exception as e:
            print(Colors.error(f"  [!] Error extracting input points: {str(e)}"))
        
        return input_points

    def _test_form_input(self, target: str, input_point: Dict, payload: str) -> requests.Response:
        """Test a form input with a payload"""
        data = {input_point['name']: payload}
        
        # Get all other form inputs to send complete data
        try:
            form_response = self.session.get(input_point['action'], timeout=5)
            soup = BeautifulSoup(form_response.text, 'html.parser')
            form = soup.find('form', action=input_point['action'].replace(self.base_url, ''))
            
            if form:
                for input_tag in form.find_all(['input', 'textarea']):
                    if input_tag.get('name') and input_tag.get('name') != input_point['name']:
                        input_type = input_tag.get('type', '').lower()
                        if input_type in ['hidden', 'text', 'password', 'email', 'search']:
                            data[input_tag.get('name')] = input_tag.get('value', '')
        except:
            pass
        
        if input_point['method'] == 'get':
            return self.session.get(input_point['action'], params=data, timeout=10)
        else:
            return self.session.post(input_point['action'], data=data, timeout=10)

    def _test_url_input(self, target: str, input_point: Dict, payload: str) -> requests.Response:
        """Test a URL parameter with a payload"""
        url = target.split('?')[0] if '?' in target else target
        params = {}
        
        if '?' in target:
            existing_params = target.split('?')[1].split('&')
            for param in existing_params:
                if '=' in param:
                    name, value = param.split('=', 1)
                    params[name] = value if name != input_point['name'] else payload
        
        params[input_point['name']] = payload
        return self.session.get(url, params=params, timeout=10)

    def _test_header_input(self, target: str, input_point: Dict, payload: str) -> requests.Response:
        """Test a header with a payload"""
        headers = {input_point['name']: payload}
        return self.session.get(target, headers=headers, timeout=10)

    def _test_json_input(self, target: str, input_point: Dict, payload: str) -> requests.Response:
        """Test a JSON input with a payload"""
        try:
            json_payload = json.loads(payload)
        except:
            json_payload = {input_point['name']: payload}
            
        headers = {'Content-Type': 'application/json'}
        return self.session.post(input_point['name'], json=json_payload, headers=headers, timeout=10)

    def _analyze_sql_response(self, response: requests.Response, payload: str, input_point: Dict) -> None:
        """Analyze response for SQL injection indicators"""
        sql_errors = [
            "SQL syntax", "mysql_fetch", "syntax error", 
            "unclosed quotation", "SQLSTATE", "ODBC",
            "JDBC", "PostgreSQL", "ORA-[0-9]", 
            "Microsoft OLE DB Provider"
        ]
        
        content = response.text.lower()
        
        # Check for error messages
        for error in sql_errors:
            if error.lower() in content:
                self._add_finding(
                    "SQL Injection",
                    f"{input_point['type']} {input_point['name']}",
                    f"SQL injection via {input_point['type']} {input_point['name']} (Error: {error})",
                    "High",
                    response.url,
                    payload
                )
                return
        
        # Check for content differences (blind SQLi)
        try:
            original_response = self.session.get(response.url.split('?')[0], timeout=10)
            if len(response.text) != len(original_response.text):
                self._add_finding(
                    "Blind SQL Injection",
                    f"{input_point['type']} {input_point['name']}",
                    f"Possible blind SQLi via {input_point['type']} {input_point['name']}",
                    "Medium",
                    response.url,
                    payload
                )
        except:
            pass

    def _analyze_command_response(self, response: requests.Response, payload: str, input_point: Dict) -> None:
        """Analyze response for command injection indicators"""
        command_indicators = [
            "root:x:0:0", "uid=", "gid=", "total", 
            "Volume Serial Number", "Directory of", 
            "Microsoft Windows", "Linux", "Darwin",
            "command not found", "Permission denied",
            "drwx", "-rw-", "index.html", "bin/bash"
        ]
        
        content = response.text
        
        for indicator in command_indicators:
            if indicator in content:
                self._add_finding(
                    "Command Injection",
                    f"{input_point['type']} {input_point['name']}",
                    f"Command injection via {input_point['type']} {input_point['name']} (Output: {indicator})",
                    "Critical",
                    response.url,
                    payload
                )
                return
        
        # Check for time-based command injection
        if "time-based" in payload.lower() and response.elapsed.total_seconds() > 3:
            self._add_finding(
                "Time-Based Command Injection",
                f"{input_point['type']} {input_point['name']}",
                f"Possible time-based command injection via {input_point['type']} {input_point['name']}",
                "High",
                response.url,
                payload
            )

    def _analyze_xss_response(self, response: requests.Response, payload: str, input_point: Dict) -> None:
        """Analyze response for XSS indicators"""
        if payload in response.text:
            self._add_finding(
                "Cross-Site Scripting (XSS)",
                f"{input_point['type']} {input_point['name']}",
                f"Reflected XSS via {input_point['type']} {input_point['name']}",
                "High",
                response.url,
                payload
            )

    def _analyze_nosql_response(self, response: requests.Response, payload: str, input_point: Dict) -> None:
        """Analyze response for NoSQL injection indicators"""
        try:
            data = response.json()
            
            # Check for different response patterns
            original_response = self.session.post(
                input_point['name'],
                json={},
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            original_data = original_response.json()
            
            # Detection logic
            if isinstance(data, list) and not isinstance(original_data, list):
                self._add_finding(
                    "NoSQL Injection",
                    input_point['name'],
                    f"NoSQL injection returning array with payload: {payload}",
                    "High",
                    response.url,
                    payload
                )
            elif response.status_code != original_response.status_code:
                self._add_finding(
                    "NoSQL Injection",
                    input_point['name'],
                    f"NoSQL injection changing status code with payload: {payload}",
                    "Medium",
                    response.url,
                    payload
                )
        except:
            pass

    def _update_progress(self, current: int, total: int) -> None:
        """Update and display progress without overwriting findings"""
        percent = (current / total) * 100
        # Move cursor up if we're not at the first line
        if current > 1:
            print("\033[F", end="")
        print(f"{Colors.info('[~] Progress:')} {percent:.1f}% ({current}/{total}){' '*20}")

    def _add_finding(self, vuln_type: str, location: str, description: str, severity: str, url: str, payload: str) -> None:
        """Add a vulnerability finding to the results with payload information"""
        finding = {
            "type": vuln_type,
            "location": location,
            "description": description,
            "severity": severity,
            "url": url,
            "payload": payload,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        
        # Print immediate finding details
        print(f"\n{Colors.error('[!] Vulnerability Found:')}")
        print(f"  Type: {Colors.info(vuln_type)}")
        print(f"  Location: {Colors.info(location)}")
        print(f"  Payload: {Colors.info(payload)}")
        print(f"  Severity: {Colors.error(severity)}")
        print(f"  URL: {Colors.subtle(url)}")

    def _print_findings_summary(self) -> None:
        """Print a summary of all findings"""
        if not self.findings:
            return
            
        print(Colors.header("\n[+] Vulnerability Details:"))
        for idx, finding in enumerate(self.findings, 1):
            print(f"\n  {Colors.error(f'{idx}.')} {finding['type']}")
            print(f"     Location: {finding['location']}")
            print(f"     Payload: {finding['payload']}")
            print(f"     Severity: {finding['severity']}")
            print(f"     URL: {finding['url']}")
            print(f"     Description: {finding['description']}")

    def _prompt_for_report(self) -> bool:
        """Ask user if they want to generate a report"""
        while True:
            print("\n")
            response = input(Colors.prompt("[?] Generate report? (y/n): ")).strip().lower()
            if response in ['y', 'yes', 'n', 'no']:
                return response in ['y', 'yes']
            print(Colors.error("  [!] Please enter 'y' or 'n'"))

    def _generate_report(self, target: str, technique: str) -> None:
        """Generate assessment report with detailed findings"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"a03_injection_{technique.lower().replace(' ', '_')}_{timestamp}.json"
        
        report = {
            "metadata": {
                "assessment": "Injection",
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
                "critical_severity": sum(1 for f in self.findings if f['severity'] == "Critical"),
                "high_severity": sum(1 for f in self.findings if f['severity'] == "High"),
                "medium_severity": sum(1 for f in self.findings if f['severity'] == "Medium"),
                "low_severity": sum(1 for f in self.findings if f['severity'] == "Low")
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(Colors.success(f"\n[√] Report saved to {filename}"))
        
        # Print detailed findings summary
        print(Colors.header("\n[+] Assessment Summary:"))
        print(f"  Target: {target}")
        print(f"  Technique: {technique}")
        print(f"  Payload size: {self.payload_size}")
        print(f"  Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds")
        print(f"  Findings: {Colors.error(str(len(self.findings)))} total")
        
        if self.findings:
            self._print_findings_summary()