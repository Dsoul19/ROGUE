import json
import re
import aiohttp
import asyncio
from datetime import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colors import Colors
from typing import Dict, List, Optional, Tuple, Any
import hashlib
from dataclasses import dataclass
import random
import socket
from .payloads import LoggingPayloads

# Configuration
MAX_CONCURRENT_REQUESTS = 10
REQUEST_TIMEOUT = 15
RETRY_ATTEMPTS = 3
BASE_BACKOFF = 1
COMMON_LOG_PATHS = [
    "/logs", "/var/log", "/admin/logs",
    "/logging", "/debug", "/console",
    "/api/logs", "/logviewer", "/logfiles"
]

@dataclass
class CachedResponse:
    """Simplified response caching structure"""
    status: int
    content: bytes
    headers: Dict[str, str]

class RateLimiter:
    """Enhanced rate limiter for requests with burst capability"""
    def __init__(self, requests_per_second: int = 5):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
        self.lock = asyncio.Lock()

    async def wait(self):
        """Wait if needed to maintain rate limit"""
        async with self.lock:
            current_time = asyncio.get_event_loop().time()
            elapsed = current_time - self.last_request_time
            wait_time = max(0, self.min_interval - elapsed)
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self.last_request_time = asyncio.get_event_loop().time()

class LoggingFailuresAssessment:
    """Comprehensive A09 Security Logging and Monitoring Assessment"""

    def __init__(self):
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Logging Configuration Testing",
                "description": "Test for inadequate security logging",
                "steps": 4
            },
            "2": {
                "id": "2",
                "name": "Monitoring Gap Analysis",
                "description": "Test security monitoring coverage",
                "steps": 3
            },
            "3": {
                "id": "3",
                "name": "Log Injection Testing",
                "description": "Test log injection vulnerabilities",
                "steps": 3
            }
        }
        self.payload_size = "medium"
        self.findings = []
        self.verbose = False
        self.session = None
        self.checked_urls = set()
        self.response_cache = {}
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.target_info = {}
        self.rate_limiter = RateLimiter()
        self.current_step = 0
        self.total_steps = 0
        self.target = ""

    async def initialize(self):
        """Initialize async session with proper error handling"""
        try:
            self.session = aiohttp.ClientSession(
                headers={
                    'User-Agent': 'ROGUEv2 Scanner/1.0',
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.5'
                },
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                connector=aiohttp.TCPConnector(
                    force_close=True,
                    enable_cleanup_closed=True,
                    limit=MAX_CONCURRENT_REQUESTS
                )
            )
        except Exception as e:
            print(Colors.error(f"Session initialization failed: {str(e)}"))
            raise

    async def close(self):
        """Cleanup resources with proper error handling"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"Error during session close: {str(e)}"))

    def set_payload_size(self, size: str) -> bool:
        """Validate and set payload size"""
        size = size.lower()
        valid_sizes = ["small", "medium", "large"]
        if size not in valid_sizes:
            return False
        self.payload_size = size
        return True

    def get_techniques(self) -> List[str]:
        """Return available techniques with proper formatting"""
        return [f"{tech_id} - {tech['name']}" for tech_id, tech in self.techniques.items()]

    async def run_assessment(self, technique_id: str, target: str, verbose: bool = False) -> bool:
        """Main assessment execution with proper async handling"""
        self.verbose = verbose
        self.target = target.rstrip('/')
        self.findings.clear()
        
        try:
            await self.initialize()
            
            if not await self._verify_target():
                print(Colors.error("\n[!] Target verification failed. Check:"))
                print(f"- URL: {self.target}")
                print("- Network connectivity")
                print("- Server availability\n")
                return False

            technique = self.techniques.get(technique_id)
            if not technique:
                print(Colors.error(f"Invalid technique ID: {technique_id}"))
                return False

            self.total_steps = technique["steps"]
            self.current_step = 0

            print(Colors.header(f"\nStarting assessment: {technique['name']}"))
            print(Colors.info(f"Target: {self.target}"))
            print(Colors.info(f"Payload size: {self.payload_size}\n"))

            if technique_id == "1":
                await self._test_logging_config()
            elif technique_id == "2":
                await self._test_monitoring_gaps()
            elif technique_id == "3":
                await self._test_log_injection()

            await self._generate_report()
            return True
            
        except Exception as e:
            print(Colors.error(f"\n[!] Critical assessment error: {str(e)}\n"))
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
        finally:
            await self.close()

    async def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[CachedResponse]:
        """Enhanced async request with proper error handling and caching"""
        cache_key = hashlib.md5(f"{method}:{url}:{json.dumps(kwargs, sort_keys=True)}".encode()).hexdigest()
        
        if cache_key in self.response_cache:
            if self.verbose:
                print(Colors.info(f"Using cached response for {url}"))
            return self.response_cache[cache_key]

        async with self.semaphore:
            await self.rate_limiter.wait()
            
            for attempt in range(RETRY_ATTEMPTS):
                try:
                    async with self.session.request(method, url, **kwargs) as resp:
                        content = await resp.read()
                        cached_resp = CachedResponse(
                            status=resp.status,
                            content=content,
                            headers=dict(resp.headers)
                        )
                        self.response_cache[cache_key] = cached_resp
                        
                        if self.verbose:
                            print(Colors.info(f"Request to {url} returned {resp.status}"))
                            
                        return cached_resp
                        
                except (aiohttp.ClientError, socket.gaierror) as e:
                    if attempt == RETRY_ATTEMPTS - 1:
                        if self.verbose:
                            print(Colors.error(f"Request failed after {RETRY_ATTEMPTS} attempts: {str(e)}"))
                    await asyncio.sleep(BASE_BACKOFF * (2 ** attempt))
                except Exception as e:
                    if self.verbose:
                        print(Colors.error(f"Unexpected error during request: {str(e)}"))
                    break
                    
        return None

    async def _verify_target(self) -> bool:
        """Enhanced target verification with better error handling"""
        try:
            if self.verbose:
                print(Colors.info("Verifying target connectivity..."))
            
            response = await self._make_request(self.target)
            if not response:
                if self.verbose:
                    print(Colors.error("No response from target"))
                return False
                
            if response.status >= 400:
                if self.verbose:
                    print(Colors.error(f"Target returned HTTP {response.status}"))
                return False
                
            # Store basic target information
            self.target_info = {
                'base_url': self.target,
                'server': response.headers.get('server', ''),
                'tech_stack': self._detect_tech_stack(response)
            }
            
            if self.verbose:
                print(Colors.success("Target verification passed"))
            return True
            
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"Target verification error: {str(e)}"))
            return False

    def _detect_tech_stack(self, response: CachedResponse) -> List[str]:
        """Detect technology stack from response headers"""
        tech_stack = []
        server = response.headers.get('server', '').lower()
        
        if 'apache' in server:
            tech_stack.append('Apache')
        elif 'nginx' in server:
            tech_stack.append('Nginx')
        elif 'iis' in server:
            tech_stack.append('IIS')
            
        powered_by = response.headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech_stack.append('PHP')
        elif 'asp.net' in powered_by:
            tech_stack.append('ASP.NET')
        elif 'node.js' in powered_by:
            tech_stack.append('Node.js')
            
        return tech_stack if tech_stack else ['Unknown']

    def _update_progress(self, current: int, total: int, assessment_name: str):
        """Show progress in the requested format with proper cleanup"""
        if total <= 0:
            return
            
        # Clear the line first
        print("\r" + " " * 100, end="", flush=True)
        
        percent = min(100, (current / total) * 100)
        progress_text = f"\r[*] {assessment_name} Progress: [{percent:.1f}%] ({current}/{total})"
        print(progress_text, end="", flush=True)
        
        if current >= total:
            print()  # New line when complete

    async def _test_logging_config(self):
        """Comprehensive logging configuration tests with better error handling"""
        try:
            total_steps = self.techniques["1"]["steps"]
            
            # Step 1: Check for exposed logging endpoints
            self._update_progress(1, total_steps, "Discovering logging endpoints")
            endpoints = await self._find_logging_endpoints()
            
            # Step 2: Test security event logging
            self._update_progress(2, total_steps, "Testing security event logging")
            security_events_logged = await self._test_security_event_logging()
            
            if not security_events_logged:
                self.findings.append(self._create_finding(
                    "Insufficient Security Logging",
                    "Critical security events are not being logged",
                    "High",
                    "Implement logging for all authentication attempts, privilege changes, and data access events"
                ))

            # Step 3: Check for sensitive data in logs
            self._update_progress(3, total_steps, "Checking for sensitive data exposure")
            sensitive_data = await self._check_log_sensitivity()
            
            if sensitive_data:
                self.findings.append(self._create_finding(
                    "Sensitive Data Exposure in Logs",
                    f"Found {len(sensitive_data)} instances of sensitive data patterns in logs",
                    "Critical",
                    "Implement log data sanitization and filtering for sensitive information"
                ))

            # Step 4: Verify log access controls
            self._update_progress(4, total_steps, "Testing log access controls")
            insecure_access = await self._check_log_access()
            
            if insecure_access:
                self.findings.append(self._create_finding(
                    "Insecure Log Access",
                    "Log files are accessible without proper authentication",
                    "High",
                    "Implement proper access controls and encryption for log files"
                ))

        except Exception as e:
            print(Colors.error(f"\nLogging configuration test failed: {str(e)}\n"))
            if self.verbose:
                import traceback
                traceback.print_exc()

    async def _find_logging_endpoints(self) -> List[str]:
        """Discover potential logging endpoints with better error handling"""
        found_endpoints = []
        
        for path in COMMON_LOG_PATHS:
            try:
                url = urljoin(self.target, path)
                if url in self.checked_urls:
                    continue
                    
                self.checked_urls.add(url)
                response = await self._make_request(url)
                
                if response and response.status == 200:
                    found_endpoints.append(url)
                    if self.verbose:
                        print(Colors.success(f"Found logging endpoint: {url}"))
                        
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error checking {url}: {str(e)}"))
                continue
                
        return found_endpoints

    async def _test_security_event_logging(self) -> bool:
        """Test if security events are properly logged"""
        test_events = [
            ("failed_login", {"username": "testuser", "ip": "192.168.1.100"}),
            ("privilege_change", {"user": "admin", "new_role": "superuser"}),
            ("data_access", {"user": "auditor", "record": "sensitive_data"}),
            ("config_change", {"admin": "sysadmin", "setting": "auth_level"})
        ]

        detected_events = 0
        base_url = self.target_info.get('base_url', self.target)

        for event_type, event_data in test_events:
            try:
                test_id = f"rogue_test_{random.randint(10000,99999)}"
                event_data['test_id'] = test_id
                
                if event_type == "failed_login":
                    login_url = urljoin(base_url, "/login")
                    payload = {
                        "username": event_data['username'],
                        "password": "invalid_password",
                        "test_id": test_id
                    }
                    await self._make_request(login_url, method="POST", data=payload)
                
                elif event_type == "privilege_change":
                    admin_url = urljoin(base_url, "/admin/roles")
                    payload = {
                        "action": "change_role",
                        "user": event_data['user'],
                        "role": event_data['new_role'],
                        "test_id": test_id
                    }
                    await self._make_request(admin_url, method="POST", json=payload)
                
                # Check logs for our test ID
                log_endpoints = await self._find_logging_endpoints()
                for endpoint in log_endpoints:
                    response = await self._make_request(endpoint)
                    if response and test_id.encode() in response.content:
                        detected_events += 1
                        if self.verbose:
                            print(Colors.success(f"Detected {event_type} event in logs"))
                        break

            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error testing {event_type} logging: {str(e)}"))
                continue

        return detected_events >= len(test_events) * 0.75  # Require 75% detection rate

    async def _check_log_sensitivity(self) -> List[str]:
        """Check for sensitive data in logs using advanced pattern matching"""
        sensitive_patterns = LoggingPayloads.get_sensitive_data_patterns(self.payload_size)['patterns']
        log_endpoints = await self._find_logging_endpoints()
        found_patterns = []
        
        for endpoint in log_endpoints:
            try:
                response = await self._make_request(endpoint)
                if not response:
                    continue
                    
                content = response.content.decode('utf-8', errors='ignore')
                
                for pattern in sensitive_patterns:
                    try:
                        if isinstance(pattern, str):
                            if pattern.lower() in content.lower():
                                found_patterns.append(f"String pattern '{pattern}' found in {endpoint}")
                        else:  # Assume it's a compiled regex
                            matches = pattern.findall(content)
                            if matches:
                                found_patterns.append(f"Regex pattern '{pattern.pattern}' matched {len(matches)} times in {endpoint}")
                    except Exception as e:
                        if self.verbose:
                            print(Colors.error(f"Error processing pattern {pattern}: {str(e)}"))
                        continue
                        
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error checking {endpoint}: {str(e)}"))
                continue
                
        return found_patterns

    async def _check_log_access(self) -> bool:
        """Check if logs are insecurely accessible through various vectors"""
        log_endpoints = await self._find_logging_endpoints()
        insecure_count = 0
        
        for endpoint in log_endpoints:
            try:
                # First check direct access
                response = await self._make_request(endpoint)
                if response and response.status == 200:
                    insecure_count += 1
                    continue
                    
                # Then check path traversal attempts
                traversal_payloads = [
                    "../../../../var/log/syslog",
                    "%2e%2e%2fetc%2fpasswd",
                    "....//....//....//etc//passwd"
                ]
                
                for payload in traversal_payloads:
                    test_url = f"{endpoint}?file={payload}"
                    response = await self._make_request(test_url)
                    if response and response.status == 200:
                        insecure_count += 1
                        break
                        
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error checking log access at {endpoint}: {str(e)}"))
                continue
                
        return insecure_count > 0

    async def _test_monitoring_gaps(self):
        """Comprehensive monitoring gap analysis with better error handling"""
        try:
            total_steps = self.techniques["2"]["steps"]
            
            # Step 1: Detect monitoring systems
            self._update_progress(1, total_steps, "Detecting monitoring systems")
            monitoring_systems = await self._detect_monitoring()
            
            if not monitoring_systems:
                self.findings.append(self._create_finding(
                    "No Monitoring Systems Detected",
                    "No security monitoring systems were identified",
                    "High",
                    "Implement comprehensive security monitoring solution"
                ))

            # Step 2: Test alerting functionality
            self._update_progress(2, total_steps, "Testing alerting mechanisms")
            alert_works = await self._test_alerting()
            
            if not alert_works:
                self.findings.append(self._create_finding(
                    "Insufficient Alerting",
                    "Security events do not trigger proper alerts",
                    "Medium",
                    "Configure alerting for critical security events"
                ))

            # Step 3: Test incident response
            self._update_progress(3, total_steps, "Testing incident response")
            response_works = await self._test_incident_response()
            
            if not response_works:
                self.findings.append(self._create_finding(
                    "Poor Incident Response",
                    "No response to security events within expected timeframe",
                    "Medium",
                    "Establish and test incident response procedures"
                ))

        except Exception as e:
            print(Colors.error(f"\nMonitoring gap analysis failed: {str(e)}\n"))
            if self.verbose:
                import traceback
                traceback.print_exc()

    async def _detect_monitoring(self) -> bool:
        """Detect monitoring systems through multiple techniques"""
        detection_methods = [
            self._check_monitoring_headers,
            self._check_known_monitoring_endpoints,
            self._analyze_response_times
        ]
        
        positive_detections = 0
        for method in detection_methods:
            try:
                if await method():
                    positive_detections += 1
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Monitoring detection method failed: {str(e)}"))
                continue
                
        return positive_detections >= 2  # Require at least 2 positive indicators

    async def _check_monitoring_headers(self) -> bool:
        """Check for monitoring-related HTTP headers"""
        response = await self._make_request(self.target)
        if not response:
            return False
            
        monitoring_headers = {
            'server': ['newrelic', 'datadog', 'splunk'],
            'x-monitoring': ['enabled', 'true'],
            'x-powered-by': ['appdynamics', 'dynatrace']
        }
        
        for header_name, header_values in monitoring_headers.items():
            header_value = response.headers.get(header_name, '').lower()
            for value in header_values:
                if value in header_value:
                    if self.verbose:
                        print(Colors.success(f"Found monitoring header: {header_name}: {header_value}"))
                    return True
        return False

    async def _check_known_monitoring_endpoints(self) -> bool:
        """Check for known monitoring system endpoints"""
        endpoints = [
            "/_monitoring", "/_status", "/_health",
            "/newrelic", "/appdynamics", "/dynatrace",
            "/api/v1/monitoring", "/internal/metrics"
        ]
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.target, endpoint)
                response = await self._make_request(url)
                if response and response.status == 200:
                    if self.verbose:
                        print(Colors.success(f"Found monitoring endpoint: {url}"))
                    return True
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error checking {endpoint}: {str(e)}"))
                continue
                
        return False

    async def _analyze_response_times(self) -> bool:
        """Detect monitoring through response time analysis"""
        try:
            test_urls = [
                urljoin(self.target, path) for path in ["/", "/login", "/api/ping"]
            ]
            
            # Get baseline response times
            base_times = []
            for url in test_urls:
                start = datetime.now()
                await self._make_request(url)
                base_times.append((datetime.now() - start).total_seconds())
            
            avg_base_time = sum(base_times) / len(base_times)
            
            # Test suspicious endpoints that might trigger monitoring
            suspicious_requests = [
                ("/admin/delete_all", "POST"),
                ("/api/users/export", "GET"),
                ("/config/password_reset", "POST")
            ]
            
            suspicious_times = []
            for path, method in suspicious_requests:
                url = urljoin(self.target, path)
                start = datetime.now()
                await self._make_request(url, method=method)
                elapsed = (datetime.now() - start).total_seconds()
                suspicious_times.append(elapsed)
                
                if self.verbose:
                    print(Colors.info(f"Response time for {method} {path}: {elapsed:.2f}s"))
            
            avg_suspicious_time = sum(suspicious_times) / len(suspicious_times)
            
            if self.verbose:
                print(Colors.info(f"Average base time: {avg_base_time:.2f}s"))
                print(Colors.info(f"Average suspicious time: {avg_suspicious_time:.2f}s"))
            
            return avg_suspicious_time > avg_base_time * 1.5
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"Response time analysis failed: {str(e)}"))
            return False

    async def _test_alerting(self) -> bool:
        """Test alerting functionality by triggering security events"""
        alert_triggers = [
            ("/login", "POST", {"username": "admin", "password": "' OR '1'='1"}),
            ("/api/users", "GET", {"filter": "ALL"}),
            ("/admin/export", "POST", {"format": "csv", "tables": "*"})
        ]
        
        base_url = self.target_info.get('base_url', self.target)
        triggered = False
        
        for path, method, data in alert_triggers:
            try:
                url = urljoin(base_url, path)
                test_id = f"rogue_alert_test_{random.randint(10000,99999)}"
                data['test_id'] = test_id
                
                await self._make_request(url, method=method, data=data)
                
                # Check if we got blocked or alerted
                response = await self._make_request(urljoin(base_url, "/"))
                if response and response.status >= 400:
                    if self.verbose:
                        print(Colors.success(f"Alert triggered for {method} {path}"))
                    triggered = True
                    break
                    
                await asyncio.sleep(3)  # Give monitoring system time to react
                
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error testing alert for {path}: {str(e)}"))
                continue
                
        return triggered

    async def _test_incident_response(self) -> bool:
        """Test incident response by measuring reaction to security events"""
        try:
            start_time = datetime.now()
            test_id = f"rogue_incident_test_{random.randint(10000,99999)}"
            
            login_url = urljoin(self.target, "/login")
            await self._make_request(login_url, method="POST", data={
                "username": f"admin'; DROP TABLE users--",
                "password": test_id
            })
            
            detection_time = None
            for _ in range(5):  # Check for response over 2.5 minutes
                await asyncio.sleep(30)
                
                # Check if we're blocked
                response = await self._make_request(login_url)
                if response and response.status >= 400:
                    detection_time = datetime.now()
                    if self.verbose:
                        print(Colors.success("Incident response detected (blocked)"))
                    break
                    
                # Check for security headers
                response = await self._make_request(urljoin(self.target, "/"))
                if 'security-alert' in response.headers.get('x-security-header', ''):
                    detection_time = datetime.now()
                    if self.verbose:
                        print(Colors.success("Incident response detected (header)"))
                    break
            
            if not detection_time:
                if self.verbose:
                    print(Colors.error("No incident response detected"))
                return False
                
            response_time = (detection_time - start_time).total_seconds() / 60
            if self.verbose:
                print(Colors.info(f"Incident response time: {response_time:.1f} minutes"))
            
            return response_time <= 15  # Response within 15 minutes
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"Incident response test failed: {str(e)}"))
            return False

    async def _test_log_injection(self):
        """Comprehensive log injection testing with better error handling"""
        try:
            total_steps = self.techniques["3"]["steps"]
            
            # Step 1: Test CRLF injection
            self._update_progress(1, total_steps, "Testing CRLF injection vulnerabilities")
            crlf_vuln = await self._test_crlf_injection()
            
            if crlf_vuln:
                self.findings.append(self._create_finding(
                    "CRLF Injection Vulnerability",
                    "Log injection possible via CRLF sequences",
                    "High",
                    "Sanitize all input for CRLF sequences before logging"
                ))

            # Step 2: Test XSS in logs
            self._update_progress(2, total_steps, "Testing for XSS in log interfaces")
            xss_vuln = await self._test_xss_in_logs()
            
            if xss_vuln:
                self.findings.append(self._create_finding(
                    "XSS in Log Interface",
                    "Cross-site scripting possible in log viewer interface",
                    "Medium",
                    "Implement proper output encoding in log display interfaces"
                ))

            # Step 3: Test log forging
            self._update_progress(3, total_steps, "Testing log forging vulnerabilities")
            forging_vuln = await self._test_log_forging()
            
            if forging_vuln:
                self.findings.append(self._create_finding(
                    "Log Forging Vulnerability",
                    "Ability to inject fake log entries detected",
                    "Low",
                    "Implement cryptographic log signing to prevent tampering"
                ))

        except Exception as e:
            print(Colors.error(f"\nLog injection testing failed: {str(e)}\n"))
            if self.verbose:
                import traceback
                traceback.print_exc()

    async def _test_crlf_injection(self) -> bool:
        """Test CRLF injection in logging mechanisms"""
        try:
            injection_payloads = LoggingPayloads.get_log_injection_payloads(self.payload_size)
            vulnerable = False
            
            # Combine all payload types
            all_payloads = []
            if 'basic' in injection_payloads.get('log_injection', {}):
                all_payloads.extend(injection_payloads['log_injection']['basic'])
            if 'advanced' in injection_payloads.get('log_injection', {}):
                all_payloads.extend(injection_payloads['log_injection']['advanced'])
            if 'techniques' in injection_payloads:
                all_payloads.extend(injection_payloads['techniques'])
            
            for payload in all_payloads:
                try:
                    if not any(seq in str(payload).lower() for seq in ['\r\n', '%0d%0a', '\n']):
                        continue
                        
                    # Test via headers
                    headers = {"X-Test-Header": str(payload)}
                    await self._make_request(urljoin(self.target, "/"), headers=headers)
                    
                    # Test via URL parameters
                    test_url = f"{self.target}/?test={payload}"
                    await self._make_request(test_url)
                    
                    # Check logs if we can access them
                    log_endpoints = await self._find_logging_endpoints()
                    for endpoint in log_endpoints:
                        log_response = await self._make_request(endpoint)
                        if log_response and str(payload).encode() in log_response.content:
                            if self.verbose:
                                print(Colors.success(f"CRLF injection successful with payload: {payload}"))
                            vulnerable = True
                            break
                            
                except Exception as e:
                    if self.verbose:
                        print(Colors.error(f"Error testing CRLF payload {payload}: {str(e)}"))
                    continue
                    
            return vulnerable
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"CRLF injection test failed: {str(e)}"))
            return False

    async def _test_xss_in_logs(self) -> bool:
        """Test for XSS vulnerabilities in log viewing interfaces"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:eval('alert(1)')"
        ]
        
        for payload in xss_payloads:
            try:
                # Inject via URL parameter
                test_url = f"{self.target}/log?test={payload}"
                await self._make_request(test_url)
                
                # Inject via User-Agent header
                headers = {"User-Agent": payload}
                await self._make_request(self.target, headers=headers)
            
                # Check log viewer interfaces
                log_endpoints = await self._find_logging_endpoints()
                for endpoint in log_endpoints:
                    response = await self._make_request(endpoint)
                    if not response:
                        continue
                        
                    content_type = response.headers.get('content-type', '')
                    if 'text/html' not in content_type:
                        continue
                        
                    # Check for reflected XSS
                    soup = BeautifulSoup(response.content.decode(), 'html.parser')
                    scripts = soup.find_all('script')
                    for script in scripts:
                        if any(payload in script.text for payload in xss_payloads):
                            if self.verbose:
                                print(Colors.success(f"XSS found in log interface with payload: {payload}"))
                            return True
                            
                    # Check for direct reflection
                    if any(payload.encode() in response.content for payload in xss_payloads):
                        if self.verbose:
                            print(Colors.success(f"XSS reflection found with payload: {payload}"))
                        return True
                        
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error testing XSS payload {payload}: {str(e)}"))
                continue
                
        return False

    async def _test_log_forging(self) -> bool:
        """Test ability to forge log entries"""
        forging_payloads = [
            "2023-01-01 [AUTH] User admin logged in from 192.168.1.1",
            "ERROR: Database connection failed - credentials invalid",
            "WARNING: Security alert - brute force attempt detected"
        ]
        
        successful_forgeries = 0
        
        for payload in forging_payloads:
            try:
                # Try different injection methods
                methods = [
                    lambda: self._make_request(
                        urljoin(self.target, "/log"),
                        method="POST",
                        data={"message": payload}
                    ),
                    lambda: self._make_request(
                        f"{self.target}/api?{payload}",
                        headers={"X-Forwarded-For": payload}
                    ),
                    lambda: self._make_request(
                        self.target,
                        headers={"User-Agent": payload}
                    )
                ]
                
                for method in methods:
                    await method()
                    
                # Check if our forged entries appear in logs
                log_endpoints = await self._find_logging_endpoints()
                for endpoint in log_endpoints:
                    response = await self._make_request(endpoint)
                    if response and payload.encode() in response.content:
                        if self.verbose:
                            print(Colors.success(f"Log forging successful with payload: {payload}"))
                        successful_forgeries += 1
                        break
                        
            except Exception as e:
                if self.verbose:
                    print(Colors.error(f"Error testing log forging payload {payload}: {str(e)}"))
                continue
                
        return successful_forgeries >= len(forging_payloads) / 2

    def _create_finding(self, title: str, description: str, severity: str, recommendation: str) -> Dict:
        """Create standardized finding structure"""
        return {
            "title": title,
            "description": description,
            "severity": severity,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()
        }

    async def _generate_report(self):
        """Generate comprehensive assessment report with better formatting"""
        if not self.findings:
            print(Colors.success("\nNo vulnerabilities found!"))
            return

        # Prepare report data
        report_data = {
            "target": self.target,
            "assessment_date": datetime.now().isoformat(),
            "payload_size": self.payload_size,
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"] == "Critical"),
                "high": sum(1 for f in self.findings if f["severity"] == "High"),
                "medium": sum(1 for f in self.findings if f["severity"] == "Medium"),
                "low": sum(1 for f in self.findings if f["severity"] == "Low")
            }
        }

        # Display report
        print(Colors.header("\nASSESSMENT REPORT"))
        print(Colors.header("=" * 50))
        print(f"{Colors.info('Target:')} {report_data['target']}")
        print(f"{Colors.info('Date:')} {report_data['assessment_date']}")
        print(f"{Colors.info('Payload Size:')} {report_data['payload_size']}")
        print(f"{Colors.info('Tech Stack:')} {', '.join(self.target_info.get('tech_stack', ['Unknown']))}\n")

        for finding in report_data["findings"]:
            print(f"\n{Colors.error(finding['title'].upper())} ({finding['severity']})")
            print(f"{Colors.info('Description:')} {finding['description']}")
            print(f"{Colors.info('Recommendation:')} {finding['recommendation']}")
            print("-" * 50)

        print(Colors.header("\nSUMMARY"))
        print(f"Total Findings: {report_data['summary']['total_findings']}")
        print(f"Critical: {report_data['summary']['critical']}")
        print(f"High: {report_data['summary']['high']}")
        print(f"Medium: {report_data['summary']['medium']}")
        print(f"Low: {report_data['summary']['low']}")