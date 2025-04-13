import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional, Union, Tuple
from bs4 import BeautifulSoup
import json
import os
from datetime import datetime
from colors import Colors
from .payloads import SecurityMisconfigPayloads

class SecurityMisconfigAssessment:
    """Comprehensive scanner for OWASP A05:2021 - Security Misconfiguration"""

    def __init__(self):
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Authentication Checks",
                "description": "Tests for weak authentication and login issues"
            },
            "2": {
                "id": "2",
                "name": "Security Headers & Configs",
                "description": "Checks security headers and server configurations"
            },
            "3": {
                "id": "3",
                "name": "Sensitive Paths Scanner",
                "description": "Finds exposed admin panels and sensitive files"
            }
        }
        self.payload_size = "medium"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ROGUE-A05-Scanner/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        self.verbose = False
        self.current_progress = 0
        self.total_tests = 0
        self.results = {}

    def set_payload_size(self, size: str):
        """Set the payload size (small, medium, large)"""
        self.payload_size = size
        print(Colors.info(f"\nPayload level set to: {size.upper()}"))

    def get_techniques(self) -> List[str]:
        """Return numbered list of available techniques"""
        return [f"{tech['id']}. {tech['name']}" for tech in self.techniques.values()]

    def run_assessment(self, technique_id: str, target: str, verbose: bool = False) -> Dict:
        """Execute the specified assessment technique"""
        self.verbose = verbose
        self.current_progress = 0
        self.results = {}

        try:
            if technique_id == "1":
                return self.auth_checks(target)
            elif technique_id == "2":
                return self.header_checks(target)
            elif technique_id == "3":
                return self.path_checks(target)
            else:
                raise ValueError("Invalid technique ID")
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self._update_progress(100, error_msg, is_error=True)
            return {"error": error_msg}

    def auth_checks(self, target: str) -> Dict:
        """Advanced authentication vulnerability checks"""
        results = {
            "default_creds": [],
            "bruteforce_vuln": False,
            "login_bypass": False,
            "form_issues": [],
            "csrf_issues": False
        }
        payloads = SecurityMisconfigPayloads.get_payloads(self.payload_size)
        self.total_tests = len(payloads["auth_issues"]) + 2  # + form analysis + CSRF check

        # Initialization
        if not self.verbose:
            print(Colors.header("\n[+] Testing Authentication"))
        else:
            print(Colors.header("\n[+] Starting Authentication Checks"))
            print(f"Target: {target}")
            print(f"Payload size: {self.payload_size}\n")

        try:
            # Phase 1: Default credentials (20%)
            self._update_progress(20, "Testing default credentials")
            default_creds = payloads["auth_issues"][0]["payload"]
            for cred_pair in default_creds:
                username, password = cred_pair.split(":")
                if self._test_default_creds(target, username, password):
                    results["default_creds"].append(cred_pair)
                    if self.verbose:
                        print(f"  [!] Found default credentials: {cred_pair}")

            # Phase 2: Bruteforce vulnerability (40%)
            self._update_progress(40, "Checking rate limiting")
            results["bruteforce_vuln"] = self._check_bruteforce_vuln(target)
            if self.verbose and results["bruteforce_vuln"]:
                print("  [!] Potential bruteforce vulnerability detected")

            # Phase 3: Login bypass (60%)
            self._update_progress(60, "Testing login bypass")
            bypass_payloads = payloads["auth_issues"][2]["payload"]
            for payload in bypass_payloads:
                if self._test_login_bypass(target, payload):
                    results["login_bypass"] = True
                    if self.verbose:
                        print(f"  [!] Login bypass successful with payload: {payload}")
                    break

            # Phase 4: Form security analysis (80%)
            self._update_progress(80, "Analyzing login forms")
            results["form_issues"] = self._analyze_login_forms(target)
            if self.verbose and results["form_issues"]:
                print("  [!] Found form security issues")

            # Phase 5: CSRF protection check (90%)
            self._update_progress(90, "Checking CSRF protection")
            results["csrf_issues"] = self._check_csrf_protection(target)
            if self.verbose and results["csrf_issues"]:
                print("  [!] CSRF protection missing or weak")

            # Completion
            self._update_progress(100, "Authentication checks completed")
            self._print_results(results, "Authentication Checks")
            self._offer_save_results(results)
            return results

        except Exception as e:
            error_msg = f"Authentication check failed: {str(e)}"
            self._update_progress(100, error_msg, is_error=True)
            return {"error": error_msg}

    def header_checks(self, target: str) -> Dict:
        """Comprehensive security header analysis"""
        results = {
            "missing_headers": [],
            "weak_headers": {},
            "debug_mode": False,
            "cors_misconfig": False,
            "meta_tags": {},
            "server_info": {}
        }
        payloads = SecurityMisconfigPayloads.get_payloads(self.payload_size)
        self.total_tests = 5  # Headers, debug, CORS, meta, server info

        # Initialization
        if not self.verbose:
            print(Colors.header("\n[+] Testing Security Headers"))
        else:
            print(Colors.header("\n[+] Starting Header Checks"))
            print(f"Target: {target}")
            print(f"Payload size: {self.payload_size}\n")

        try:
            resp = self.session.get(target)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Phase 1: Security headers (20%)
            self._update_progress(20, "Checking security headers")
            security_headers = payloads["header_checks"][0]["headers"]
            for header in security_headers:
                if header not in resp.headers:
                    results["missing_headers"].append(header)
                    if self.verbose:
                        print(f"  [!] Missing header: {header}")
                else:
                    results["weak_headers"][header] = resp.headers[header]
                    if self.verbose:
                        print(f"  [i] Header found: {header}: {resp.headers[header]}")

            # Phase 2: Debug mode detection (40%)
            self._update_progress(40, "Checking debug mode")
            debug_indicators = payloads["header_checks"][1]["indicators"]
            for indicator in debug_indicators:
                if indicator in resp.text:
                    results["debug_mode"] = True
                    if self.verbose:
                        print(f"  [!] Debug indicator found: {indicator}")
                    break

            # Phase 3: CORS misconfiguration (60%)
            self._update_progress(60, "Checking CORS policy")
            results["cors_misconfig"] = self._check_cors_misconfig(target)
            if self.verbose and results["cors_misconfig"]:
                print("  [!] CORS misconfiguration detected")

            # Phase 4: Meta tag analysis (80%)
            self._update_progress(80, "Analyzing meta tags")
            results["meta_tags"] = self._analyze_meta_tags(soup)
            if self.verbose:
                for tag, present in results["meta_tags"].items():
                    status = "PRESENT" if present else "MISSING"
                    print(f"  [i] Meta tag '{tag}': {status}")

            # Phase 5: Server information (90%)
            self._update_progress(90, "Gathering server info")
            results["server_info"] = self._gather_server_info(resp)
            if self.verbose:
                for key, value in results["server_info"].items():
                    print(f"  [i] {key}: {value}")

            # Completion
            self._update_progress(100, "Header checks completed")
            self._print_results(results, "Header Checks")
            self._offer_save_results(results)
            return results

        except Exception as e:
            error_msg = f"Header check failed: {str(e)}"
            self._update_progress(100, error_msg, is_error=True)
            return {"error": error_msg}

    def path_checks(self, target: str) -> Dict:
        """Advanced sensitive path detection with BeautifulSoup"""
        results = {
            "admin_panels": [],
            "config_files": [],
            "directory_listing": [],
            "vulnerable_endpoints": [],
            "exposed_files": []
        }
        payloads = SecurityMisconfigPayloads.get_payloads(self.payload_size)
        
        # Calculate total tests
        admin_paths = len(payloads["sensitive_paths"][0]["paths"])
        config_paths = len(payloads["sensitive_paths"][1]["paths"])
        dir_paths = len(payloads["sensitive_paths"][2]["paths"])
        self.total_tests = admin_paths + config_paths + dir_paths + 2  # + endpoints + files

        # Initialization
        if not self.verbose:
            print(Colors.header("\n[+] Testing Sensitive Paths"))
        else:
            print(Colors.header("\n[+] Starting Path Checks"))
            print(f"Target: {target}")
            print(f"Payload size: {self.payload_size}\n")

        try:
            # Phase 1: Admin panels (20%)
            self._update_progress(20, "Scanning for admin panels")
            admin_paths = payloads["sensitive_paths"][0]["paths"]
            for path in admin_paths:
                url = urljoin(target, path)
                status, content_type = self._check_url(url)
                if status == 200 and "html" in content_type:
                    soup = self._get_page_soup(url)
                    if self._is_admin_panel(soup):
                        panel_info = {
                            "url": url,
                            "title": soup.title.string if soup.title else "No title",
                            "status": status
                        }
                        results["admin_panels"].append(panel_info)
                        if self.verbose:
                            print(f"  [!] Admin panel found: {url}")

            # Phase 2: Config files (40%)
            self._update_progress(40, "Scanning for config files")
            config_paths = payloads["sensitive_paths"][1]["paths"]
            for path in config_paths:
                url = urljoin(target, path)
                status, content_type = self._check_url(url)
                if status == 200:
                    file_info = {
                        "url": url,
                        "type": path.split('.')[-1] if '.' in path else "unknown",
                        "status": status
                    }
                    results["config_files"].append(file_info)
                    if self.verbose:
                        print(f"  [!] Config file found: {url}")

            # Phase 3: Directory listing (60%)
            self._update_progress(60, "Checking directory listing")
            dir_paths = payloads["sensitive_paths"][2]["paths"]
            for path in dir_paths:
                url = urljoin(target, path)
                if self._is_directory_listing(url):
                    results["directory_listing"].append(url)
                    if self.verbose:
                        print(f"  [!] Directory listing enabled: {url}")

            # Phase 4: Vulnerable endpoints (80%)
            self._update_progress(80, "Finding vulnerable endpoints")
            results["vulnerable_endpoints"] = self._find_vulnerable_endpoints(target)
            if self.verbose and results["vulnerable_endpoints"]:
                for endpoint in results["vulnerable_endpoints"]:
                    print(f"  [!] Vulnerable endpoint: {endpoint}")

            # Phase 5: Exposed files (90%)
            self._update_progress(90, "Checking for exposed files")
            results["exposed_files"] = self._find_exposed_files(target)
            if self.verbose and results["exposed_files"]:
                for file in results["exposed_files"]:
                    print(f"  [!] Exposed file: {file}")

            # Completion
            self._update_progress(100, "Path checks completed")
            self._print_results(results, "Path Checks")
            self._offer_save_results(results)
            return results

        except Exception as e:
            error_msg = f"Path check failed: {str(e)}"
            self._update_progress(100, error_msg, is_error=True)
            return {"error": error_msg}

    # ======================
    # Advanced Detection Methods
    # ======================

    def _is_admin_panel(self, soup: BeautifulSoup) -> bool:
        """Detect admin panels using multiple indicators"""
        # Check page title
        title = soup.title.string.lower() if soup.title else ""
        admin_titles = ["admin", "dashboard", "control panel", "login", "sign in"]
        if any(term in title for term in admin_titles):
            return True

        # Check form fields
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            has_username = any(i.get('name', '').lower() in ['username', 'email'] for i in inputs)
            has_password = any(i.get('type') == 'password' for i in inputs)
            if has_username and has_password:
                return True

        # Check common admin panel text
        text = soup.get_text().lower()
        admin_terms = [
            'administrator', 'welcome admin', 'user management',
            'system configuration', 'privileged access'
        ]
        return any(term in text for term in admin_terms)

    def _analyze_meta_tags(self, soup: BeautifulSoup) -> Dict:
        """Check for security-related meta tags"""
        security_meta = {
            'viewport': False,
            'csrf-token': False,
            'content-security-policy': False,
            'referrer': False,
            'x-ua-compatible': False
        }

        for meta in soup.find_all('meta'):
            # Check by name attribute
            name = meta.get('name', '').lower()
            if name in security_meta:
                security_meta[name] = True

            # Check by http-equiv attribute
            http_equiv = meta.get('http-equiv', '').lower()
            if http_equiv in security_meta:
                security_meta[http_equiv] = True

            # Special case for CSP
            if 'content-security-policy' in http_equiv.lower():
                security_meta['content-security-policy'] = True

        return security_meta

    def _analyze_login_forms(self, target: str) -> List[Dict]:
        """Comprehensive login form analysis"""
        issues = []
        login_url = self._detect_login(target)
        if not login_url:
            return issues

        try:
            resp = self.session.get(login_url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'issues': [],
                    'fields': []
                }

                # Collect all form fields
                for input_tag in form.find_all('input'):
                    form_data['fields'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text')
                    })

                # Check for password field
                if not any(f['type'] == 'password' for f in form_data['fields']):
                    form_data['issues'].append('Missing password field')

                # Check form action security
                if form_data['action'].startswith('http://'):
                    form_data['issues'].append('Form submits over HTTP')

                # Check for CSRF protection
                csrf_fields = [
                    f['name'].lower() for f in form_data['fields'] 
                    if 'csrf' in f['name'].lower()
                ]
                if not csrf_fields:
                    form_data['issues'].append('Missing CSRF token')

                # Check autocomplete
                if form.get('autocomplete', '').lower() == 'off':
                    form_data['issues'].append('Autocomplete disabled')

                if form_data['issues']:
                    issues.append(form_data)

        except Exception as e:
            if self.verbose:
                print(f"  [!] Form analysis error: {str(e)}")

        return issues

    def _is_directory_listing(self, url: str) -> bool:
        """Advanced directory listing detection"""
        try:
            resp = self.session.get(url)
            if resp.status_code != 200:
                return False

            # Check common indicators in response
            indicators = [
                'index of', 'directory listing', 'parent directory',
                '<title>directory</title>', '<directory>',
                'last modified', 'size</th>', 'name</th>'
            ]
            text = resp.text.lower()
            if any(indicator in text for indicator in indicators):
                return True

            # Check for common directory listing patterns
            soup = BeautifulSoup(resp.text, 'html.parser')
            tables = soup.find_all('table')
            for table in tables:
                headers = [th.get_text().lower() for th in table.find_all('th')]
                if 'name' in headers and ('size' in headers or 'last modified' in headers):
                    return True

            return False
        except:
            return False

    def _find_vulnerable_endpoints(self, target: str) -> List[str]:
        """Discover potentially vulnerable API endpoints"""
        vulnerable = []
        common_endpoints = [
            '/api/', '/v1/', '/v2/', '/admin/', '/wp-admin/',
            '/console/', '/phpmyadmin/', '/debug/', '/swagger/',
            '/graphql', '/rest/', '/oauth/', '/auth/'
        ]

        for endpoint in common_endpoints:
            url = urljoin(target, endpoint)
            status, content_type = self._check_url(url)
            if status in [200, 403, 401]:  # 403/401 might indicate protected but existing
                vulnerable.append(url)

        return vulnerable

    def _find_exposed_files(self, target: str) -> List[str]:
        """Find exposed sensitive files"""
        exposed = []
        common_files = [
            '/.env', '/.htaccess', '/web.config',
            '/package.json', '/composer.json',
            '/config.php', '/settings.py',
            '/README.md', '/CHANGELOG.txt'
        ]

        for file_path in common_files:
            url = urljoin(target, file_path)
            status, content_type = self._check_url(url)
            if status == 200:
                exposed.append(url)

        return exposed

    def _check_csrf_protection(self, target: str) -> bool:
        """Check for CSRF protection mechanisms"""
        login_url = self._detect_login(target)
        if not login_url:
            return False

        try:
            resp = self.session.get(login_url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Check for CSRF token in forms
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                csrf_fields = [
                    i for i in inputs 
                    if 'csrf' in i.get('name', '').lower() or 'token' in i.get('name', '').lower()
                ]
                if not csrf_fields:
                    return True  # Vulnerability exists

            return False  # No vulnerability found
        except:
            return True  # Assume vulnerable if check fails

    def _gather_server_info(self, response: requests.Response) -> Dict:
        """Extract server information from headers"""
        server_info = {}
        headers = response.headers

        # Server software
        if 'server' in headers:
            server_info['server_software'] = headers['server']
        
        # Powered by
        if 'x-powered-by' in headers:
            server_info['powered_by'] = headers['x-powered-by']
        
        # Framework detection
        if 'x-django-version' in headers:
            server_info['framework'] = f"Django {headers['x-django-version']}"
        elif 'x-aspnet-version' in headers:
            server_info['framework'] = f"ASP.NET {headers['x-aspnet-version']}"
        
        # PHP version
        if 'x-php-version' in headers:
            server_info['php_version'] = headers['x-php-version']

        return server_info

    # ======================
    # Core Test Methods
    # ======================

    def _test_default_creds(self, target: str, username: str, password: str) -> bool:
        """Test default credentials on login forms"""
        login_url = self._detect_login(target)
        if not login_url:
            return False

        try:
            # First get the login page to capture any CSRF tokens
            resp = self.session.get(login_url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Prepare form data
            form_data = {
                'username': username,
                'password': password
            }

            # Find and add CSRF token if present
            csrf_token = soup.find('input', {'name': lambda x: x and 'csrf' in x.lower()})
            if csrf_token:
                form_data[csrf_token['name']] = csrf_token.get('value', '')

            # Submit login
            resp = self.session.post(login_url, data=form_data)

            # Check for successful login indicators
            return (
                resp.status_code == 302 or  # Redirect after login
                'logout' in resp.text.lower() or
                'welcome' in resp.text.lower() or
                username.lower() in resp.text.lower()
            )
        except:
            return False

    def _check_bruteforce_vuln(self, target: str) -> bool:
        """Check if application is vulnerable to brute force attacks"""
        login_url = self._detect_login(target)
        if not login_url:
            return False

        try:
            # Test with 10 rapid login attempts
            responses = []
            for i in range(10):
                form_data = {
                    'username': f'testuser{i}',
                    'password': 'wrongpassword'
                }
                resp = self.session.post(login_url, data=form_data)
                responses.append(resp.status_code)

                # If we get blocked early, exit
                if resp.status_code == 429 or 'locked' in resp.text.lower():
                    return False

            # If all responses are the same (no blocking occurred)
            return len(set(responses)) == 1
        except:
            return False

    def _test_login_bypass(self, target: str, payload: str) -> bool:
        """Test for SQL injection or other login bypass techniques"""
        login_url = self._detect_login(target)
        if not login_url:
            return False

        try:
            # Get login page to capture CSRF token
            resp = self.session.get(login_url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Prepare malicious payload
            form_data = {
                'username': payload,
                'password': 'anything'
            }

            # Add CSRF token if present
            csrf_token = soup.find('input', {'name': lambda x: x and 'csrf' in x.lower()})
            if csrf_token:
                form_data[csrf_token['name']] = csrf_token.get('value', '')

            # Submit malicious login
            resp = self.session.post(login_url, data=form_data)

            # Check for bypass success
            return (
                resp.status_code == 302 or  # Redirect after "successful" login
                'logout' in resp.text.lower() or
                'welcome' in resp.text.lower()
            )
        except:
            return False

    def _check_cors_misconfig(self, target: str) -> bool:
        """Check for CORS misconfigurations"""
        try:
            # Send OPTIONS request with malicious origin
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'X-Requested-With'
            }
            resp = self.session.options(target, headers=headers)

            # Check for dangerous CORS headers
            cors_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            cors_creds = resp.headers.get('Access-Control-Allow-Credentials', '')

            return (
                cors_origin == '*' or
                cors_origin == 'null' or
                (cors_origin == 'https://evil.com' and cors_creds.lower() == 'true')
            )
        except:
            return False

    # ======================
    # Utility Methods
    # ======================

    def _check_url(self, url: str) -> Tuple[int, str]:
        """Check URL and return status code and content type"""
        try:
            resp = self.session.get(url, timeout=5, allow_redirects=False)
            return resp.status_code, resp.headers.get('content-type', '').lower()
        except:
            return 0, ''

    def _get_page_soup(self, url: str) -> BeautifulSoup:
        """Get BeautifulSoup object for a URL"""
        try:
            resp = self.session.get(url, timeout=5)
            return BeautifulSoup(resp.text, 'html.parser')
        except:
            return BeautifulSoup('', 'html.parser')

    def _detect_login(self, target: str) -> Optional[str]:
        """Detect login page URL"""
        common_paths = [
            '/login', '/signin', '/auth',
            '/admin', '/wp-login.php',
            '/account/login', '/user/login'
        ]

        for path in common_paths:
            url = urljoin(target, path)
            status, content_type = self._check_url(url)
            if status == 200 and 'html' in content_type:
                # Verify it's actually a login page
                soup = self._get_page_soup(url)
                if self._is_login_page(soup):
                    return url
        return None

    def _is_login_page(self, soup: BeautifulSoup) -> bool:
        """Determine if page is a login form"""
        # Check for password fields
        if soup.find('input', {'type': 'password'}):
            return True

        # Check common login text
        text = soup.get_text().lower()
        login_terms = [
            'login', 'sign in', 'username',
            'password', 'authenticate'
        ]
        return any(term in text for term in login_terms)

    def _update_progress(self, progress: int, message: str, is_error: bool = False):
        """Update and display progress"""
        self.current_progress = progress
        if is_error:
            msg = Colors.error(f"[{progress}%] {message}")
        else:
            msg = Colors.info(f"[{progress}%] {message}")

        # In verbose mode or for important messages
        if self.verbose or progress % 25 == 0 or progress == 100 or is_error:
            print(msg)

    def _print_results(self, results: Dict, title: str):
        """Print formatted results with severity indicators"""
        print(Colors.header(f"\n{title} Results:"))

        for category, findings in results.items():
            if not findings:
                print(Colors.success(f"[✓] No {category.replace('_', ' ')} found"))
                continue

            print(Colors.error(f"[!] {category.replace('_', ' ').title()}:"))
            
            if isinstance(findings, list):
                for item in findings:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            print(f"  - {k}: {v}")
                        print()
                    else:
                        print(f"  - {item}")
            elif isinstance(findings, dict):
                for k, v in findings.items():
                    print(f"  - {k}: {v}")
            elif isinstance(findings, bool):
                print("  - Vulnerability confirmed")
            else:
                print(f"  - {findings}")

    def _offer_save_results(self, results: Dict):
        """Offer to save results to JSON file"""
        if not self.verbose:
            return

        try:
            save = input("\nSave results to JSON file? (y/n): ").lower()
            if save != 'y':
                return

            default_name = f"a05_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filename = input(f"Enter filename (default: {default_name}): ").strip()
            filename = filename if filename else default_name

            if not filename.endswith('.json'):
                filename += '.json'

            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)

            print(Colors.success(f"\nResults saved to {os.path.abspath(filename)}"))
        except Exception as e:
            print(Colors.error(f"\nFailed to save results: {str(e)}"))