import json
import re
import requests
import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pathlib import Path
from colors import Colors
from .payloads import AuthenticationPayloads

class AuthenticationFailuresAssessment:
    def __init__(self):
        self.payload_size = "medium"
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Basic Authentication Checks",
                "description": "Test for weak login forms and credential handling",
                "function": self.assess_basic_auth
            },
            "2": {
                "id": "2",
                "name": "Session Management Audit",
                "description": "Analyze session cookies and tokens",
                "function": self.assess_session_management
            },
            "3": {
                "id": "3",
                "name": "Comprehensive Authentication Audit",
                "description": "Full authentication mechanism assessment",
                "function": self.assess_comprehensive
            },
            "4": {
                "id": "4",
                "name": "Dynamic Form Detection",
                "description": "Find and test all authentication forms",
                "function": self.assess_dynamic_forms
            }
        }
        self.results = []
        self.target = None
        self.verbose = False
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ROGUEv2-Scanner/1.0'})
        self.payloads = AuthenticationPayloads.get_payloads(self.payload_size)
        self.tech_stack = None

    def set_payload_size(self, size):
        """Set the payload size (small, medium, large)"""
        self.payload_size = size.lower()
        if self.payload_size not in ["small", "medium", "large"]:
            self.payload_size = "medium"
        self.payloads = AuthenticationPayloads.get_payloads(self.payload_size)

    def show_techniques(self):
        """Display available techniques in a numbered list"""
        print(Colors.header("\nAvailable Techniques for A07:2021 - Identification and Authentication Failures:"))
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

    def run_assessment(self, technique_id, target, verbose=False):
        """Run the specified assessment technique with professional output"""
        if technique_id not in self.techniques:
            print(Colors.error(f"Invalid technique ID: {technique_id}"))
            return

        self.target = target.rstrip('/')
        self.verbose = verbose
        technique = self.techniques[technique_id]
        self.results = []  # Clear previous results
        self._detect_tech_stack()

        # Print scan header
        print(Colors.header("\n" + "-" * 50))
        print(Colors.header(f" Running: {technique['name']}"))
        print(Colors.header(f" Target: {self.target}"))
        print(Colors.header(f" Payload size: {self.payload_size.capitalize()}"))
        if self.tech_stack:
            print(Colors.header(f" Detected Tech: {', '.join(self.tech_stack)}"))
        print(Colors.header("-" * 50 + "\n"))

        try:
            technique["function"]()
            self._generate_professional_report()
            
            save_report = input(Colors.prompt("\nSave Report? (y/n): ")).lower()
            if save_report in ['y', 'yes']:
                self.save_report_to_file()
                
        except Exception as e:
            print(Colors.error(f"\n[!] Assessment failed: {e}"))

    def _detect_tech_stack(self):
        """Detect technology stack of target"""
        self.tech_stack = []
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            
            # Check headers
            server_header = response.headers.get('Server', '').lower()
            if 'apache' in server_header:
                self.tech_stack.append('Apache')
            elif 'nginx' in server_header:
                self.tech_stack.append('Nginx')
            elif 'iis' in server_header:
                self.tech_stack.append('IIS')
                
            # Check cookies
            for cookie in response.cookies:
                if 'php' in cookie.name.lower():
                    self.tech_stack.append('PHP')
                    break
                elif 'jsessionid' in cookie.name.lower():
                    self.tech_stack.append('Java')
                    break
                    
            # Check HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check meta tags
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator:
                content = meta_generator.get('content', '').lower()
                if 'wordpress' in content:
                    self.tech_stack.append('WordPress')
                elif 'drupal' in content:
                    self.tech_stack.append('Drupal')
                elif 'joomla' in content:
                    self.tech_stack.append('Joomla')
                    
            # Check scripts
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                if 'jquery' in src:
                    self.tech_stack.append('jQuery')
                if 'react' in src:
                    self.tech_stack.append('React')
                if 'angular' in src:
                    self.tech_stack.append('Angular')
                    
            # Check common framework patterns
            if 'wp-content' in response.text:
                self.tech_stack.append('WordPress')
            if '/media/jui/' in response.text:
                self.tech_stack.append('Joomla')
            if 'drupal.js' in response.text:
                self.tech_stack.append('Drupal')
                
        except Exception as e:
            if self.verbose:
                print(Colors.error(f"Error detecting tech stack: {e}"))

    def assess_basic_auth(self):
        """Check for weak authentication mechanisms"""
        print(Colors.info("\n🔍 Step 1: Identifying Authentication Endpoints (0%)"))
        self._update_progress(0, 4, "Scanning for login pages")
        
        # Find login endpoints
        login_pages = self._find_login_pages()
        if not login_pages:
            print(Colors.warning("\nNo login pages found with default payloads"))
            return

        self._update_progress(1, 4, "Testing common credentials (25%)")
        # Test for default credentials
        self._test_common_credentials(login_pages)

        self._update_progress(2, 4, "Checking password policies (50%)")
        # Check password policies
        self._check_password_policies(login_pages)

        self._update_progress(3, 4, "Testing HTTP Auth headers (75%)")
        # Check HTTP authentication headers
        self._check_http_auth_headers()

        self._update_progress(4, 4, "Completed basic auth checks (100%)")
        print()

    def assess_session_management(self):
        """Analyze session management issues"""
        print(Colors.info("\n🔍 Analyzing Session Management (0%)"))
        self._update_progress(0, 3, "Checking session cookies (0%)")
        
        # Check session cookies
        self._check_session_cookies()

        self._update_progress(1, 3, "Verifying token security (33%)")
        # Check auth tokens
        self._check_auth_tokens()

        self._update_progress(2, 3, "Testing CSRF protection (66%)")
        # Check CSRF protection
        self._check_csrf_protection()

        self._update_progress(3, 3, "Completed session analysis (100%)")
        print()

    def assess_comprehensive(self):
        """Run full authentication assessment"""
        print(Colors.header("\n🚀 Starting Comprehensive Authentication Audit (0%)"))
        self.assess_basic_auth()
        self.assess_session_management()
        self._check_for_credential_leaks()
        self._check_auth_methods()
        print(Colors.success("\n✅ Comprehensive audit completed (100%)"))

    def assess_dynamic_forms(self):
        """Dynamically find and test all authentication forms"""
        print(Colors.info("\n🔍 Dynamic Form Detection (0%)"))
        self._update_progress(0, 3, "Crawling for forms (0%)")
        
        forms = self._find_all_forms()
        if not forms:
            print(Colors.warning("\nNo forms found on target"))
            return
            
        auth_forms = self._identify_auth_forms(forms)
        if not auth_forms:
            print(Colors.warning("\nNo authentication forms identified"))
            return
            
        self._update_progress(1, 3, "Testing identified forms (33%)")
        self._test_auth_forms(auth_forms)
        
        self._update_progress(2, 3, "Analyzing form security (66%)")
        self._analyze_form_security(auth_forms)
        
        self._update_progress(3, 3, "Completed dynamic form analysis (100%)")
        print()

    def _find_login_pages(self):
        """Locate login pages on target using dynamic detection"""
        found_pages = []
        endpoints_to_check = set(self.payloads["login_endpoints"])
        
        # Add technology-specific paths
        if self.tech_stack:
            if 'WordPress' in self.tech_stack:
                endpoints_to_check.update(['/wp-admin', '/wp-login.php'])
            if 'Drupal' in self.tech_stack:
                endpoints_to_check.add('/user/login')
            if 'Joomla' in self.tech_stack:
                endpoints_to_check.add('/administrator')
        
        total = len(endpoints_to_check)
        
        for i, endpoint in enumerate(endpoints_to_check, 1):
            url = urljoin(self.target, endpoint)
            try:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    login_form = self._is_login_form(soup)
                    if login_form:
                        found_pages.append({
                            "url": url,
                            "title": soup.title.string if soup.title else "No title",
                            "form": login_form
                        })
            except requests.RequestException:
                continue
            
            self._update_progress(i, total, f"Checking login endpoints ({int((i/total)*100)}%)")
        
        return found_pages

    def _is_login_form(self, soup):
        """Determine if a form is a login form"""
        forms = soup.find_all('form')
        for form in forms:
            # Check for password field
            if form.find('input', {'type': 'password'}):
                return form
            # Check for common login form attributes
            if form.get('id', '').lower() in ['login-form', 'signin-form']:
                return form
            if form.get('name', '').lower() in ['login', 'signin']:
                return form
        return None

    def _test_common_credentials(self, login_pages):
        """Test for default/weak credentials with dynamic form handling"""
        for page in login_pages:
            url = page["url"]
            form = page.get("form")
            
            if form:
                # Dynamic form submission
                form_data = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('type') == 'password':
                        form_data[input_tag.get('name', 'password')] = 'test'
                    elif input_tag.get('type') == 'text':
                        form_data[input_tag.get('name', 'username')] = 'admin'
                    elif input_tag.get('type') == 'hidden':
                        form_data[input_tag.get('name')] = input_tag.get('value', '')
                
                action = form.get('action', url)
                method = form.get('method', 'get').lower()
                action_url = urljoin(url, action)
                
                for username, password in self.payloads["common_credentials"]:
                    try:
                        # Update form data with current credentials
                        for name, value in form_data.items():
                            if 'pass' in name.lower():
                                form_data[name] = password
                            elif 'user' in name.lower() or 'name' in name.lower():
                                form_data[name] = username
                                
                        if method == 'post':
                            response = self.session.post(action_url, 
                                                       data=form_data,
                                                       timeout=5,
                                                       allow_redirects=False)
                        else:
                            response = self.session.get(action_url, 
                                                      params=form_data,
                                                      timeout=5,
                                                      allow_redirects=False)
                            
                        if self._is_successful_login(response):
                            self.results.append({
                                "type": "Weak Credentials",
                                "name": f"Default credentials work: {username}/{password}",
                                "url": url,
                                "severity": "Critical",
                                "details": f"Default credentials {username}/{password} provide access to {url}",
                                "recommendation": "Change default credentials and implement account lockout"
                            })
                            break
                            
                    except requests.RequestException:
                        continue
            else:
                # Fallback to standard POST attempt
                for username, password in self.payloads["common_credentials"]:
                    try:
                        response = self.session.post(url, 
                                                   data={'username': username, 'password': password},
                                                   timeout=5,
                                                   allow_redirects=False)
                        if self._is_successful_login(response):
                            self.results.append({
                                "type": "Weak Credentials",
                                "name": f"Default credentials work: {username}/{password}",
                                "url": url,
                                "severity": "Critical",
                                "details": f"Default credentials {username}/{password} provide access to {url}",
                                "recommendation": "Change default credentials and implement account lockout"
                            })
                            break
                    except requests.RequestException:
                        continue

    def _is_successful_login(self, response):
        """Determine if login was successful"""
        if response.status_code in [301, 302]:
            return True
        if 'logout' in response.text.lower():
            return True
        if 'welcome' in response.text.lower():
            return True
        if 'invalid' not in response.text.lower() and 'incorrect' not in response.text.lower():
            # If no explicit failure message, might be successful
            return True
        return False

    def _check_password_policies(self, login_pages):
        """Check for weak password policies with dynamic form handling"""
        for page in login_pages:
            url = page["url"]
            form = page.get("form")
            
            if form:
                # Dynamic form submission for password policy check
                form_data = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('type') == 'password':
                        form_data[input_tag.get('name', 'password')] = 'weakpassword'
                    elif input_tag.get('type') == 'text':
                        form_data[input_tag.get('name', 'username')] = 'testuser'
                    elif input_tag.get('type') == 'hidden':
                        form_data[input_tag.get('name')] = input_tag.get('value', '')
                
                action = form.get('action', url)
                method = form.get('method', 'get').lower()
                action_url = urljoin(url, action)
                
                for weak_pwd in self.payloads["password_policy_checks"]:
                    try:
                        # Update password in form data
                        for name, value in form_data.items():
                            if 'pass' in name.lower():
                                form_data[name] = weak_pwd
                                
                        if method == 'post':
                            response = self.session.post(action_url, 
                                                       data=form_data,
                                                       timeout=5)
                        else:
                            response = self.session.get(action_url, 
                                                      params=form_data,
                                                      timeout=5)
                            
                        if not self._detect_password_policy(response):
                            self.results.append({
                                "type": "Weak Password Policy",
                                "name": f"Accepts weak password: {weak_pwd}",
                                "url": url,
                                "severity": "High",
                                "details": f"System accepts weak password: {weak_pwd} at {url}",
                                "recommendation": "Implement strong password policy with complexity requirements"
                            })
                            break
                    except requests.RequestException:
                        continue
            else:
                # Fallback to standard POST attempt
                for weak_pwd in self.payloads["password_policy_checks"]:
                    try:
                        response = self.session.post(url,
                                                   data={'password': weak_pwd, 'confirm_password': weak_pwd},
                                                   timeout=5)
                        if not self._detect_password_policy(response):
                            self.results.append({
                                "type": "Weak Password Policy",
                                "name": f"Accepts weak password: {weak_pwd}",
                                "url": url,
                                "severity": "High",
                                "details": f"System accepts weak password: {weak_pwd} at {url}",
                                "recommendation": "Implement strong password policy with complexity requirements"
                            })
                            break
                    except requests.RequestException:
                        continue

    def _detect_password_policy(self, response):
        """Check if response indicates password policy enforcement"""
        text = response.text.lower()
        if 'password is too weak' in text:
            return True
        if 'password must contain' in text:
            return True
        if 'minimum length' in text:
            return True
        if 'complexity requirements' in text:
            return True
        return False

    def _check_http_auth_headers(self):
        """Check for HTTP authentication headers"""
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            
            # Check for HTTP Basic Auth
            if response.status_code == 401 and 'WWW-Authenticate' in response.headers:
                auth_header = response.headers['WWW-Authenticate']
                self.results.append({
                    "type": "HTTP Authentication",
                    "name": "HTTP Basic Authentication Enabled",
                    "url": self.target,
                    "severity": "Medium",
                    "details": f"Server uses HTTP Basic Auth: {auth_header}",
                    "recommendation": "Consider using more secure authentication methods"
                })
                
            # Check for auth headers in requests
            for header in self.payloads["auth_headers"]:
                if header in response.request.headers:
                    self.results.append({
                        "type": "Auth Header Exposure",
                        "name": f"Authentication header detected: {header}",
                        "url": self.target,
                        "severity": "High",
                        "details": f"Authentication header {header} is exposed in requests",
                        "recommendation": "Ensure sensitive headers are properly secured"
                    })
                    
        except requests.RequestException as e:
            if self.verbose:
                print(Colors.error(f"Error checking HTTP auth: {e}"))

    def _check_session_cookies(self):
        """Analyze session cookie security with enhanced checks"""
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            cookies = response.cookies
            
            for cookie in cookies:
                if any(name.lower() in cookie.name.lower() for name in self.payloads["session_cookies"]):
                    findings = []
                    if not cookie.secure:
                        findings.append("Missing Secure flag")
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        findings.append("Missing HttpOnly flag")
                    if cookie.expires and cookie.expires > datetime.datetime.now().timestamp() + 31536000:  # 1 year
                        findings.append("Excessive expiration time")
                    if 'samesite' not in cookie.__dict__.get('_rest', {}):
                        findings.append("Missing SameSite attribute")
                    
                    if findings:
                        self.results.append({
                            "type": "Session Misconfiguration",
                            "name": f"Cookie: {cookie.name}",
                            "url": self.target,
                            "severity": "High",
                            "details": ", ".join(findings),
                            "recommendation": "Set Secure, HttpOnly, SameSite flags and proper expiration"
                        })
                        
                    # Check for session fixation
                    if not cookie.has_nonstandard_attr('SameSite'):
                        self.results.append({
                            "type": "Session Fixation Risk",
                            "name": f"Cookie {cookie.name} vulnerable to fixation",
                            "url": self.target,
                            "severity": "Medium",
                            "details": "Cookie missing SameSite attribute allows session fixation",
                            "recommendation": "Implement SameSite cookie attribute"
                        })
        except requests.RequestException as e:
            if self.verbose:
                print(Colors.error(f"Error checking cookies: {e}"))

    def _check_auth_tokens(self):
        """Check for exposed auth tokens in JS files and local storage"""
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check script files for exposed tokens
            for script in soup.find_all('script', src=True):
                script_url = urljoin(self.target, script['src'])
                try:
                    script_content = requests.get(script_url, timeout=5).text
                    for keyword in self.payloads["sensitive_keywords"]:
                        matches = re.findall(fr'{keyword}["\']?\s*:\s*["\']([a-zA-Z0-9_-]+)', script_content)
                        if matches:
                            for match in matches:
                                self.results.append({
                                    "type": "Exposed Credentials",
                                    "name": f"Hardcoded {keyword} found",
                                    "url": script_url,
                                    "severity": "Critical",
                                    "details": f"{keyword}: {match[:10]}... (truncated)",
                                    "recommendation": "Remove credentials from client-side code"
                                })
                except requests.RequestException:
                    continue
                    
            # Check localStorage access in JavaScript
            inline_scripts = soup.find_all('script', src=False)
            for script in inline_scripts:
                if script.string:
                    for keyword in self.payloads["sensitive_keywords"]:
                        if f"localStorage.setItem('{keyword}" in script.string:
                            self.results.append({
                                "type": "LocalStorage Exposure",
                                "name": f"Sensitive data stored in localStorage",
                                "url": self.target,
                                "severity": "High",
                                "details": f"Potential {keyword} storage in localStorage",
                                "recommendation": "Avoid storing sensitive data in client-side storage"
                            })
        except requests.RequestException as e:
            if self.verbose:
                print(Colors.error(f"Error checking auth tokens: {e}"))

    def _check_csrf_protection(self):
        """Check for CSRF protection mechanisms"""
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            csrf_protected = False
            
            for form in forms:
                # Check for CSRF token input
                if form.find('input', {'name': 'csrf_token'}):
                    csrf_protected = True
                if form.find('input', {'name': '_token'}):  # Laravel style
                    csrf_protected = True
                if form.find('input', {'name': 'authenticity_token'}):  # Rails style
                    csrf_protected = True
                    
                # Check for custom headers
                if form.get('data-csrf', False):
                    csrf_protected = True
                    
            if not csrf_protected and forms:
                self.results.append({
                    "type": "CSRF Vulnerability",
                    "name": "Missing CSRF Protection",
                    "url": self.target,
                    "severity": "High",
                    "details": "Forms lack CSRF protection tokens",
                    "recommendation": "Implement CSRF tokens for all state-changing operations"
                })
        except requests.RequestException as e:
            if self.verbose:
                print(Colors.error(f"Error checking CSRF protection: {e}"))

    def _check_for_credential_leaks(self):
        """Check for credential leaks in public files with dynamic detection"""
        print(Colors.info("\n🔍 Checking for Credential Leaks (0%)"))
        
        files_to_check = set(self.payloads["config_files"])
        
        # Add technology-specific files
        if self.tech_stack:
            if 'WordPress' in self.tech_stack:
                files_to_check.update(['/wp-config.php', '/wp-config-sample.php'])
            if 'Drupal' in self.tech_stack:
                files_to_check.add('/sites/default/settings.php')
            if 'Laravel' in self.tech_stack:
                files_to_check.add('/.env.example')
        
        total = len(files_to_check)
        
        for i, file in enumerate(files_to_check, 1):
            url = urljoin(self.target, file)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    for keyword in self.payloads["sensitive_keywords"]:
                        if keyword in content:
                            self.results.append({
                                "type": "Exposed Credentials",
                                "name": f"Sensitive data in {file}",
                                "url": url,
                                "severity": "Critical",
                                "details": f"File contains potential {keyword}: {url}",
                                "recommendation": "Restrict access to configuration files"
                            })
                            break
            except requests.RequestException:
                continue
            
            self._update_progress(i, total, f"Checking sensitive files ({int((i/total)*100)}%)")
    
    def _check_auth_methods(self):
        """Check authentication methods in use"""
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            
            # Check for JWT tokens
            if 'authorization' in response.request.headers:
                auth_header = response.request.headers['authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    if len(token.split('.')) == 3:  # Likely JWT
                        self.results.append({
                            "type": "Authentication Method",
                            "name": "JWT Authentication Detected",
                            "url": self.target,
                            "severity": "Info",
                            "details": "JWT tokens are being used for authentication",
                            "recommendation": "Ensure proper JWT implementation with signature verification"
                        })
            
            # Check for OAuth
            if 'oauth' in response.text.lower() or '/oauth2/' in response.text.lower():
                self.results.append({
                    "type": "Authentication Method",
                    "name": "OAuth Authentication Detected",
                    "url": self.target,
                    "severity": "Info",
                    "details": "OAuth protocol is being used for authentication",
                    "recommendation": "Verify OAuth implementation follows security best practices"
                })
                
            # Check for vulnerable methods
            for method in self.payloads.get("vulnerable_auth_methods", []):
                if method.lower() in response.text.lower():
                    self.results.append({
                        "type": "Vulnerable Authentication",
                        "name": f"Vulnerable Auth Method: {method}",
                        "url": self.target,
                        "severity": "High",
                        "details": f"Vulnerable authentication method detected: {method}",
                        "recommendation": "Upgrade to more secure authentication method"
                    })
                    
        except requests.RequestException as e:
            if self.verbose:
                print(Colors.error(f"Error checking auth methods: {e}"))

    def _find_all_forms(self):
        """Find all forms on the target page"""
        try:
            response = self.session.get(self.target, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except requests.RequestException:
            return []

    def _identify_auth_forms(self, forms):
        """Identify authentication forms from all forms"""
        auth_forms = []
        for form in forms:
            if self._is_login_form(form):
                auth_forms.append({
                    "form": form,
                    "action": form.get('action', self.target),
                    "method": form.get('method', 'get').lower()
                })
        return auth_forms

    def _test_auth_forms(self, auth_forms):
        """Test identified authentication forms"""
        for auth_form in auth_forms:
            form = auth_form["form"]
            action = auth_form["action"]
            method = auth_form["method"]
            action_url = urljoin(self.target, action)
            
            # Build form data
            form_data = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('type') == 'password':
                    form_data[input_tag.get('name', 'password')] = 'testpassword'
                elif input_tag.get('type') == 'text':
                    form_data[input_tag.get('name', 'username')] = 'testuser'
                elif input_tag.get('type') == 'hidden':
                    form_data[input_tag.get('name')] = input_tag.get('value', '')
            
            # Test with common credentials
            for username, password in self.payloads["common_credentials"]:
                try:
                    # Update form data with current credentials
                    test_data = form_data.copy()
                    for name, value in test_data.items():
                        if 'pass' in name.lower():
                            test_data[name] = password
                        elif 'user' in name.lower() or 'name' in name.lower():
                            test_data[name] = username
                            
                    if method == 'post':
                        response = self.session.post(action_url, 
                                                   data=test_data,
                                                   timeout=5,
                                                   allow_redirects=False)
                    else:
                        response = self.session.get(action_url, 
                                                  params=test_data,
                                                  timeout=5,
                                                  allow_redirects=False)
                        
                    if self._is_successful_login(response):
                        self.results.append({
                            "type": "Form-based Authentication",
                            "name": f"Default credentials work on form: {username}/{password}",
                            "url": action_url,
                            "severity": "Critical",
                            "details": f"Form at {action_url} accepts default credentials {username}/{password}",
                            "recommendation": "Implement stronger authentication controls"
                        })
                        break
                except requests.RequestException:
                    continue

    def _analyze_form_security(self, auth_forms):
        """Analyze security aspects of authentication forms"""
        for auth_form in auth_forms:
            form = auth_form["form"]
            action = auth_form["action"]
            action_url = urljoin(self.target, action)
            
            # Check for HTTPS in form action
            if not action_url.startswith('https://'):
                self.results.append({
                    "type": "Form Security",
                    "name": "Form submits credentials over HTTP",
                    "url": action_url,
                    "severity": "High",
                    "details": f"Form at {action_url} submits credentials without HTTPS",
                    "recommendation": "Always use HTTPS for credential submission"
                })
                
            # Check for password autocomplete
            password_fields = form.find_all('input', {'type': 'password'})
            for field in password_fields:
                if field.get('autocomplete', 'on') != 'off':
                    self.results.append({
                        "type": "Form Security",
                        "name": "Password field allows autocomplete",
                        "url": action_url,
                        "severity": "Medium",
                        "details": f"Password field at {action_url} allows browser autocomplete",
                        "recommendation": "Add autocomplete='off' to password fields"
                    })
                    
            # Check for CSRF protection
            if not form.find('input', {'name': lambda x: x and 'csrf' in x.lower()}):
                self.results.append({
                    "type": "Form Security",
                    "name": "Missing CSRF protection in form",
                    "url": action_url,
                    "severity": "High",
                    "details": f"Form at {action_url} lacks CSRF protection",
                    "recommendation": "Add CSRF tokens to all forms"
                })

    def _generate_professional_report(self):
        """Generate professional formatted report"""
        if not self.results:
            print(Colors.success("\n✅ No authentication vulnerabilities found!"))
            return
            
        # Categorize findings by severity
        critical = [f for f in self.results if f["severity"] == "Critical"]
        high = [f for f in self.results if f["severity"] == "High"]
        medium = [f for f in self.results if f["severity"] == "Medium"]
        low = [f for f in self.results if f["severity"] == "Low"]

        # Print scan summary
        print(Colors.header("\nSCAN SUMMARY"))
        print(Colors.header("-" * 50))
        print(f" Target: {Colors.info(self.target)}")
        print(f" Total Findings: {Colors.info(len(self.results))}")
        print(f" - Critical: {Colors.error(len(critical))}")
        print(f" - High: {Colors.error(len(high))}")
        print(f" - Medium: {Colors.warning(len(medium))}")
        print(f" - Low: {Colors.success(len(low))}")
        print(Colors.header("-" * 50))

        # Print Critical Findings
        if critical:
            print(Colors.error("\nCRITICAL FINDINGS"))
            print(Colors.error("-" * 50))
            for finding in critical:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Details: {finding['details']}")
                print(f"   Recommendation: {finding['recommendation']}\n")

        # Print High-Risk Findings
        if high:
            print(Colors.error("\nHIGH-RISK FINDINGS"))
            print(Colors.error("-" * 50))
            for finding in high:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Details: {finding['details']}")
                print(f"   Recommendation: {finding['recommendation']}\n")

        # Print Medium Findings
        if medium:
            print(Colors.warning("\nMEDIUM-RISK FINDINGS"))
            print(Colors.warning("-" * 50))
            for finding in medium:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Details: {finding['details']}")
                print(f"   Recommendation: {finding['recommendation']}\n")

        # Print Low Findings
        if low:
            print(Colors.info("\nLOW-RISK FINDINGS"))
            print(Colors.info("-" * 50))
            for finding in low:
                print(f" [{finding['type']}] {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Details: {finding['details']}")
                print(f"   Recommendation: {finding['recommendation']}\n")

        # Print General Recommendations
        print(Colors.header("\nGENERAL RECOMMENDATIONS"))
        print(Colors.header("-" * 50))
        print(" - Implement multi-factor authentication for sensitive accounts")
        print(" - Enforce strong password policies (min length, complexity)")
        print(" - Set Secure and HttpOnly flags on session cookies")
        print(" - Implement account lockout after failed attempts")
        print(" - Regularly audit and rotate API keys and credentials")
        print(" - Ensure proper logout functionality invalidates sessions")
        print(Colors.header("-" * 50))

    def _update_progress(self, current, total, message=""):
        """Display enhanced progress bar with percentage"""
        progress = int((current / total) * 100)
        filled = int(progress/5)
        bar = f"[{'#' * filled}{'-' * (20 - filled)}]"
        color = Colors.success if progress == 100 else Colors.info
        print(f"\r{color(f'{message} {bar} {progress}%')}", end="")
        if current == total:
            print()

    def save_report_to_file(self):
        """Save the report to a JSON file"""
        if not self.results:
            print(Colors.error("No findings to save in report"))
            return
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"authentication_audit_{timestamp}.json"
        
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
            },
            "recommendations": [
                "Implement multi-factor authentication for sensitive accounts",
                "Enforce strong password policies (min length, complexity)",
                "Set Secure and HttpOnly flags on session cookies",
                "Implement account lockout after failed attempts",
                "Regularly audit and rotate API keys and credentials",
                "Ensure proper logout functionality invalidates sessions"
            ]
        }

        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            print(Colors.success(f"\nReport saved to: {filename}"))
        except Exception as e:
            print(Colors.error(f"\nFailed to save report: {e}"))

    def __del__(self):
        """Clean up resources"""
        self.session.close()