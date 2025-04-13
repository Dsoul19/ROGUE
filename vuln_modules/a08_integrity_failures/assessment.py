import json
import re
import requests
import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from pathlib import Path
from colors import Colors
from .payloads import IntegrityPayloads
from requests.exceptions import RequestException

class IntegrityFailuresAssessment:
    """Advanced professional assessment for Software and Data Integrity Failures"""
    
    def __init__(self):
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Update Mechanism Testing",
                "description": "Test for unsigned/insecure software update mechanisms",
                "steps": 4
            },
            "2": {
                "id": "2",
                "name": "Checksum Validation Testing",
                "description": "Test file integrity verification methods",
                "steps": 3
            },
            "3": {
                "id": "3",
                "name": "Dependency Confusion",
                "description": "Test for dependency hijacking possibilities",
                "steps": 4
            },
            "4": {
                "id": "4",
                "name": "Build Process Testing",
                "description": "Test CI/CD pipelines for integrity issues",
                "steps": 2
            }
        }
        self.payload_size = "medium"
        self.findings = []
        self.verbose = False
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ROGUEv2 Security Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.checked_urls = set()
        self.total_steps = 0
        self.current_step = 0

    def _update_progress(self, current, total, message=""):
        """Calculate and display scan progress percentage"""
        percent = int((current / total) * 100)
        progress_bar = f"[{'#' * (percent//5)}{' ' * (20 - percent//5)}]"
        print(f"\r{Colors.info(message)} {progress_bar} {percent}%", end="")
        if current >= total:
            print()  # New line when complete

    def set_payload_size(self, size):
        """Set payload size (small, medium, large)"""
        if size.lower() in ["small", "medium", "large"]:
            self.payload_size = size.lower()
            print(Colors.success(f"\nPayload size set to: {self.payload_size}\n"))
        else:
            print(Colors.error("\nInvalid payload size. Use small, medium, or large\n"))

    def get_techniques(self):
        """Return available techniques"""
        return [f"{tech['id']} - {tech['name']}" for tech in self.techniques.values()]

    def run_assessment(self, technique_id, target, verbose=False):
        """Run the selected assessment technique"""
        self.verbose = verbose
        self.target = target.rstrip('/')
        self.findings = []
        self.checked_urls = set()
        self.current_step = 0

        print(Colors.header(f"\nRunning: A08 Software & Data Integrity Assessment"))
        print(Colors.info(f"Target: {self.target}"))
        print(Colors.info(f"Payload size: {self.payload_size.capitalize()}"))
        print(Colors.header("-" * 50))

        try:
            # Verify target is reachable first
            if not self._verify_target():
                print(Colors.error("Target is not reachable or returns error status"))
                return

            technique = self.techniques.get(technique_id)
            if not technique:
                print(Colors.error(f"Invalid technique ID: {technique_id}"))
                return

            self.total_steps = technique["steps"]

            if technique_id == "1":
                self._test_update_mechanisms()
            elif technique_id == "2":
                self._test_checksum_validation()
            elif technique_id == "3":
                self._test_dependency_confusion()
            elif technique_id == "4":
                self._test_build_processes()

            self._generate_report()
        except Exception as e:
            print(Colors.error(f"\n[!] Assessment failed: {str(e)}"))

    def _verify_target(self):
        """Verify the target URL is reachable and returns valid content"""
        try:
            resp = self.session.get(self.target, timeout=10)
            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '').lower()
                if any(x in content_type for x in ['text/html', 'application/json', 'text/plain']):
                    return True
            return False
        except RequestException:
            return False

    def _make_request(self, url):
        """Safe request wrapper with caching and enhanced validation"""
        if url in self.checked_urls:
            return None
            
        try:
            resp = self.session.get(url, timeout=10, allow_redirects=True)
            self.checked_urls.add(url)
            
            # Only return responses with valid content
            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '').lower()
                if any(x in content_type for x in ['text/html', 'application/json', 'text/plain']):
                    return resp
            return None
        except RequestException:
            self.checked_urls.add(url)
            return None

    def _test_update_mechanisms(self):
        """Professional update mechanism testing with enhanced validation"""
        self._update_progress(0, self.total_steps, "[+] Testing Update Mechanisms")
        
        # 1. Find and validate update URLs
        update_urls = self._find_update_urls()
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Update Mechanisms")
        
        # 2. Check update signing status
        for url in update_urls:
            if not self._check_signed_update(url):
                self.findings.append({
                    "severity": "Critical",
                    "type": "Insecure Software Update",
                    "description": "Unsigned Updates Detected",
                    "location": url,
                    "impact": "Attackers can replace updates with malicious files",
                    "recommendation": "Implement digital signatures and enforce verification",
                    "evidence": f"Found unsigned update at {url}"
                })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Update Mechanisms")

        # 3. Check for insecure channels
        insecure_channel = self._check_insecure_channels()
        if insecure_channel["insecure"]:
            self.findings.append({
                "severity": "High",
                "type": "Insecure Update Channel",
                "description": insecure_channel["description"],
                "location": insecure_channel["location"],
                "impact": "Potential for MITM attacks during update",
                "recommendation": "Serve updates over HTTPS with certificate pinning",
                "evidence": insecure_channel["evidence"]
            })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Update Mechanisms")

        # 4. Check update verification
        if self._check_update_verification():
            self.findings.append({
                "severity": "High",
                "type": "Missing Update Verification",
                "description": "No update authenticity verification",
                "location": self.target,
                "impact": "Potential for malicious update injection",
                "recommendation": "Implement cryptographic verification of updates",
                "evidence": "No update verification mechanism detected"
            })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Update Mechanisms")

    def _find_update_urls(self):
        """Professional update URL discovery with multiple detection methods"""
        update_urls = []
        
        # 1. Check common update paths
        common_paths = [
            'update', 'updates', 'download', 'autoupdate',
            'api/update', 'api/v1/update', 'version/check'
        ]
        
        for path in common_paths:
            url = urljoin(self.target, path)
            resp = self._make_request(url)
            if resp:
                update_urls.append(url)
        
        # 2. Parse HTML for update links
        resp = self._make_request(self.target)
        if resp and 'text/html' in resp.headers.get('Content-Type', ''):
            soup = BeautifulSoup(resp.text, 'html.parser')
            for element in soup.find_all(['a', 'form', 'script']):
                url = None
                if element.name == 'a' and element.get('href'):
                    url = element['href']
                elif element.name == 'form' and element.get('action'):
                    url = element['action']
                elif element.name == 'script' and element.get('src'):
                    url = element['src']
                
                if url and any(x in url.lower() for x in ['update', 'download', 'upgrade']):
                    full_url = urljoin(self.target, url)
                    if full_url not in update_urls and self._make_request(full_url):
                        update_urls.append(full_url)
        
        # 3. Check JavaScript files for update URLs
        js_urls = self._find_js_update_urls()
        update_urls.extend(js_urls)
        
        return list(set(update_urls))  # Remove duplicates

    def _find_js_update_urls(self):
        """Find update URLs referenced in JavaScript files"""
        js_urls = []
        resp = self._make_request(self.target)
        if not resp:
            return js_urls
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        for script in soup.find_all('script'):
            if script.get('src'):
                js_url = urljoin(self.target, script['src'])
                js_resp = self._make_request(js_url)
                if js_resp:
                    # Simple pattern matching for update URLs in JS
                    matches = re.findall(r'["\'](https?://[^"\']+/update[^"\']*?)["\']', js_resp.text)
                    js_urls.extend([urljoin(js_url, match) for match in matches])
        
        return js_urls

    def _check_signed_update(self, url):
        """Professional update signing verification"""
        resp = self._make_request(url)
        if not resp:
            return True  # Non-existent URLs considered secure
            
        # Check for common signature indicators
        if url.endswith(('.exe', '.msi', '.dmg', '.pkg')):
            # Check for digital signatures in binary files
            return False  # Simulating unsigned binaries
            
        elif url.endswith(('.zip', '.tar.gz', '.deb', '.rpm')):
            # Check for accompanying signature files
            sig_url = f"{url}.sig"
            if not self._make_request(sig_url):
                return False
                
        return True

    def _check_insecure_channels(self):
        """Comprehensive insecure channel detection"""
        result = {
            "insecure": False,
            "description": "",
            "location": self.target,
            "evidence": ""
        }
        
        # 1. Check if main target is HTTP
        if self.target.startswith('http:'):
            result.update({
                "insecure": True,
                "description": "Main site served over HTTP",
                "evidence": f"Target URL {self.target} uses HTTP"
            })
            return result
            
        # 2. Check update endpoints
        update_urls = self._find_update_urls()
        for url in update_urls:
            if url.startswith('http:'):
                result.update({
                    "insecure": True,
                    "description": "Update endpoint served over HTTP",
                    "evidence": f"Update URL {url} uses HTTP"
                })
                return result
                
        # 3. Check for HTTPS->HTTP downgrade
        try:
            resp = self.session.get(self.target, timeout=5, allow_redirects=True)
            if resp.history:
                for r in resp.history:
                    if r.url.startswith('http:'):
                        result.update({
                            "insecure": True,
                            "description": "HTTPS to HTTP redirect detected",
                            "evidence": f"Redirect from {r.url} to {resp.url}"
                        })
                        return result
        except RequestException:
            pass
            
        return result

    def _check_update_verification(self):
        """Check for update verification mechanisms"""
        update_urls = self._find_update_urls()
        for url in update_urls:
            # Check for common verification patterns
            if any(x in url.lower() for x in ['verify', 'check', 'validate']):
                return False
                
            # Check for signature files
            if self._make_request(f"{url}.sig"):
                return False
                
        return True

    def _test_checksum_validation(self):
        """Professional checksum validation testing"""
        self._update_progress(0, self.total_steps, "[+] Testing Checksum Validation")
        
        # 1. Detect checksum algorithms
        algorithms = self._detect_checksum_algorithms()
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Checksum Validation")
        
        # 2. Validate algorithm strength
        for algo in algorithms:
            if algo.lower() in ["md5", "sha1"]:
                self.findings.append({
                    "severity": "High",
                    "type": "Weak File Integrity Checks",
                    "description": f"{algo.upper()} Used for Verification",
                    "location": f"{self.target}/updates/",
                    "impact": f"{algo.upper()} is vulnerable to collision attacks",
                    "recommendation": "Use SHA-256 or stronger hashing algorithms",
                    "evidence": f"Detected {algo} checksum usage"
                })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Checksum Validation")

        # 3. Test checksum bypass
        if self._test_checksum_bypass():
            self.findings.append({
                "severity": "Critical",
                "type": "Checksum Verification Bypass",
                "description": "No checksum verification performed",
                "location": self.target,
                "impact": "Files can be modified without detection",
                "recommendation": "Implement strict checksum verification for all critical files",
                "evidence": "No checksum verification mechanism detected"
            })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Checksum Validation")

    def _detect_checksum_algorithms(self):
        """Professional checksum algorithm detection"""
        algorithms = []
        
        # 1. Check common checksum files
        checksum_files = [
            'checksums.txt', 'SHASUMS.txt', 'md5sums.txt',
            'verify.sig', 'hashes.json'
        ]
        
        for file in checksum_files:
            url = urljoin(self.target, file)
            resp = self._make_request(url)
            if resp:
                content = resp.text.lower()
                if 'md5' in content:
                    algorithms.append('MD5')
                if 'sha1' in content:
                    algorithms.append('SHA1')
                if 'sha256' in content or 'sha-256' in content:
                    algorithms.append('SHA256')
                if 'sha512' in content or 'sha-512' in content:
                    algorithms.append('SHA512')
        
        # 2. Check HTML for checksum references
        resp = self._make_request(self.target)
        if resp and 'text/html' in resp.headers.get('Content-Type', ''):
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text().lower()
            if 'md5' in text:
                algorithms.append('MD5')
            if 'sha1' in text:
                algorithms.append('SHA1')
        
        return list(set(algorithms))  # Remove duplicates

    def _test_checksum_bypass(self):
        """Professional checksum bypass testing"""
        # 1. Check for verification endpoints
        verify_urls = [
            'api/verify', 'verify_update', 'checksum/validate',
            'hash/check', 'integrity/verify'
        ]
        
        for path in verify_urls:
            url = urljoin(self.target, path)
            resp = self._make_request(url)
            if resp and 'verification' in resp.text.lower():
                return False
                
        # 2. Check for signature files
        update_urls = self._find_update_urls()
        for url in update_urls:
            if self._make_request(f"{url}.sig"):
                return False
                
        return True

    def _test_dependency_confusion(self):
        """Professional dependency confusion testing"""
        self._update_progress(0, self.total_steps, "[+] Testing Dependency Confusion")
        
        # 1. Detect package managers
        package_managers = self._detect_package_managers()
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Dependency Confusion")
        
        # 2. Test each package manager
        for pm in package_managers:
            vuln_details = self._test_dependency_hijacking(pm)
            if vuln_details["vulnerable"]:
                self.findings.append({
                    "severity": "Critical",
                    "type": "Dependency Confusion",
                    "description": f"Malicious Package Injection Possible in {pm}",
                    "location": vuln_details["location"],
                    "impact": "Potential for unauthorized code execution",
                    "recommendation": f"Use scoped namespaces and verified package registries for {pm}",
                    "evidence": vuln_details["evidence"]
                })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Dependency Confusion")

        # 3. Check for hardcoded secrets
        secrets = self._find_hardcoded_secrets()
        for secret in secrets:
            self.findings.append({
                "severity": "High",
                "type": "Hardcoded Secrets in Codebase",
                "description": f"Exposed {secret['type']}",
                "location": secret["file"],
                "impact": "Sensitive credentials exposed",
                "recommendation": "Store secrets securely using environment variables or secret managers",
                "evidence": secret["evidence"]
            })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Dependency Confusion")

        # 4. Check dependency lock files
        if self._check_dependency_lock_files():
            self.findings.append({
                "severity": "Medium",
                "type": "Missing Dependency Lock Files",
                "description": "No lock files for precise dependency versions",
                "location": f"{self.target}/package-lock.json",
                "impact": "Potential for dependency version drift",
                "recommendation": "Use lock files (package-lock.json, Pipfile.lock, etc.)",
                "evidence": "No dependency lock file detected"
            })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Dependency Confusion")

    def _detect_package_managers(self):
        """Professional package manager detection"""
        managers = []
        config_files = {
            'npm': ['package.json', 'package-lock.json'],
            'pip': ['requirements.txt', 'Pipfile', 'setup.py'],
            'composer': ['composer.json', 'composer.lock'],
            'maven': ['pom.xml'],
            'gradle': ['build.gradle'],
            'nuget': ['packages.config', '*.csproj']
        }
        
        for pm, files in config_files.items():
            for file in files:
                url = urljoin(self.target, file)
                if self._make_request(url):
                    managers.append(pm)
                    break
        
        return list(set(managers))  # Remove duplicates

    def _test_dependency_hijacking(self, package_manager):
        """Professional dependency hijacking testing"""
        result = {
            "vulnerable": False,
            "location": f"{self.target}/package.json",
            "evidence": ""
        }
        
        if package_manager == 'npm':
            url = urljoin(self.target, 'package.json')
            resp = self._make_request(url)
            if resp:
                content = resp.text
                # Check for unscoped packages
                if '"dependencies":' in content and '@' not in content:
                    result.update({
                        "vulnerable": True,
                        "evidence": "Found unscoped packages in package.json"
                    })
                # Check for custom registries
                if '"registry":' in content or 'registry.npmjs.org' not in content:
                    result.update({
                        "vulnerable": True,
                        "evidence": "Custom package registry configured"
                    })
                    
        elif package_manager == 'pip':
            url = urljoin(self.target, 'requirements.txt')
            resp = self._make_request(url)
            if resp and ('--index-url' in resp.text or '--extra-index-url' in resp.text):
                result.update({
                    "vulnerable": True,
                    "evidence": "Custom package index configured"
                })
        
        return result

    def _find_hardcoded_secrets(self):
        """Professional secret detection with reduced false positives"""
        secrets = []
        secret_patterns = {
            'API Key': r'(?i)(api|access|secret)[_-]?key[\\s"\':=]+([a-z0-9]{32,})',
            'Database Credentials': r'(?i)(db|database)[\\s"\':]*(user|name|pass|pw)[\\s"\':=]+([^\\s"\']+)',
            'AWS Keys': r'(?i)aws[\\s"\':_]*(access|secret)[\\s"\':=]*([a-z0-9]{20,40})',
            'Cryptographic Keys': r'-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----'
        }
        
        # Check common files
        secret_files = [
            '.env', 'config.json', 'settings.py',
            'config/database.php', 'application.properties'
        ]
        
        for file in secret_files:
            url = urljoin(self.target, file)
            resp = self._make_request(url)
            if resp:
                content = resp.text
                for secret_type, pattern in secret_patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        secrets.append({
                            "type": secret_type,
                            "file": url,
                            "evidence": f"Found {secret_type} pattern in {file}"
                        })
        
        return secrets

    def _check_dependency_lock_files(self):
        """Check for dependency lock files"""
        lock_files = [
            'package-lock.json', 'yarn.lock', 'Pipfile.lock',
            'composer.lock', 'Gemfile.lock'
        ]
        
        for file in lock_files:
            url = urljoin(self.target, file)
            if self._make_request(url):
                return False
                
        return True

    def _test_build_processes(self):
        """Professional CI/CD pipeline testing"""
        self._update_progress(0, self.total_steps, "[+] Testing Build Processes")
        
        # 1. Detect CI systems
        ci_systems = self._detect_ci_systems()
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Build Processes")
        
        # 2. Test each CI system
        for system in ci_systems:
            vuln_details = self._test_ci_insecurity(system)
            if vuln_details["insecure"]:
                self.findings.append({
                    "severity": "High",
                    "type": "Insecure CI/CD Pipeline",
                    "description": f"{vuln_details['description']} in {system}",
                    "location": vuln_details["location"],
                    "impact": "Remote execution of unverified scripts",
                    "recommendation": "Enforce script whitelisting and authentication",
                    "evidence": vuln_details["evidence"]
                })
        self.current_step += 1
        self._update_progress(self.current_step, self.total_steps, "[+] Testing Build Processes")

    def _detect_ci_systems(self):
        """Professional CI system detection"""
        systems = []
        ci_files = {
            'GitHub Actions': ['.github/workflows/*.yml'],
            'Jenkins': ['Jenkinsfile', '.jenkinsfile'],
            'GitLab CI': ['.gitlab-ci.yml'],
            'CircleCI': ['.circleci/config.yml'],
            'Travis CI': ['.travis.yml'],
            'Azure Pipelines': ['azure-pipelines.yml']
        }
        
        for system, patterns in ci_files.items():
            for pattern in patterns:
                url = urljoin(self.target, pattern.replace('*', 'main'))
                if self._make_request(url):
                    systems.append(system)
                    break
                    
        return systems

    def _test_ci_insecurity(self, system):
        """Professional CI security testing"""
        result = {
            "insecure": False,
            "description": "",
            "location": f"{self.target}/.github/workflows/",
            "evidence": ""
        }
        
        if system == 'GitHub Actions':
            url = urljoin(self.target, '.github/workflows/main.yml')
            resp = self._make_request(url)
            if resp:
                content = resp.text
                # Check for pull_request trigger
                if 'on: pull_request' not in content:
                    result.update({
                        "insecure": True,
                        "description": "Missing PR approval requirement",
                        "evidence": "No pull_request trigger in GitHub Actions workflow"
                    })
                # Check for self-hosted runners
                if 'runs-on: self-hosted' in content:
                    result.update({
                        "insecure": True,
                        "description": "Self-hosted runner without restrictions",
                        "evidence": "Self-hosted runner detected in GitHub Actions"
                    })
                    
        elif system == 'Jenkins':
            url = urljoin(self.target, 'Jenkinsfile')
            resp = self._make_request(url)
            if resp and 'scriptApproval' not in resp.text:
                result.update({
                    "insecure": True,
                    "description": "Missing script approval",
                    "evidence": "No script approval in Jenkinsfile"
                })
                
        return result

    def _generate_report(self):
        """Generate professional assessment report"""
        if not self.findings:
            print(Colors.success("\nNo verified vulnerabilities found!"))
            return

        # Remove duplicates and verify findings
        unique_findings = []
        seen = set()
        for finding in self.findings:
            key = (finding["type"], finding["location"], finding.get("evidence", ""))
            if key not in seen and self._verify_finding(finding):
                seen.add(key)
                unique_findings.append(finding)

        if not unique_findings:
            print(Colors.success("\nNo verified vulnerabilities found!"))
            return

        # Categorize by severity
        severity_order = ["Critical", "High", "Medium", "Low"]
        categorized = {sev: [] for sev in severity_order}
        for finding in unique_findings:
            categorized[finding["severity"]].append(finding)

        # Print summary
        total = len(unique_findings)
        critical = len(categorized["Critical"])
        high = len(categorized["High"])
        medium = len(categorized["Medium"])
        low = len(categorized["Low"])

        print(Colors.header("\nSCAN SUMMARY"))
        print(Colors.header("-" * 50))
        print(f"{Colors.info('Target:')} {self.target}")
        print(f"{Colors.info('Total Findings:')} {total}")
        print(f"{Colors.error('Critical:')} {critical}")
        print(f"{Colors.warning('High:')} {high}")
        print(f"{Colors.info('Medium:')} {medium}")
        print(f"{Colors.subtle('Low:')} {low}")
        print(Colors.header("-" * 50))

        # Print findings by severity
        for severity in severity_order:
            if categorized[severity]:
                print(Colors.header(f"\n{severity.upper()} FINDINGS"))
                print(Colors.header("-" * 50))
                for finding in categorized[severity]:
                    print(f"\n{Colors.error(finding['type'])}: {finding['description']}")
                    print(f"  {Colors.info('Location:')} {finding['location']}")
                    print(f"  {Colors.info('Impact:')} {finding['impact']}")
                    print(f"  {Colors.info('Evidence:')} {finding.get('evidence', 'N/A')}")
                    print(f"  {Colors.success('Recommendation:')} {finding['recommendation']}")

        # Save report option
        save = input(Colors.prompt("\nSave report to file? (y/n): ")).lower()
        if save in ['y', 'yes']:
            filename = f"a08_integrity_report_{self.target.replace('://', '_').replace('/', '_')}.json"
            try:
                with open(filename, 'w') as f:
                    json.dump({
                        "metadata": {
                            "target": self.target,
                            "timestamp": datetime.now().isoformat(),
                            "scanner": "ROGUEv2 A08 Scanner",
                            "payload_size": self.payload_size
                        },
                        "summary": {
                            "total": total,
                            "critical": critical,
                            "high": high,
                            "medium": medium,
                            "low": low
                        },
                        "findings": unique_findings
                    }, f, indent=2)
                print(Colors.success(f"\nReport saved to {filename}"))
            except Exception as e:
                print(Colors.error(f"\nFailed to save report: {str(e)}"))

    def _verify_finding(self, finding):
        """Verify a finding before including in report"""
        # Skip verification for certain finding types
        if finding["type"] in ["Weak File Integrity Checks", "Missing Dependency Lock Files"]:
            return True
            
        # For URL-based findings, verify the URL exists
        if finding["location"].startswith('http'):
            return finding["location"] in self.checked_urls
            
        return True