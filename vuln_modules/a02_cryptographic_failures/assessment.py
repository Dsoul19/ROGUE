# vuln_modules/a02_cryptographic_failures/assessment.py
import requests
import re
import ssl
import socket
import logging
import os
from urllib.parse import urljoin
from datetime import datetime
import json
from typing import List, Dict
from colors import Colors
from .payloads import CryptographicFailuresPayloads

# Configure logging
# LOG_FILE = 'cryptographic_failures.log'
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

class CryptographicFailuresAssessment:
    def __init__(self):
        self.name = "Cryptographic Failures Assessment"
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Weak Cryptographic Algorithms",
                "function": self.assess_weak_algorithms,
                "description": "Detects outdated algorithms like MD5, SHA1, RC4, DES, and weak TLS configurations"
            },
            "2": {
                "id": "2",
                "name": "Hardcoded Secrets & Weak Credentials",
                "function": self.assess_hardcoded_secrets,
                "description": "Finds exposed API keys, passwords, tokens, and sensitive secrets in source code"
            },
            "3": {
                "id": "3",
                "name": "Improper Encryption Practices",
                "function": self.assess_encryption_practices,
                "description": "Checks for insecure encryption modes like AES-ECB, static IVs, and weak key storage"
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
        self.payloads = CryptographicFailuresPayloads()
        self.current_payloads = self.payloads.get_payloads(self.payload_size)

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

        technique = next(tech for tech in self.techniques.values() if tech['id'] == technique_id)
        self.start_time = datetime.now()
        self.findings = []
        
        print(Colors.header(f"\n[+] Starting {technique['name']} assessment"))
        print(Colors.info(f"[~] Target: {target}"))
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

    def assess_weak_algorithms(self, target: str, verbose: bool) -> None:
        """Check for weak cryptographic algorithms and TLS configurations"""
        print(Colors.info("\n[~] Checking for Weak Cryptographic Algorithms..."))
        
        # Parse target URL to get hostname and port
        hostname, port = self._parse_target(target)
        
        # Check TLS/SSL configurations
        print(Colors.subtle("\n  [~] Analyzing TLS/SSL configurations..."))
        self._check_tls_config(hostname, port, verbose)
        
        # Check for weak hash algorithms in content
        print(Colors.subtle("\n  [~] Searching for weak hash algorithms..."))
        self._check_weak_hashes(target, verbose)
        
        print(Colors.success("\n[√] Weak algorithms check completed"))

    def assess_hardcoded_secrets(self, target: str, verbose: bool) -> None:
        """Check for hardcoded secrets and weak credentials"""
        print(Colors.info("\n[~] Checking for Hardcoded Secrets..."))
        
        # Check in response content
        print(Colors.subtle("\n  [~] Scanning response for secrets..."))
        self._scan_for_secrets(target, verbose)
        
        # Check in common files
        print(Colors.subtle("\n  [~] Checking common files for secrets..."))
        self._check_common_files(target, verbose)
        
        print(Colors.success("\n[√] Hardcoded secrets check completed"))

    def assess_encryption_practices(self, target: str, verbose: bool) -> None:
        """Check for improper encryption practices"""
        if self.payload_size == "small":
            print(Colors.error("\n  [!] This technique requires at least medium payload size"))
            return
            
        print(Colors.info("\n[~] Checking for Improper Encryption Practices..."))
        
        # Check for ECB mode usage
        print(Colors.subtle("\n  [~] Checking for ECB mode usage..."))
        self._check_ecb_mode(target, verbose)
        
        # Check for static IVs
        print(Colors.subtle("\n  [~] Checking for static IVs..."))
        self._check_static_ivs(target, verbose)
        
        print(Colors.success("\n[√] Encryption practices check completed"))

    # Helper methods for weak algorithms assessment
    def _check_tls_config(self, hostname: str, port: int, verbose: bool) -> None:
        """Check for weak TLS configurations"""
        try:
            context = ssl.create_default_context()
            context.set_ciphers('ALL:@SECLEVEL=0')
            
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    if verbose:
                        print(Colors.subtle(f"    Current cipher: {cipher[0]}"))
                        print(Colors.subtle(f"    Protocol version: {protocol}"))
                    
                    if protocol in self.current_payloads["tls_checks"]:
                        self._add_finding(
                            "Weak TLS Protocol",
                            f"{hostname}:{port}",
                            f"Using insecure protocol: {protocol}",
                            "High"
                        )
                        print(Colors.error(f"    [!] Insecure protocol detected: {protocol}"))
                    
                    if "RC4" in cipher[0] or "DES" in cipher[0] or "3DES" in cipher[0]:
                        self._add_finding(
                            "Weak Cipher Suite",
                            f"{hostname}:{port}",
                            f"Using insecure cipher: {cipher[0]}",
                            "High"
                        )
                        print(Colors.error(f"    [!] Weak cipher detected: {cipher[0]}"))
        except Exception as e:
            # logger.error(f"TLS check failed: {str(e)}")
            if verbose:
                print(Colors.error(f"    [!] TLS check failed: {str(e)}"))

    def _check_weak_hashes(self, target: str, verbose: bool) -> None:
        """Check for weak hash algorithms in content"""
        try:
            response = self.session.get(target, timeout=10)
            content = response.text
            
            for algo in self.current_payloads["weak_algorithms"]:
                pattern = re.compile(rf'{algo}\b', re.IGNORECASE)
                if pattern.search(content):
                    self._add_finding(
                        "Weak Hash Algorithm",
                        target,
                        f"Reference to weak algorithm: {algo}",
                        "Medium"
                    )
                    if verbose:
                        print(Colors.error(f"    [!] Found reference to weak algorithm: {algo}"))
        except Exception as e:
            # logger.error(f"Hash check failed: {str(e)}")
            if verbose:
                print(Colors.error(f"    [!] Hash check failed: {str(e)}"))

    # Helper methods for hardcoded secrets assessment
    def _scan_for_secrets(self, target: str, verbose: bool) -> None:
        """Scan response content for potential secrets"""
        try:
            response = self.session.get(target, timeout=10)
            content = response.text
            
            for pattern in self.current_payloads["secret_patterns"]:
                if pattern in content:
                    self._add_finding(
                        "Potential Hardcoded Secret",
                        target,
                        f"Found pattern indicating secret: {pattern}",
                        "High"
                    )
                    if verbose:
                        print(Colors.error(f"    [!] Found potential secret pattern: {pattern}"))
        except Exception as e:
            # logger.error(f"Secret scan failed: {str(e)}")
            if verbose:
                print(Colors.error(f"    [!] Secret scan failed: {str(e)}"))

    def _check_common_files(self, target: str, verbose: bool) -> None:
        """Check common configuration files for secrets"""
        common_files = [
            "/.env", "/config.json", "/configuration.json",
            "/secrets.json", "/.git/config", "/.aws/credentials"
        ]
        
        for file in common_files:
            url = urljoin(target, file)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text
                    for pattern in self.current_payloads["secret_patterns"]:
                        if pattern in content:
                            self._add_finding(
                                "Exposed Configuration File",
                                url,
                                f"Found secret pattern in {file}: {pattern}",
                                "Critical"
                            )
                            if verbose:
                                print(Colors.error(f"    [!] Found secret in {file}: {pattern}"))
            except Exception as e:
                if verbose:
                    print(Colors.subtle(f"    [~] Checking {url}..."))

    # Helper methods for encryption practices assessment
    def _check_ecb_mode(self, target: str, verbose: bool) -> None:
        """Check for ECB mode usage patterns"""
        try:
            response = self.session.get(target, timeout=10)
            content = response.text
            
            for pattern in self.current_payloads["encryption_anti_patterns"]:
                if pattern in content:
                    self._add_finding(
                        "Insecure Encryption Mode",
                        target,
                        f"Reference to insecure mode: {pattern}",
                        "High"
                    )
                    if verbose:
                        print(Colors.error(f"    [!] Found reference to insecure mode: {pattern}"))
        except Exception as e:
            # logger.error(f"ECB mode check failed: {str(e)}")
            if verbose:
                print(Colors.error(f"    [!] ECB mode check failed: {str(e)}"))

    def _check_static_ivs(self, target: str, verbose: bool) -> None:
        """Check for static IV patterns"""
        static_iv_patterns = [
            "iv=static_value", "initialization_vector=fixed",
            "iv=00000000", "iv=12345678"
        ]
        
        try:
            response = self.session.get(target, timeout=10)
            content = response.text
            
            for pattern in static_iv_patterns:
                if pattern in content:
                    self._add_finding(
                        "Static IV Detected",
                        target,
                        f"Found pattern indicating static IV: {pattern}",
                        "High"
                    )
                    if verbose:
                        print(Colors.error(f"    [!] Found static IV pattern: {pattern}"))
        except Exception as e:
            # logger.error(f"Static IV check failed: {str(e)}")
            if verbose:
                print(Colors.error(f"    [!] Static IV check failed: {str(e)}"))

    # Common helper methods
    def _parse_target(self, target: str) -> tuple:
        """Parse target URL into hostname and port"""
        if target.startswith("http://"):
            hostname = target[7:].split('/')[0]
            port = 80
        elif target.startswith("https://"):
            hostname = target[8:].split('/')[0]
            port = 443
        else:
            hostname = target.split('/')[0]
            port = 80
        
        if ':' in hostname:
            hostname, port = hostname.split(':')
            port = int(port)
        
        return hostname, port

    def _add_finding(self, vuln_type: str, location: str, description: str, severity: str) -> None:
        """Add a vulnerability finding to the results"""
        self.findings.append({
            "type": vuln_type,
            "location": location,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })

    def _prompt_for_report(self) -> bool:
        """Ask user if they want to generate a report"""
        print("\n")
        response = input(Colors.prompt("[?] Generate report? (y/n): ")).strip().lower()
        return response in ['y', 'yes']

    def _generate_report(self, target: str, technique: str) -> None:
        """Generate assessment report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"a02_crypto_failures_{technique.lower().replace(' ', '_')}_{timestamp}.json"
        
        report = {
            "metadata": {
                "assessment": "Cryptographic Failures",
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
        
        print(Colors.header("\n[+] Assessment Summary:"))
        print(f"  Target: {target}")
        print(f"  Technique: {technique}")
        print(f"  Payload size: {self.payload_size}")
        print(f"  Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds")
        print(f"  Findings: {Colors.error(str(len(self.findings)))} total")
        print(f"    Critical severity: {Colors.error(str(report['summary']['critical_severity']))}")
        print(f"    High severity: {Colors.error(str(report['summary']['high_severity']))}")
        
        if self.findings:
            print(Colors.header("\n[+] Critical Findings:"))
            for finding in self.findings:
                if finding['severity'] in ["Critical", "High"]:
                    print(f"  {Colors.error('➜')} {finding['type']}")
                    print(f"    Location: {finding['location']}")
                    print(f"    Severity: {finding['severity']}")
                    print(f"    Description: {finding['description']}\n")