import re
import json
import base64
import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from colors import Colors
from .payloads import InsecureDesignPayloads

class InsecureDesignAssessment:
    """Dynamic scanner for OWASP A04:2021 - Insecure Design"""
    
    def __init__(self):
        self.techniques = {
            "1": {
                "id": "1",
                "name": "Session & Authentication Testing",
                "description": "Tests session management and authentication design flaws"
            },
            "2": {
                "id": "2",
                "name": "Business Logic Testing",
                "description": "Tests for workflow bypasses and logic flaws"
            }
        }
        self.payload_size = "medium"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ROGUE-A04-Scanner/3.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        self.verbose = False

    def set_payload_size(self, size: str):
        """Set the payload size (small, medium, large)"""
        self.payload_size = size

    def get_techniques(self) -> List[str]:
        """Return numbered list of available techniques"""
        return [f"{tech['id']}. {tech['name']}" for tech in self.techniques.values()]

    def run_assessment(self, technique_id: str, target: str, verbose: bool = False) -> Dict:
        """Execute the specified assessment technique"""
        self.verbose = verbose
        if technique_id == "1":
            return self.session_auth_testing(target)
        elif technique_id == "2":
            return self.business_logic_testing(target)
        else:
            raise ValueError("Invalid technique ID")

    def session_auth_testing(self, target: str) -> Dict:
        """Combined session and authentication testing"""
        results = {
            "session_fixation": False,
            "cookie_flaws": [],
            "auth_bypass_attempts": [],
            "jwt_issues": []
        }
        payloads = InsecureDesignPayloads.get_payloads(self.payload_size)
        
        if self.verbose:
            print(Colors.header("\n[+] Starting Session & Authentication Testing"))
        else:
            print(Colors.header("\n[+] Testing Session Management"))

        try:
            # Session Testing
            if self.verbose:
                print("\n[Phase 1] Session Testing")
            
            for test in payloads["session_tests"]:
                if test["action"] == "session_fixation":
                    if self.verbose:
                        print("- Testing session fixation with cookie:", test["test_cookie"])
                    else:
                        print("[20%] Testing session fixation")
                    results["session_fixation"] = self._test_session_fixation(target, test["test_cookie"])
                
                elif test["action"] == "cookie_analysis":
                    if self.verbose:
                        print("- Analyzing cookies:", test.get("cookies", "all"))
                    else:
                        print("[40%] Analyzing cookie security")
                    flaws = self._analyze_cookies(target, test.get("cookies", []))
                    results["cookie_flaws"].extend(flaws)

            # Authentication Testing
            if self.verbose:
                print("\n[Phase 2] Authentication Testing")
            elif not self.verbose:
                print(Colors.header("\n[+] Testing Authentication Flows"))
            
            for test in payloads["auth_tests"]:
                if test["action"] == "weak_password":
                    if self.verbose:
                        print("- Testing weak password:", test["password"])
                    else:
                        print("[60%] Testing weak password requirements")
                    if self._test_weak_password(target, test["password"]):
                        results["auth_bypass_attempts"].append(f"Weak password accepted: {test['password']}")
                
                elif test["action"] == "jwt_analysis":
                    if self.verbose:
                        print("- Analyzing JWT tokens")
                    else:
                        print("[80%] Analyzing JWT tokens")
                    issues = self._analyze_jwt_tokens(target)
                    results["jwt_issues"].extend(issues)

            if self.verbose:
                print("\n[+] Testing completed")
            else:
                print("[100%] Scan completed")
                
            self._print_results(results, "Session & Authentication")
            return results

        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            print(Colors.error(f"[100%] {error_msg}"))
            return {"error": error_msg}

    def business_logic_testing(self, target: str) -> Dict:
        """Test for business logic flaws with payloads"""
        results = {
            "workflow_bypass": [],
            "parameter_tampering": [],
            "quantity_manipulation": False
        }
        payloads = InsecureDesignPayloads.get_payloads(self.payload_size)
        
        if self.verbose:
            print(Colors.header("\n[+] Starting Business Logic Testing"))
        else:
            print(Colors.header("\n[+] Testing Business Logic Flows"))

        try:
            for i, test in enumerate(payloads["business_logic"], 1):
                progress = int((i/len(payloads["business_logic"]))*100)
                
                if test["action"] == "checkout_bypass":
                    if self.verbose:
                        print(f"\n[Test {i}] Testing checkout workflow bypass")
                        print("- Parameters:", test["params"])
                    else:
                        print(f"[{progress}%] Testing checkout workflow bypass")
                    if bypass_url := self._test_checkout_bypass(target, test["params"]):
                        results["workflow_bypass"].append(bypass_url)
                
                elif test["action"] == "price_tamper":
                    if self.verbose:
                        print(f"\n[Test {i}] Testing price manipulation")
                        print("- Parameters:", test["params"])
                    else:
                        print(f"[{progress}%] Testing price manipulation")
                    if self._test_price_tampering(target, test["params"]):
                        results["parameter_tampering"].append("Price tampering successful")
                
                elif test["action"] == "quantity_tamper":
                    if self.verbose:
                        print(f"\n[Test {i}] Testing quantity manipulation")
                        print("- Parameters:", test["params"])
                    else:
                        print(f"[{progress}%] Testing quantity manipulation")
                    if self._test_quantity_tampering(target, test["params"]):
                        results["quantity_manipulation"] = True

            if self.verbose:
                print("\n[+] Testing completed")
            else:
                print("[100%] Scan completed")
                
            self._print_results(results, "Business Logic")
            return results

        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            print(Colors.error(f"[100%] {error_msg}"))
            return {"error": error_msg}


    def _test_session_fixation(self, target: str, session_id: str) -> bool:
        """Test for session fixation vulnerability"""
        s = requests.Session()
        s.cookies.set("SESSIONID", session_id)
        login_url = self._detect_login(target)
        if login_url:
            s.post(login_url, data={"username": "test", "password": "test"})
            return s.cookies.get("SESSIONID") == session_id
        return False

    def _analyze_cookies(self, target: str, cookie_names: List[str]) -> List[Dict]:
        """Analyze cookies for security flaws"""
        flaws = []
        resp = self.session.get(target)
        
        cookies_to_check = cookie_names if cookie_names != "all" else list(self.session.cookies.keys())
        
        for name in cookies_to_check:
            if name in self.session.cookies:
                cookie = self.session.cookies.get(name)
                flaw = {
                    "name": name,
                    "issues": []
                }
                if not cookie.secure:
                    flaw["issues"].append("missing_secure")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    flaw["issues"].append("missing_httponly")
                if flaw["issues"]:
                    flaws.append(flaw)
        return flaws

    def _test_weak_password(self, target: str, password: str) -> bool:
        """Test if weak passwords are accepted"""
        signup_url = self._detect_signup(target)
        if signup_url:
            resp = self.session.post(signup_url, data={
                "username": "test",
                "password": password,
                "confirm_password": password
            })
            return resp.status_code == 200 and "success" in resp.text.lower()
        return False

    def _analyze_jwt_tokens(self, target: str) -> List[str]:
        """Analyze JWT tokens in requests"""
        issues = []
        resp = self.session.get(target)
        auth_header = resp.request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            issues.extend(self._check_jwt_security(token))
        
        return issues

    def _test_checkout_bypass(self, target: str, params: Dict) -> Optional[str]:
        """Test for checkout workflow bypass"""
        cart_urls = self._find_cart_urls(target)
        for url in cart_urls:
            resp = self.session.post(url, data=params)
            if resp.status_code == 200 and "complete" in resp.text.lower():
                return url
        return None

    def _test_price_tampering(self, target: str, params: Dict) -> bool:
        """Test for price manipulation vulnerability"""
        product_urls = self._find_product_urls(target)
        if product_urls:
            resp = self.session.post(product_urls[0], data=params)
            return resp.status_code == 200 and "total" in resp.text.lower()
        return False

    def _test_quantity_tampering(self, target: str, params: Dict) -> bool:
        """Test for quantity manipulation vulnerability"""
        cart_urls = self._find_cart_urls(target)
        if cart_urls:
            resp = self.session.post(cart_urls[0], data=params)
            return resp.status_code == 200 and "quantity" in resp.text.lower()
        return False

    def _print_results(self, results: Dict, title: str):
        """Print formatted results"""
        print(Colors.header(f"\n{title} Results:"))
        for key, value in results.items():
            if value:
                if isinstance(value, list):
                    print(Colors.error(f"[!] {key.replace('_', ' ').title()}:"))
                    for item in value:
                        print(f"  - {item}")
                elif isinstance(value, bool):
                    print(Colors.error(f"[!] {key.replace('_', ' ').title()} detected"))
            else:
                print(Colors.success(f"[✓] No {key.replace('_', ' ')} found"))

    # Helper methods remain unchanged from previous version
    def _detect_login(self, url: str) -> Optional[str]:
        """Detect login endpoint"""
        paths = ["/login", "/signin", "/auth"]
        for path in paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200 and any(x in resp.text.lower() for x in ["login", "username", "password"]):
                    return test_url
            except:
                continue
        return None

    def _detect_signup(self, url: str) -> Optional[str]:
        """Detect signup endpoint"""
        paths = ["/signup", "/register", "/create-account"]
        for path in paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200 and any(x in resp.text.lower() for x in ["signup", "register", "create account"]):
                    return test_url
            except:
                continue
        return None

    def _find_cart_urls(self, url: str) -> List[str]:
        """Find cart/checkout URLs"""
        paths = ["/cart", "/checkout", "/basket"]
        found = []
        for path in paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200 and any(x in resp.text.lower() for x in ["cart", "checkout"]):
                    found.append(test_url)
            except:
                continue
        return found

    def _find_product_urls(self, url: str) -> List[str]:
        """Find product URLs"""
        paths = ["/products", "/items", "/shop"]
        found = []
        for path in paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200 and any(x in resp.text.lower() for x in ["product", "item"]):
                    found.append(test_url)
            except:
                continue
        return found

    def _check_jwt_security(self, token: str) -> List[str]:
        """Check JWT for security issues"""
        issues = []
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return ["Invalid JWT format"]

            header = json.loads(self._base64_decode(parts[0]))
            payload = json.loads(self._base64_decode(parts[1]))

            if header.get("alg", "").lower() == "none":
                issues.append("'none' algorithm allowed")
            if "exp" not in payload:
                issues.append("Missing expiration claim")
            if header.get("alg") in ["HS256", "HS384"]:
                issues.append(f"Weak algorithm: {header['alg']}")

        except Exception as e:
            issues.append(f"JWT parsing error: {str(e)}")

        return issues

    def _base64_decode(self, data: str) -> str:
        """Base64 URL-safe decoding"""
        padding = len(data) % 4
        if padding > 0:
            data += "=" * (4 - padding)
        return base64.urlsafe_b64decode(data).decode('utf-8')