import json
import random
import string
from typing import Dict, List

class InsecureDesignPayloads:
    """Dynamic payloads for insecure design testing"""
    
    PAYLOADS = {
        "small": {
            "session_tests": [
                {"action": "session_fixation", "test_cookie": "TEST_SESSION"},
                {"action": "cookie_analysis", "cookies": ["sessionid", "token"]}
            ],
            "auth_tests": [
                {"action": "weak_password", "password": "1"},
                {"action": "jwt_analysis", "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."}
            ],
            "business_logic": [
                {"action": "checkout_bypass", "params": {"step": "complete"}},
                {"action": "price_tamper", "params": {"price": "0"}}
            ]
        },
        "medium": {
            "session_tests": [
                {"action": "session_fixation", "test_cookie": "FIXATED_SESSION_{rand}"},
                {"action": "cookie_analysis", "cookies": ["session", "auth", "identity"]},
                {"action": "entropy_check", "values": ["sessionid", "csrf_token"]}
            ],
            "auth_tests": [
                {"action": "weak_password", "password": "password123"},
                {"action": "jwt_analysis", "token": "auto_detect"},
                {"action": "credential_stuffing", "users": ["admin", "test"]}
            ],
            "business_logic": [
                {"action": "checkout_bypass", "params": {"step": "payment_skip"}},
                {"action": "price_tamper", "params": {"price": "-1"}},
                {"action": "quantity_tamper", "params": {"quantity": "9999"}}
            ]
        },
        "large": {
            "session_tests": [
                {"action": "session_fixation", "test_cookie": "SESSION_{rand32}"},
                {"action": "cookie_analysis", "cookies": "all"},
                {"action": "entropy_check", "values": "all_cookies"},
                {"action": "session_timeout", "delay": 300}
            ],
            "auth_tests": [
                {"action": "weak_password", "password": "{rand}"},
                {"action": "jwt_analysis", "token": "auto_detect"},
                {"action": "credential_stuffing", "users": "common"},
                {"action": "mfa_bypass", "methods": ["sms", "email"]}
            ],
            "business_logic": [
                {"action": "checkout_bypass", "params": {"skip_validation": "true"}},
                {"action": "price_tamper", "params": {"price": "0.01"}},
                {"action": "quantity_tamper", "params": {"quantity": "-1"}},
                {"action": "role_tamper", "params": {"role": "admin"}}
            ]
        }
    }

    @classmethod
    def get_payloads(cls, size: str = "medium") -> Dict[str, List[Dict]]:
        """Get payloads with dynamic value generation"""
        base_payloads = cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])
        return cls._generate_dynamic_values(base_payloads)

    @classmethod
    def _generate_dynamic_values(cls, payloads: Dict) -> Dict:
        """Replace dynamic placeholders with actual values"""
        dynamic_payloads = json.loads(json.dumps(payloads))  # Deep copy

        for category in dynamic_payloads.values():
            for test in category:
                if isinstance(test, dict):
                    for key, value in test.items():
                        if isinstance(value, str):
                            if "{rand}" in value:
                                test[key] = value.replace(
                                    "{rand}",
                                    ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                                )
                            elif "{rand32}" in value:
                                test[key] = value.replace(
                                    "{rand32}",
                                    ''.join(random.choices(string.ascii_letters + string.digits, k=32))
                                )
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if isinstance(sub_value, str):
                                    if "{rand}" in sub_value:
                                        value[sub_key] = sub_value.replace(
                                            "{rand}",
                                            ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                                        )
                                    elif "{rand32}" in sub_value:
                                        value[sub_key] = sub_value.replace(
                                            "{rand32}",
                                            ''.join(random.choices(string.ascii_letters + string.digits, k=32))
                                        )
        return dynamic_payloads
