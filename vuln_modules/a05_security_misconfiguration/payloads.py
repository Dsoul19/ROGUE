class SecurityMisconfigPayloads:
    """Payloads for OWASP A05:2021 - Security Misconfiguration"""
    
    PAYLOADS = {
        "small": {
            "auth_issues": [
                {"type": "default_creds", "payload": ["admin:admin", "guest:guest"]},
                {"type": "bruteforce", "payload": "top10_passwords.txt"}
            ],
            "header_checks": [
                {"type": "security_headers", "headers": ["CSP", "HSTS"]},
                {"type": "debug_mode", "indicators": ["DEBUG = True"]}
            ],
            "sensitive_paths": [
                {"type": "admin_panels", "paths": ["/admin", "/wp-admin"]},
                {"type": "config_files", "paths": ["/.env", "/config.json"]}
            ]
        },
        "medium": {
            "auth_issues": [
                {"type": "default_creds", "payload": ["admin:admin123", "root:toor"]},
                {"type": "bruteforce", "payload": "top100_passwords.txt"},
                {"type": "login_bypass", "payload": ["' OR '1'='1", "admin'--"]}
            ],
            "header_checks": [
                {"type": "security_headers", "headers": ["CSP", "HSTS", "X-Frame-Options"]},
                {"type": "debug_mode", "indicators": ["DEBUG = True", "stacktrace"]},
                {"type": "cors", "payload": ["*", "null"]}
            ],
            "sensitive_paths": [
                {"type": "admin_panels", "paths": ["/admin/", "/wp-admin", "/phpmyadmin"]},
                {"type": "config_files", "paths": ["/.env", "/config.json", "/.git/config"]},
                {"type": "directory_listing", "paths": ["/backups", "/logs"]}
            ]
        },
        "large": {
            "auth_issues": [
                {"type": "default_creds", "payload": ["administrator:password", "sysadmin:changeme"]},
                {"type": "bruteforce", "payload": "top1000_passwords.txt"},
                {"type": "login_bypass", "payload": ["' OR 1=1--", "admin'#"]},
                {"type": "rate_limit", "payload": "100_requests_per_second"}
            ],
            "header_checks": [
                {"type": "security_headers", "headers": ["CSP", "HSTS", "X-Frame-Options", "X-XSS-Protection"]},
                {"type": "debug_mode", "indicators": ["DEBUG = True", "stacktrace", "traceback"]},
                {"type": "cors", "payload": ["*.example.com", "https://*"]},
                {"type": "server_info", "indicators": ["Server: ", "X-Powered-By: "]}
            ],
            "sensitive_paths": [
                {"type": "admin_panels", "paths": ["/admin", "/administrator", "/wp-admin"]},
                {"type": "config_files", "paths": ["/.env", "/.htaccess", "/web.config"]},
                {"type": "directory_listing", "paths": ["/backup", "/temp", "/uploads"]},
                {"type": "version_control", "paths": ["/.git", "/.svn", "/.hg"]}
            ]
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        """Get payloads with dynamic value generation"""
        return cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])