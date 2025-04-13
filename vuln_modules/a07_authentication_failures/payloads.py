from colors import Colors

class AuthenticationPayloads:
    PAYLOADS = {
        "small": {
            "login_endpoints": ["/login", "/admin", "/auth"],
            "common_credentials": [
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "toor")
            ],
            "session_cookies": ["sessionid", "PHPSESSID", "JSESSIONID"],
            "auth_headers": ["Authorization", "X-API-Key"],
            "password_policy_checks": ["123456", "password"],
            "sensitive_keywords": ["password", "secret", "key", "token"],
            "config_files": ["/robots.txt", "/.env"]
        },
        "medium": {
            "login_endpoints": [
                "/login", "/admin", "/auth", 
                "/signin", "/wp-login.php",
                "/administrator", "/api/auth"
            ],
            "common_credentials": [
                ("admin", "admin"), ("admin", "password"), ("root", "toor"),
                ("user", "user"), ("test", "test"), ("guest", "guest"),
                ("administrator", "password"), ("admin", "123456")
            ],
            "session_cookies": [
                "sessionid", "PHPSESSID", "JSESSIONID",
                "auth_token", "access_token", "id_token"
            ],
            "auth_headers": [
                "Authorization", "X-API-Key",
                "X-Auth-Token", "X-CSRF-Token"
            ],
            "password_policy_checks": [
                "123456", "password", "123456789",
                "12345678", "12345", "qwerty"
            ],
            "sensitive_keywords": [
                "password", "secret", "key", "token",
                "credential", "access", "private"
            ],
            "config_files": [
                "/robots.txt", "/.env", "/config.json",
                "/web.config", "/.git/config"
            ],
            "auth_methods": ["Basic", "Bearer", "Digest"]
        },
        "large": {
            "login_endpoints": [
                "/login", "/admin", "/auth", "/signin", 
                "/wp-login.php", "/administrator", "/api/auth",
                "/oauth2/authorize", "/saml2/login", "/openid/connect",
                "/api/login", "/rest/auth", "/graphql/auth"
            ],
            "common_credentials": [
                ("admin", "admin"), ("admin", "password"), ("root", "toor"),
                ("user", "user"), ("test", "test"), ("guest", "guest"),
                ("administrator", "password"), ("admin", "123456"),
                ("demo", "demo"), ("service", "service"), ("backup", "backup"),
                ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql")
            ],
            "session_cookies": [
                "sessionid", "PHPSESSID", "JSESSIONID",
                "auth_token", "access_token", "id_token",
                "refresh_token", "remember_token", "csrf_token",
                "jwt_token", "oauth_token"
            ],
            "auth_headers": [
                "Authorization", "X-API-Key", "X-Auth-Token",
                "X-CSRF-Token", "X-OAuth-Token", "Bearer",
                "JWT", "OAuth", "SAML"
            ],
            "password_policy_checks": [
                "123456", "password", "123456789", "12345678",
                "12345", "qwerty", "letmein", "welcome",
                "admin123", "password1", "123123", "sunshine"
            ],
            "sensitive_keywords": [
                "password", "secret", "key", "token",
                "credential", "access", "private",
                "database", "connection", "aws",
                "api_key", "oauth", "jwt"
            ],
            "config_files": [
                "/robots.txt", "/.env", "/config.json",
                "/web.config", "/.git/config", "/.htaccess",
                "/appsettings.json", "/application.properties"
            ],
            "auth_methods": [
                "Basic", "Bearer", "Digest", "NTLM",
                "JWT", "OAuth", "SAML", "OpenID"
            ],
            "vulnerable_auth_methods": [
                "Basic", "Digest", "NTLM",
                "JWT (none algorithm)", "OAuth 1.0"
            ]
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        """Get payloads based on size (small, medium, large) with dynamic additions"""
        payloads = cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])
        
        # Add dynamic common admin paths based on technology
        tech_specific_paths = {
            "wordpress": ["/wp-admin", "/wp-login.php"],
            "drupal": ["/user/login"],
            "joomla": ["/administrator"],
            "laravel": ["/login", "/admin/login"]
        }
        
        for tech, paths in tech_specific_paths.items():
            payloads["login_endpoints"].extend(paths)
        
        # Remove duplicates
        payloads["login_endpoints"] = list(set(payloads["login_endpoints"]))
        
        return payloads