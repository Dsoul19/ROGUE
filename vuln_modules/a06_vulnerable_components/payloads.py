# vuln_modules/a06_vulnerable_components/payloads.py
from colors import Colors

class VulnerableComponentsPayloads:
    TECH_SIGNATURES = {
        "WordPress": {
            "pattern": r"wp-content|wp-includes",
            "check_url": "/readme.html",
            "version_pattern": r"Version ([\d.]+)"
        },
        "jQuery": {
            "pattern": r"jquery[.-]([\d.]+)\.js",
            "check_url": None
        },
        "Bootstrap": {
            "pattern": r"bootstrap[.-]([\d.]+)\.(?:js|css)",
            "check_url": None
        },
        "Apache": {
            "header": "Server",
            "pattern": r"Apache/([\d.]+)"
        },
        "Nginx": {
            "header": "Server",
            "pattern": r"nginx/([\d.]+)"
        },
        "PHP": {
            "header": "X-Powered-By",
            "pattern": r"PHP/([\d.]+)"
        },
        "MySQL": {
            "pattern": r"MySQL ([\d.]+)",
            "check_url": None
        },
        "MongoDB": {
            "header": "X-Powered-By",
            "pattern": r"MongoDB/([\d.]+)"
        },
        "React": {
            "pattern": r"react[.-]([\d.]+)\.js",
            "check_url": None
        },
        "Vue": {
            "pattern": r"vue[.-]([\d.]+)\.js",
            "check_url": None
        },
        "Django": {
            "header": "X-Framework",
            "pattern": r"Django/([\d.]+)"
        },
        "Laravel": {
            "header": "X-Powered-By",
            "pattern": r"Laravel/([\d.]+)"
        }
    }

    VULNERABLE_ENDPOINTS = {
        "small": [
            "/.git/", "/.env", "/wp-admin/",
            "/phpmyadmin/", "/admin/", "/swagger-ui.html"
        ],
        "medium": [
            "/.git/", "/.env", "/wp-admin/", "/phpmyadmin/",
            "/admin/", "/swagger-ui.html", "/actuator/health",
            "/.svn/", "/.hg/", "/debug/console"
        ],
        "large": [
            "/.git/", "/.env", "/wp-admin/", "/phpmyadmin/", "/admin/",
            "/swagger-ui.html", "/actuator/health", "/.svn/", "/.hg/",
            "/debug/console", "/.aws/credentials", "/config.json",
            "/web.config", "/.htaccess", "/jmx-console/"
        ]
    }

    @classmethod
    def get_tech_signatures(cls):
        return cls.TECH_SIGNATURES

    @classmethod
    def get_endpoints(cls, size="medium"):
        return cls.VULNERABLE_ENDPOINTS.get(size.lower(), cls.VULNERABLE_ENDPOINTS["medium"])