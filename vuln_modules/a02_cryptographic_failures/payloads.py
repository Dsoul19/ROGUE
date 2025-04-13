# vuln_modules/a02_cryptographic_failures/payloads.py
class CryptographicFailuresPayloads:
    PAYLOADS = {
        "small": {
            "weak_algorithms": ["MD5", "SHA1", "RC4", "DES"],
            "tls_checks": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
            "secret_patterns": ["password=", "secret_key=", "api_key="]
        },
        "medium": {
            "weak_algorithms": ["MD5", "SHA1", "RC4", "DES", "3DES", "Blowfish"],
            "tls_checks": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"],
            "secret_patterns": [
                "password=", "secret_key=", "api_key=",
                "access_token=", "private_key=", "database_password="
            ],
            "encryption_anti_patterns": ["AES/ECB", "DES/ECB", "RSA/ECB"]
        },
        "large": {
            "weak_algorithms": ["MD5", "SHA1", "RC4", "DES", "3DES", "Blowfish", "SHA-224"],
            "tls_checks": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"],
            "secret_patterns": [
                "password=", "secret_key=", "api_key=",
                "access_token=", "private_key=", "database_password=",
                "aws_secret=", "jwt_secret=", "encryption_key="
            ],
            "encryption_anti_patterns": [
                "AES/ECB", "DES/ECB", "RSA/ECB",
                "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"
            ],
            "weak_key_sizes": ["RSA-1024", "DSA-1024", "DH-1024"]
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        return cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])