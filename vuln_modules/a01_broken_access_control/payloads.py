# vuln_modules/a01_broken_access_control/payloads.py
class BrokenAccessControlPayloads:
    PAYLOADS = {
        "small": {
            "admin_paths": [
                "/admin",
                "/wp-admin", 
                "/administrator",
                "/backoffice"
            ],
            "idor_params": [
                "id=1",
                "user_id=1",
                "account=1"
            ]
        },
        "medium": {
            "admin_paths": [
                "/admin",
                "/wp-admin",
                "/administrator", 
                "/backoffice",
                "/admin/dashboard",
                "/admin/console",
                "/system"
            ],
            "idor_params": [
                "id=1",
                "user_id=1",
                "account=1",
                "document=1001",
                "file=report.pdf",
                "order=1001"
            ],
            "privileged_actions": [
                "/api/roles/update",
                "/api/users/promote"
            ]
        },
        "large": {
            "admin_paths": [
                "/admin",
                "/wp-admin",
                "/administrator",
                "/backoffice",
                "/admin/dashboard",
                "/admin/console",
                "/system",
                "/admincp",
                "/webadmin",
                "/admin_area",
                "/admin123",
                "/adminpanel"
            ],
            "idor_params": [
                "id=1",
                "user_id=1",
                "account=1",
                "document=1001",
                "file=report.pdf", 
                "order=1001",
                "invoice=1001",
                "transaction=1001",
                "customer=1",
                "client=1"
            ],
            "privileged_actions": [
                "/api/roles/update",
                "/api/users/promote",
                "/api/permissions/grant",
                "/api/keys/generate",
                "/api/config/security",
                "/api/settings/global"
            ],
            "sensitive_paths": [
                "/.env",
                "/config.json",
                "/.git/config",
                "/phpinfo.php",
                "/.htaccess"
            ]
        }
    }
    @classmethod
    def get_payloads(cls, size="medium"):
        return cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])