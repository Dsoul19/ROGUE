# ROGUE 🕵️‍♂️

**Python-Powered OWASP Top 10 Deep Scanner for Offensive Security**

![ROGUE Banner](https://img.shields.io/badge/ROGUE-Deep_Scanning_Tool-red?style=for-the-badge&logo=python)  
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)  
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)  
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen?style=flat-square)

---

## 🌌 Unleash the Power of ROGUE

**ROGUE** is a state-of-the-art, Python-based offensive security scanner designed to detect and exploit vulnerabilities in web applications, with a laser focus on the **OWASP Top 10 (2021)**. Crafted for security researchers, penetration testers, and red teamers, ROGUE combines precision, modularity, and raw power to uncover weaknesses with surgical accuracy.

With its sleek, hacker-inspired CLI, customizable payloads, and deep scanning capabilities, ROGUE is your ultimate weapon for offensive security assessments. Whether you’re hunting broken access controls, cryptographic flaws, or server-side request forgery (SSRF), ROGUE delivers results with style and dominance.

---

## 🎯 Key Features

- **Comprehensive OWASP Top 10 Coverage**: Targets all OWASP Top 10 (2021) vulnerabilities with precision.
- **Modular Architecture**: Extensible modules for each vulnerability, equipped with tailored assessment logic and payloads.
- **Customizable Payloads**: Select small, medium, or large payload sizes to balance speed and thoroughness.
- **Verbose Debugging**: Toggle verbose mode for detailed scanning insights.
- **Async & Sync Support**: Handles both synchronous and asynchronous assessments for maximum efficiency.
- **Hacker-Centric CLI**: Colorful, intuitive command-line interface built for pros.
- **Cross-Platform**: Runs seamlessly on Windows, macOS, and Linux.
- **Open-Source**: Licensed under the MIT License, welcoming community contributions.

---

## 🛠️ Installation

Get ROGUE up and running in minutes to start owning your targets.

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- A hacker’s mindset 😎

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Dsoul19/ROGUE.git
   cd ROGUE
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch ROGUE**:
   ```bash
   python rogue.py
   ```

4. **Optional**: Verify installation:
   ```bash
   python rogue.py --help
   ```

---

## 🚀 Usage

ROGUE’s CLI is engineered for speed, precision, and a true hacker experience. Dive in with these commands:

### Basic Commands

```bash
rogue> help                # Display help menu
rogue> show modules        # List OWASP Top 10 modules
rogue> use <module_id>     # Select a module (e.g., `use 1` for Broken Access Control)
rogue> show techniques     # List techniques for the selected module
rogue> set target <url>    # Set the target URL (e.g., `set target http://example.com`)
rogue> set payload <size>  # Choose payload size: small, medium, large
rogue> set verbose on      # Enable verbose output
rogue> run                 # Execute the selected technique
rogue> exit                # Terminate the session
```

### Example Workflow

```bash
rogue> show modules
rogue> use 3               # Select A03: Injection
rogue/Injection> show techniques
rogue/Injection> use 1     # Select a technique
rogue/Injection/SQL_Injection> set target http://example.com
rogue/Injection/SQL_Injection> set payload medium
rogue/Injection/SQL_Injection> run
```

---

## 🔍 Supported Modules

ROGUE covers the full **OWASP Top 10 (2021)** vulnerability spectrum:

| ID  | Module Name                              | Description                                                                 |
|-----|------------------------------------------|-----------------------------------------------------------------------------|
| A01 | Broken Access Control                    | Detects unauthorized access to restricted resources.                        |
| A02 | Cryptographic Failures                   | Identifies weak encryption and sensitive data exposure.                     |
| A03 | Injection                                | Uncovers SQL, command, and other injection vulnerabilities.                 |
| A04 | Insecure Design                          | Finds flaws in application design that lead to security risks.              |
| A05 | Security Misconfiguration                 | Exposes misconfigured servers, APIs, and cloud services.                    |
| A06 | Vulnerable and Outdated Components       | Detects use of known vulnerable libraries and frameworks.                   |
| A07 | Identification and Authentication Failures | Exploits weak authentication mechanisms.                                   |
| A08 | Software and Data Integrity Failures     | Identifies integrity issues in software updates and data validation.        |
| A09 | Security Logging and Monitoring Failures | Detects insufficient logging that allows attacks to go unnoticed.           |
| A10 | Server-Side Request Forgery (SSRF)       | Exploits forced internal requests bypassing firewalls.                      |

Each module includes **custom assessment logic** and **payloads** for deep, targeted scanning.

---

## 🖥️ CLI Interface

ROGUE’s CLI blends functionality with a bold, hacker-inspired aesthetic:

```
                                        .-+#-               
                                      .+####.               
                          ..-.        +##..                 
                         ..##..      .##.          ..++-.   
                         .+#+....-+++##+...        .+##+.   
           ...      ..-##############++#####-..  ..+##+.    
                  .+####################+-####+.+###+..     
             ...-#########################++####+-..        
          .+####################################.           
       .-#######################################.           
       .++..###################################-.           
          .##+--+################################-..---.   
..........##+     .+##################################++-  .
..     .-###+     .+############################....        
    .-#######.  ..#####+.    .+#################            
   .-##+######--#######-       .+##############+            
   .##-.+########..+###.        -##############.            
  .##+  .+######.  -####-.....-#################+..         
 .+#+.    -#####  .+########################-..###-         
          .+####--+######################+-.    +#+         
          .+#################-......+###.       +##         
          .+##############-.         .###.      -##.        
           .############+.            -##       ....        
            .+#####+..               .##+                   
                            .        .##-                   
                                     .##.                   

       =[--- - -- +    ROGUE v1.0    + -- - ---=]
+ -- --=[  Python-Powered OWASP Top 10 Scanner   ]
+ -- --=[  Scan - Detect - Report                ]
+ -- --=[  Coded By - Dsoul19 A.K.A Goutam       ]

Type help or ? for commands
------------------------------------------------------------
rogue> 
```

---

## ⚠️ Legal Disclaimer

**ROGUE is intended for authorized security testing only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for misuse of this tool. Always obtain proper authorization before scanning.

---

## 🤝 Contributing

We welcome contributions from the security community! Whether it’s adding new modules, refining payloads, or fixing bugs, your input strengthens ROGUE.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/awesome-module`).
3. Commit your changes (`git commit -m "Added awesome module"`).
4. Push to the branch (`git push origin feature/awesome-module`).
5. Open a Pull Request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📜 License

ROGUE is licensed under the [MIT License](LICENSE).  
Copyright © 2025 Goutam Kumar Jena.  
See the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

- **Goutam Kumar Jena (Dsoul19)**  
  Twitter: [@Dsoul19](https://twitter.com/Dsoul19)  
  GitHub: [Dsoul19](https://github.com/Dsoul19)

---

## 🌟 Acknowledgments

- The **OWASP Foundation** for the Top 10 framework.
- The open-source community for inspiration and collaboration.
- Every hacker pushing the boundaries of offensive security.

---

**ROGUE: Scan Deep, Hack Smart.**  
Ready to dominate your next pentest? Fire up ROGUE and let’s roll! 🚀
```
