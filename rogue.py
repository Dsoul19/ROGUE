import cmd
import sys
import os
import platform
from pathlib import Path
from colors import Colors
import asyncio
from datetime import datetime

from vuln_modules.a01_broken_access_control.assessment import BrokenAccessControlAssessment
from vuln_modules.a02_cryptographic_failures.assessment import CryptographicFailuresAssessment
from vuln_modules.a03_injection.assessment import InjectionAssessment
from vuln_modules.a04_insecure_design.assessment import InsecureDesignAssessment
from vuln_modules.a05_security_misconfiguration.assessment import SecurityMisconfigAssessment
from vuln_modules.a06_vulnerable_components.assessment import VulnerableComponentsAssessment
from vuln_modules.a07_authentication_failures.assessment import AuthenticationFailuresAssessment
from vuln_modules.a08_integrity_failures.assessment import IntegrityFailuresAssessment
from vuln_modules.a09_logging_monitoring_failures.assessment import LoggingFailuresAssessment
from vuln_modules.a10_ssrf.assessment import SSRFAssessment

BANNER = Colors.info(r"""                                                                                                                                                                                                                                           
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
""")
class RogueCLI(cmd.Cmd):
    intro = f"""{BANNER}
       =[=--- - -- +{Colors.banner('    ROgUE v1.0    ')}+ -- - ---=]
+ -- --=[{Colors.banner('  Python-Powered OWASP Top 10 Scanner')}   ]
+ -- --=[{Colors.banner('  Scan - Detect - Report')}                ]
+ -- --=[{Colors.banner('  Coded By - Dsoul19 A.K.A Goutam')}       ]

{Colors.subtle('Type help or ? for commands')}
{Colors.subtle('-' * 60)}"""
    prompt = Colors.prompt("rogue> ")
    doc_header = Colors.info("Available Commands (type help <command> for details):")
    
    def __init__(self):
        super().__init__()
        self.modules = {
            "1": {
                "name": "A01:2021 - Broken Access Control", 
                "class": BrokenAccessControlAssessment,
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions."
            },
            "2": {
                "name": "A02:2021 - Cryptographic Failures", 
                "class": CryptographicFailuresAssessment,
                "description": "Focuses on failures related to cryptography which often lead to sensitive data exposure."
            },
            "3": {
                "name": "A03:2021 - Injection", 
                "class": InjectionAssessment,
                "description": "Untrusted data is sent to an interpreter as part of a command or query."
            },
            "4": {
                "name": "A04:2021 - Insecure Design", 
                "class": InsecureDesignAssessment,
                "description": "Missing or ineffective control design that fails to prevent security issues."
            },
            "5": {
                "name": "A05:2021 - Security Misconfiguration", 
                "class": SecurityMisconfigAssessment,
                "description": "Insecure configurations in applications, servers, or cloud services."
            },
            "6": {
                "name": "A06:2021 - Vulnerable and Outdated Components", 
                "class": VulnerableComponentsAssessment,
                "description": "Use of known vulnerable components in applications."
            },
            "7": {
                "name": "A07:2021 - Identification and Authentication Failures", 
                "class": AuthenticationFailuresAssessment,
                "description": "Weak authentication mechanisms that can be bypassed or broken."
            },
            "8": {
                "name": "A08:2021 - Software and Data Integrity Failures", 
                "class": IntegrityFailuresAssessment,
                "description": "Failures related to integrity verification of software and data."
            },
            "9": {
                "name": "A09:2021 - Security Logging and Monitoring Failures", 
                "class": LoggingFailuresAssessment,
                "description": "Insufficient logging and monitoring enabling attacks to go undetected."
            },
            "10": {
                "name": "A10:2021 - Server-Side Request Forgery", 
                "class": SSRFAssessment,
                "description": "Forced requests to internal systems bypassing firewall protections."
            }
        }
        self.current_module = None
        self.current_module_id = None
        self.current_technique = None
        self.target = None
        self.payload_size = "medium"
        self.verbose = False
        self.scan_active = False

    def emptyline(self):
        """Do nothing on empty input"""
        pass

    def preloop(self):
        """Initialization before command loop"""
        if not hasattr(self, '_first_run'):
            if platform.system() == 'Windows':
                os.system('cls')
            else:
                os.system('clear')
            self._first_run = True

    def do_clear(self, arg):
        """Clear the screen"""
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')
        
    def do_help(self, arg):
        """Display help message"""
        help_text = f"""
        
{Colors.header("Core Commands:")}
  {Colors.info("help/?")}               - Display this help message
  {Colors.info("show modules")}         - List OWASP Top 10 vulnerability modules
  {Colors.info("show info")}            - Show info about current module
  {Colors.info("show techniques")}      - List techniques for the current module
  {Colors.info("use <id>")}             - Select a module or technique by ID
  {Colors.info("set target <url>")}     - Define the target URL
  {Colors.info("set payload <size>")}   - Set payload size (small, medium, large)
  {Colors.info("set verbose <on/off>")} - Toggle verbose output
  {Colors.info("run")}                  - Execute the selected technique
  {Colors.info("back/prev")}            - Navigate to the previous level
  {Colors.info("return")}               - Return to root prompt
  {Colors.info("clear")}                - Clear the screen
  {Colors.info("exit")}                 - Terminate Rogue session
"""
        print(help_text)

    def do_show(self, arg):
        """Show modules, techniques, or module info"""
        if not arg:
            print(Colors.error("Usage: show [modules|techniques|info]"))
            return
            
        args = arg.split()
        if args[0] == "modules":
            self._show_modules()
        elif args[0] == "techniques":
            self._show_techniques()
        elif args[0] == "info":
            self._show_module_info()
        else:
            print(Colors.error(f"Invalid show command: {arg}"))

    def _show_modules(self):
        """Display available modules"""
        print(Colors.header("\nOWASP Top 10 Vulnerability Modules:"))
        for id, module in self.modules.items():
            print(f"  {Colors.success(id)}. {module['name']}")
        print()
        

    def _show_techniques(self):
        """Display techniques for current module"""
        if not self.current_module:
            print(Colors.error("No module selected. Use 'use <id>' first."))
            return
            
        techniques = self.current_module.get_techniques()
        if not techniques:
            print(Colors.error("No techniques available for this module."))
            return
            
        print(Colors.header(f"\nAvailable Techniques for {self.modules[self.current_module_id]['name']}:"))
        for tech in techniques:
            print(f"  {Colors.success(tech)}")
        print()

    def _show_module_info(self):
        """Display information about current module"""
        if not self.current_module:
            print(Colors.error("No module selected. Use 'use <id>' first."))
            return
            
        module_info = self.modules[self.current_module_id]
        print(Colors.header("\nModule Information:"))
        print(f"{Colors.info('Name:')} {module_info['name']}")
        print(f"{Colors.info('Description:')} {module_info.get('description', 'No description available')}")
        print(f"{Colors.info('Techniques:')} {len(self.current_module.get_techniques())} available\n")

    def do_use(self, arg):
        """Select montón or technique by ID"""
        if not arg:
            print(Colors.error("Usage: use <module_id> or use <technique_id>"))
            return
            
        if not self.current_module:
            if arg in self.modules:
                self._select_module(arg)
            else:
                print(Colors.error(f"Invalid module ID: {arg}"))
        else:
            self._select_technique(arg)

    def _select_module(self, module_id):
        """Handle module selection"""
        try:
            self.current_module_id = module_id
            self.current_module = self.modules[module_id]["class"]()
            module_name_short = self.modules[module_id]["name"].split(' - ')[1].replace(' ', '_')
            self.prompt = Colors.prompt(f"rogue/{module_name_short}> ")
            print(Colors.success(f"\nModule selected: {self.modules[module_id]['name']}"))
            print(Colors.info(f"Use 'show techniques' to list available assessments.\n"))
        except Exception as e:
            print(Colors.error(f"[!] Error initializing module: {e}"))
            self.current_module = None
            self.current_module_id = None

    def _select_technique(self, tech_id):
        """Handle technique selection"""
        try:
            clean_id = ''.join(filter(str.isdigit, tech_id))
            
            if not clean_id:
                print(Colors.error("Please specify a technique number"))
                return
                
            techniques = self.current_module.get_techniques()
            
            if not (1 <= int(clean_id) <= len(techniques)):
                print(Colors.error(f"Invalid technique ID: {tech_id}"))
                return
                
            tech_info = next(tech for tech in self.current_module.techniques.values() if tech['id'] == clean_id)
            self.current_technique = tech_info
            
            module_short = self.modules[self.current_module_id]["name"].split(' - ')[1].replace(' ', '_')
            tech_short = tech_info['name'].replace(' ', '_').replace('(', '').replace(')', '')
            self.prompt = Colors.prompt(f"rogue/{module_short}/{tech_short}> ")
            
            print(Colors.success(f"\nTechnique selected: {tech_info['name']}\n"))
            
        except Exception as e:
            print(Colors.error(f"[!] Error selecting technique: {e}"))

    def do_set(self, arg):
        """Set target URL, payload size, or verbose mode"""
        if not arg:
            print(Colors.header("\nCurrent settings:"))
            print(f"  {Colors.info('Target:')} {self.target or Colors.error('Not set')}")
            print(f"  {Colors.info('Payload size:')} {self.payload_size}")
            print(f"  {Colors.info('Verbose:')} {'On' if self.verbose else 'Off'}\n")
            return
            
        args = arg.split()
        if len(args) < 2:
            print(Colors.error("Usage: set [target|payload|verbose] <value>"))
            return
            
        try:
            if args[0] == "target":
                self.target = args[1]
                print(Colors.success(f"\nTarget configured: {self.target}\n"))
            elif args[0] == "payload":
                if args[1] in ["small", "medium", "large"]:
                    self.payload_size = args[1]
                    if self.current_module:
                        self.current_module.set_payload_size(self.payload_size)
                    print(Colors.success(f"\nPayload size set to: {self.payload_size}\n"))
                else:
                    print(Colors.error("\nInvalid payload size. Use small, medium, or large\n"))
            elif args[0] == "verbose":
                if args[1].lower() in ["on", "true", "1"]:
                    self.verbose = True
                    print(Colors.success("\nVerbose mode enabled\n"))
                elif args[1].lower() in ["off", "false", "0"]:
                    self.verbose = False
                    print(Colors.success("\nVerbose mode disabled\n"))
                else:
                    print(Colors.error("\nInvalid verbose value. Use on/off\n"))
            else:
                print(Colors.error("\nInvalid set command. Use target, payload, or verbose\n"))
        except Exception as e:
            print(Colors.error(f"\nError in set command: {e}\n"))

    def do_run(self, arg):
        """Run the selected technique - works with both sync and async modules"""
        if not self.current_module or not self.current_technique:
            print(Colors.error("\nPlease select a module and technique first\n"))
            return
            
        if not self.target:
            print(Colors.error("\nPlease set a target first using 'set target <url>'\n"))
            return
            
        print(Colors.header(f"\nExecuting: {self.current_technique['name']}"))
        print(Colors.info(f"Target: {self.target}"))
        print(Colors.info(f"Payload size: {self.payload_size}"))
        print(Colors.info(f"Verbose: {'On' if self.verbose else 'Off'}\n"))
        
        try:
            self.scan_active = True
            module = self.modules[self.current_module_id]["class"]()
            module.set_payload_size(self.payload_size)
            
            if asyncio.iscoroutinefunction(module.run_assessment):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(
                        module.run_assessment(
                            technique_id=self.current_technique['id'],
                            target=self.target,
                            verbose=self.verbose
                        )
                    )
                finally:
                    loop.close()
            else:
                module.run_assessment(
                    technique_id=self.current_technique['id'],
                    target=self.target,
                    verbose=self.verbose
                )
                
            self.scan_active = False
        except KeyboardInterrupt:
            self.scan_active = False
            print(Colors.error("\n[!] Scan interrupted by user"))
        except Exception as e:
            self.scan_active = False
            print(Colors.error(f"\n[!] Assessment failed: {e}\n"))

    def do_prev(self, arg):
        """Alias for back command"""
        self.do_back(arg)

    def do_back(self, arg):
        """Navigate back one level"""
        if self.current_technique:
            self.current_technique = None
            module_short = self.modules[self.current_module_id]["name"].split(' - ')[1].replace(' ', '_')
            self.prompt = Colors.prompt(f"rogue/{module_short}> ")
            print(Colors.info("\nReturned to module level\n"))
        elif self.current_module:
            self.current_module = None
            self.current_module_id = None
            self.prompt = Colors.prompt("rogue> ")
            print(Colors.info("\nReturned to main menu\n"))

    def do_return(self, arg):
        """Return directly to root prompt"""
        self.current_module = None
        self.current_module_id = None
        self.current_technique = None
        self.prompt = Colors.prompt("rogue> ")
        print(Colors.info("\nReturned to root prompt\n"))

    def do_exit(self, arg):
        """Exit the CLI"""
        if self.scan_active:
            confirm = input(Colors.error("[!] Scan in progress. Are you sure you want to exit? (y/n): "))
            if confirm.lower() not in ['y', 'yes']:
                return False
        
        print(Colors.header("\nShutting down Rogue scanner..."))
        print(Colors.subtle("All connections terminated\n"))
        return True

    def cmdloop(self, intro=None):
        """Custom command loop to handle KeyboardInterrupt gracefully"""
        # Run preloop to clear screen if needed
        self.preloop()
        # Print intro only on first run
        if not hasattr(self, '_intro_printed'):
            print(self.intro)
            self._intro_printed = True
        
        while True:
            try:
                super().cmdloop(intro="")
                break  # Exit loop if cmdloop completes (e.g., via do_exit)
            except KeyboardInterrupt:
                print(Colors.error("\n[!] Interrupted. Press Ctrl+D or type 'exit' to quit."))
                # Do NOT break; continue the loop to keep prompting
                continue
            except Exception as e:
                print(Colors.error(f"\n[!] Unexpected error: {e}"))
                continue  # Continue on other exceptions to keep CLI alive

if __name__ == "__main__":
    try:
        RogueCLI().cmdloop()
    except KeyboardInterrupt:
        print(Colors.error("\n[!] Terminated by user."))
        print(Colors.header("Shutting down Rogue scanner..."))
        print(Colors.subtle("All connections terminated"))
        sys.exit(0)
    except Exception as e:
        print(Colors.error(f"\n[CRITICAL] Fatal error: {e}"))
        sys.exit(1)