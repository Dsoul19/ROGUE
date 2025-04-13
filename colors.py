# colors.py
class Colors:
    """ANSI color codes for a unique, professional hacking aesthetic."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
   
    
    # Core hacking palette
    NEON_CYAN = "\033[96m"    # Bright cyan for prompts and key info
    NEON_LIME = "\033[92m"    # Vibrant lime for success and positive results
    NEON_MAGENTA = "\033[95m" # Magenta for headers and standout elements
    DEEP_RED = "\033[31m"     # Darker red for errors and critical severity
    SHADOW_GRAY = "\033[90m"  # Subtle gray for secondary details
    RED = "\033[0;91m"  # Vivid orange for the banner
    GREEN= "\033[32m"
    BLUE= "\033[34m"  

    @staticmethod
    def colorize(text, color, bold=False, underline=False):
        """Apply color with optional bold or underline formatting."""
        formatting = ""
        if bold:
            formatting += Colors.BOLD
        return f"{formatting}{color}{text}{Colors.RESET}"

    # Styled methods for a hacking look
    @staticmethod
    def header(text):
        """Bold magenta headers for section titles."""
        return Colors.colorize(text, Colors.DEEP_RED, bold=False)

    @staticmethod
    def success(text):
        """Lime green for successful outcomes."""
        return Colors.colorize(text, Colors.NEON_LIME)

    @staticmethod
    def error(text):
        """Deep red for errors and warnings."""
        return Colors.colorize(text, Colors.DEEP_RED)

    @staticmethod
    def info(text):
        """Neon cyan for informational messages."""
        return Colors.colorize(text, Colors.NEON_CYAN)

    @staticmethod
    def prompt(text):
        """Bold neon cyan for the CLI prompt (no underline)."""
        return Colors.colorize(text, Colors.NEON_CYAN, bold=True)

    @staticmethod
    def banner(text):
        """Atomic orange for the Rogue banner."""
        return Colors.colorize(text, Colors.RED, bold=False)

    @staticmethod
    def subtle(text):
        """Gray for less prominent details."""
        return Colors.colorize(text, Colors.SHADOW_GRAY)
    
    @staticmethod
    def intro(text):
        """For Intro"""
        return Colors.colorize(text, Colors.GREEN)
    
    @staticmethod
    def report(text):
        """For Intro"""
        return Colors.colorize(text, Colors.BLUE)
    
    @staticmethod
    def warning(text):
        """Yellow for warnings"""
        return Colors.colorize(text, "\033[93m")  # Yellow