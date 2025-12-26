# Configuration settings
class Config:
    # API Keys (Add your own keys)
    VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
    SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
    SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
    CENSYS_API_ID = "YOUR_CENSYS_API_ID"
    CENSYS_API_SECRET = "YOUR_CENSYS_API_SECRET"
    
    # Default wordlist paths
    DEFAULT_WORDLIST = "wordlists/subdomains.txt"
    BRUTE_WORDLIST = "wordlists/brute_subdomains.txt"
    
    # Timeout settings
    REQUEST_TIMEOUT = 10
    CONCURRENT_REQUESTS = 50
    
    # Output settings
    SAVE_RESULTS = True
    DEFAULT_OUTPUT_FORMAT = "txt"
    
    # Colors for output
    COLORS = {
        'success': '\033[92m',
        'warning': '\033[93m',
        'error': '\033[91m',
        'info': '\033[94m',
        'reset': '\033[0m'
    }