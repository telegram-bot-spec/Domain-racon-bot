import os
from typing import Dict, List

# ============================================================================
# ADMIN CONFIGURATION
# ============================================================================

# Your Telegram User ID (get from @userinfobot)
ADMIN_USER_ID = os.environ.get('ADMIN_USER_ID', '123456789')  # CHANGE THIS!
MAIN_ADMIN_ID = int(ADMIN_USER_ID) if ADMIN_USER_ID else 0

# Additional admins (comma-separated)
ADMIN_USER_IDS_STR = os.environ.get('ADMIN_USER_IDS', '')
ADMIN_USER_IDS = [int(id.strip()) for id in ADMIN_USER_IDS_STR.split(',') if id.strip()]

# ============================================================================
# PAYMENT CONFIGURATION
# ============================================================================

# UPI ID (your personal UPI)
UPI_ID = os.environ.get('UPI_ID', 'your_upi@paytm')  # CHANGE THIS!
UPI_NAME = os.environ.get('UPI_NAME', 'Aryan')  # CHANGE THIS!

# Support Contact
SUPPORT_USERNAME = os.environ.get('SUPPORT_USERNAME', 'aryansmilezzz')
SUPPORT_GROUP = os.environ.get('SUPPORT_GROUP', 'https://t.me/your_group')

# ============================================================================
# PRICING PLANS
# ============================================================================

PRICING_PLANS = {
    'trial': {
        'name': 'Trial',
        'duration_hours': 1,
        'price_inr': 29,
        'price_usd': 0.35,
        'scans_limit': 15,
        'emoji': '⏰',
        'features': ['All scan modes', 'Test features', '15 scans'],
    },
    'basic': {
        'name': 'Basic',
        'duration_hours': 24,
        'price_inr': 79,
        'price_usd': 0.95,
        'scans_limit': 50,
        'emoji': '📦',
        'features': ['All scans', 'Subdomain scan', '50 scans', '1 day access'],
    },
    'standard': {
        'name': 'Standard',
        'duration_hours': 168,  # 1 week
        'price_inr': 199,
        'price_usd': 2.40,
        'scans_limit': 200,
        'emoji': '⭐',
        'features': ['Full OSINT', 'Export results', '200 scans', '1 week access'],
    },
    'pro': {
        'name': 'Pro',
        'duration_hours': 720,  # 30 days
        'price_inr': 499,
        'price_usd': 6.00,
        'scans_limit': 1000,
        'emoji': '🚀',
        'features': ['All features', 'API access', '1000 scans', '1 month access'],
    },
    'lifetime': {
        'name': 'Lifetime',
        'duration_hours': None,  # Never expires
        'price_inr': 1999,
        'price_usd': 24.00,
        'scans_limit': None,  # Unlimited
        'emoji': '♾️',
        'features': ['Unlimited scans', 'Forever access', 'All future features'],
    },
}

# Free tier configuration
FREE_TIER = {
    'daily_scan_limit': 5,
    'allowed_commands': ['quick'],
    'features': ['Basic DNS', 'Quick scan only', 'Limited results'],
}

# Feature gating per plan
PLAN_FEATURES = {
    'free': {
        'commands': ['start', 'help', 'quick', 'shop', 'myplan'],
        'daily_scans': 5,
        'modules': ['dns_basic', 'ip_basic'],
    },
    'trial': {
        'commands': ['start', 'help', 'quick', 'scan', 'dns', 'shop', 'myplan'],
        'total_scans': 15,
        'modules': ['dns', 'subdomains_basic', 'tech_basic', 'whois'],
    },
    'basic': {
        'commands': ['start', 'help', 'quick', 'scan', 'dns', 'subs', 'whois', 'ports', 'tech', 'ip', 'shop', 'myplan'],
        'total_scans': 50,
        'modules': ['dns', 'subdomains', 'whois', 'tech', 'security', 'ip', 'ports_quick'],
    },
    'standard': {
        'commands': ['*'],  # All except ninja
        'total_scans': 200,
        'modules': ['dns_full', 'subdomains_full', 'whois', 'tech_full', 'security_full', 'ip_full', 'social_basic', 'ports_full'],
        'export': True,
    },
    'pro': {
        'commands': ['*'],  # All commands
        'total_scans': 1000,
        'modules': ['*'],  # All modules
        'export': True,
        'api_access': True,
    },
    'lifetime': {
        'commands': ['*'],
        'scans': 'unlimited',
        'modules': ['*'],
        'export': True,
        'api_access': True,
    },
}

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

# Database URL (Supabase PostgreSQL or local SQLite)
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Use SQLite for local development
USE_SQLITE = os.environ.get('USE_SQLITE', 'True').lower() == 'true'
SQLITE_DB_PATH = 'data/bot_database.db'

# ============================================================================
# BOT CONFIGURATION
# ============================================================================

# Telegram Bot Token (Required)
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')

# Bot Information
BOT_VERSION = "2.0.0"
BOT_NAME = "Ultimate Recon Bot"
DEVELOPER = "Your Name"

# ============================================================================
# RATE LIMITING
# ============================================================================

# Maximum scans per user per time window
RATE_LIMIT_SCANS = 20  # scans
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

# Cooldown between scans (same domain)
DOMAIN_COOLDOWN = 30  # seconds

# Global rate limiting (all users combined)
GLOBAL_RATE_LIMIT = 100  # scans per hour
GLOBAL_RATE_WINDOW = 3600  # seconds

# ============================================================================
# SCAN SETTINGS
# ============================================================================

# Timeouts (seconds)
DEFAULT_TIMEOUT = 10
DNS_TIMEOUT = 5
PORT_SCAN_TIMEOUT = 1
HTTP_TIMEOUT = 10
WHOIS_TIMEOUT = 15

# Subdomain scanning
MAX_SUBDOMAINS = 500
SUBDOMAIN_VALIDATION = True  # Check if subdomains resolve
SUBDOMAIN_ALIVE_CHECK = True  # Check if subdomains respond to HTTP

# Port scanning
DEFAULT_PORTS_TO_SCAN = 100
MAX_PORTS_TO_SCAN = 1000
PARALLEL_PORT_SCANS = 20  # Scan 20 ports simultaneously

# Common ports to scan
COMMON_PORTS: Dict[int, str] = {
    # Web Services
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    3000: "Node.js/React Dev",
    5000: "Flask/Python Dev",
    8000: "Django/Python Dev",
    8888: "HTTP-Alt",
    9090: "HTTP-Alt",
    
    # SSH/FTP/Telnet
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    69: "TFTP",
    115: "SFTP",
    2222: "SSH-Alt",
    
    # Mail
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    
    # Database
    1433: "MS SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    7474: "Neo4j",
    8529: "ArangoDB",
    9042: "Cassandra",
    9200: "Elasticsearch",
    27017: "MongoDB",
    27018: "MongoDB",
    28017: "MongoDB Web",
    50000: "DB2",
    
    # Message Queues
    4369: "Erlang Port Mapper",
    5671: "AMQPS",
    5672: "AMQP",
    9092: "Kafka",
    15672: "RabbitMQ Management",
    61613: "STOMP",
    61614: "STOMP-SSL",
    61616: "ActiveMQ",
    
    # Proxy/Cache
    3128: "Squid Proxy",
    8080: "Proxy",
    9050: "Tor",
    11211: "Memcached",
    
    # Remote Access
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    
    # Directory Services
    389: "LDAP",
    636: "LDAPS",
    
    # Monitoring/Management
    161: "SNMP",
    162: "SNMP Trap",
    10000: "Webmin",
    19999: "Netdata",
    
    # Game Servers
    25565: "Minecraft",
    27015: "Steam/Source",
    
    # IoT/MQTT
    1883: "MQTT",
    8883: "MQTT-SSL",
    
    # Docker/Kubernetes
    2375: "Docker",
    2376: "Docker-SSL",
    6443: "Kubernetes API",
    8001: "Kubernetes Dashboard",
    10250: "Kubelet API",
    
    # Other
    111: "RPC",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    514: "Syslog",
    873: "Rsync",
    1194: "OpenVPN",
    1723: "PPTP",
    2049: "NFS",
    3000: "Grafana",
    4444: "Metasploit",
    5000: "Docker Registry",
    5555: "Android Debug Bridge",
    5601: "Kibana",
    6000: "X11",
    7001: "WebLogic",
    8081: "HTTP-Alt",
    8082: "HTTP-Alt",
    8089: "Splunk",
    8161: "ActiveMQ Admin",
    9000: "SonarQube",
    9090: "Prometheus",
    9091: "Transmission",
    9443: "HTTPS-Alt",
    10050: "Zabbix Agent",
    50000: "SAP",
}

# ============================================================================
# API ENDPOINTS (Free Services)
# ============================================================================

# Subdomain enumeration APIs
SUBDOMAIN_SOURCES = {
    'crtsh': 'https://crt.sh/?q=%.{domain}&output=json',
    'hackertarget': 'https://api.hackertarget.com/hostsearch/?q={domain}',
    'threatcrowd': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
}

# IP Intelligence APIs
IP_APIS = {
    'ipapi': 'http://ip-api.com/json/{ip}',  # Free, 45 req/min
    'ipinfo': 'https://ipinfo.io/{ip}/json',  # Free, 50k/month (no key needed for basic)
}

# Reputation/Threat Intel APIs (No key required)
REPUTATION_APIS = {
    'phishtank': 'https://checkurl.phishtank.com/checkurl/',
    'urlhaus': 'https://urlhaus-api.abuse.ch/v1/url/',
}

# ============================================================================
# OPTIONAL API KEYS (Enhance functionality if provided)
# ============================================================================

# VirusTotal (Free: 4 requests/minute, 500/day)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

# AbuseIPDB (Free: 1000 requests/day)
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

# Shodan (Limited free search)
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

# SecurityTrails (Free: 50 requests/month)
SECURITYTRAILS_API_KEY = os.environ.get('SECURITYTRAILS_API_KEY', '')

# Hunter.io (Free: 25 requests/month)
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY', '')

# Google Safe Browsing (Free with quota)
GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')

# Have I Been Pwned (Free for breaches, paid for paste search)
HIBP_API_KEY = os.environ.get('HIBP_API_KEY', '')

# ============================================================================
# BLACKLIST (Domains to NEVER scan)
# ============================================================================

BLACKLISTED_DOMAINS: List[str] = [
    # Government domains
    '.gov',
    '.mil',
    
    # Critical infrastructure
    'whitehouse.gov',
    'defense.gov',
    'fbi.gov',
    'cia.gov',
    'nsa.gov',
    
    # Add more as needed
]

BLACKLISTED_TLDs: List[str] = [
    '.gov',
    '.mil',
]

# ============================================================================
# USER AGENTS (Rotate for requests)
# ============================================================================

USER_AGENTS: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
]

# ============================================================================
# MESSAGE FORMATTING
# ============================================================================

# Telegram message limits
MAX_MESSAGE_LENGTH = 4096
MAX_CAPTION_LENGTH = 1024

# Emojis for formatting
EMOJI = {
    'success': '✅',
    'warning': '⚠️',
    'error': '❌',
    'info': 'ℹ️',
    'loading': '🔄',
    'search': '🔍',
    'globe': '🌐',
    'lock': '🔒',
    'unlock': '🔓',
    'fire': '🔥',
    'chart': '📊',
    'computer': '💻',
    'database': '🗄️',
    'email': '📧',
    'link': '🔗',
    'shield': '🛡️',
    'target': '🎯',
    'rocket': '🚀',
    'ninja': '🥷',
    'lightning': '⚡',
    'spy': '🕵️',
    'satellite': '📡',
    'package': '📦',
    'gear': '⚙️',
    'phone': '📱',
    'building': '🏢',
    'location': '📍',
    'flag': '🚩',
}

# Risk levels
RISK_LEVELS = {
    'critical': {'emoji': '🔴', 'label': 'CRITICAL', 'min': 0, 'max': 39},
    'high': {'emoji': '🟠', 'label': 'HIGH', 'min': 40, 'max': 59},
    'medium': {'emoji': '🟡', 'label': 'MEDIUM', 'min': 60, 'max': 74},
    'low': {'emoji': '🟢', 'label': 'LOW', 'min': 75, 'max': 89},
    'excellent': {'emoji': '🟢', 'label': 'EXCELLENT', 'min': 90, 'max': 100},
}

# ============================================================================
# SCAN MODES
# ============================================================================

SCAN_MODES = {
    'quick': {
        'name': 'Quick Scan',
        'emoji': '⚡',
        'duration': '30-60s',
        'modules': ['dns_basic', 'subdomains_basic', 'tech_basic', 'security_headers', 'ip_geo'],
    },
    'smart': {
        'name': 'Smart Scan',
        'emoji': '🔍',
        'duration': '2-4min',
        'modules': ['dns', 'subdomains', 'whois', 'tech', 'security', 'ip', 'social_basic', 'ports_quick'],
    },
    'deep': {
        'name': 'Deep Scan',
        'emoji': '🕵️',
        'duration': '5-7min',
        'modules': ['dns_full', 'subdomains_full', 'whois', 'tech_full', 'security_full', 'ip_full', 
                    'social_full', 'emails', 'github_secrets', 'reputation', 'content', 'api_discovery', 'ports_full'],
    },
    'ninja': {
        'name': 'Ninja Scan',
        'emoji': '🥷',
        'duration': '8-10min',
        'modules': ['dns_full', 'subdomains_full', 'whois', 'tech_full', 'security_full', 'ip_full', 
                    'social_full', 'emails', 'github_secrets', 'reputation', 'content', 'api_discovery', 'ports_stealth'],
        'stealth': True,
        'delay_range': (2, 5),  # Random delay between requests
    },
}

# ============================================================================
# TECHNOLOGY DETECTION CATEGORIES
# ============================================================================

TECH_CATEGORIES = [
    'cms',
    'frameworks',
    'programming_languages',
    'web_servers',
    'databases',
    'analytics',
    'cdn',
    'waf',
    'js_libraries',
    'payment_processors',
    'marketing_automation',
    'tag_managers',
]

# ============================================================================
# DNS RECORD TYPES
# ============================================================================

DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR']

# ============================================================================
# VALIDATION
# ============================================================================

def validate_config():
    """Validate that required configuration is present"""
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN environment variable is required!")
    return True

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_risk_level(score: int) -> dict:
    """Get risk level information based on score (0-100)"""
    for level, info in RISK_LEVELS.items():
        if info['min'] <= score <= info['max']:
            return {'level': level, **info}
    return RISK_LEVELS['critical']

def is_blacklisted(domain: str) -> bool:
    """Check if domain is blacklisted"""
    domain = domain.lower()
    
    # Check full domain
    if domain in BLACKLISTED_DOMAINS:
        return True
    
    # Check TLDs
    for tld in BLACKLISTED_TLDs:
        if domain.endswith(tld):
            return True
    
    return False

def get_ports_by_category(category: str = None) -> List[int]:
    """Get ports by category (web, database, mail, etc.)"""
    if category == 'web':
        return [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090]
    elif category == 'database':
        return [1433, 1521, 3306, 5432, 5984, 6379, 7474, 8529, 9042, 9200, 27017, 27018]
    elif category == 'mail':
        return [25, 110, 143, 465, 587, 993, 995]
    elif category == 'ssh':
        return [22, 2222]
    elif category == 'common':
        return list(COMMON_PORTS.keys())[:50]  # Top 50
    else:
        return list(COMMON_PORTS.keys())  # All ports
