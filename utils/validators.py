"""
Input validation and sanitization utilities
"""

import re
import ipaddress
import sys
import os
from typing import Optional, Tuple
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def is_valid_domain(domain: str) -> bool:
    """
    Validate if string is a valid domain name
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not domain or len(domain) > 253:
        return False
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Domain regex pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    
    if not re.match(pattern, domain):
        return False
    
    # Check each label (part between dots)
    labels = domain.split('.')
    if len(labels) < 2 and domain.lower() != 'localhost':  # Must have at least domain.tld (except localhost)
        return False
    
    for label in labels:
        if len(label) > 63:  # Max label length
            return False
    
    return True


def is_valid_ip(ip: str) -> bool:
    """
    Validate if string is a valid IP address (v4 or v6)
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_url(url: str) -> bool:
    """
    Validate if string is a valid URL
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def sanitize_domain(domain: str) -> str:
    """
    Clean and sanitize domain input
    
    Args:
        domain: Raw domain input
        
    Returns:
        Cleaned domain name
    """
    # Remove whitespace
    domain = domain.strip()
    
    # Remove protocol
    domain = domain.replace('http://', '').replace('https://', '')
    
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Remove path and query string
    domain = domain.split('/')[0].split('?')[0]
    
    # Remove port
    if ':' in domain and not is_valid_ip(domain):
        domain = domain.split(':')[0]
    
    # Convert to lowercase
    domain = domain.lower()
    
    return domain


def parse_domain_input(user_input: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Parse and validate user domain input
    
    Args:
        user_input: Raw user input
        
    Returns:
        Tuple of (is_valid, domain, error_message)
    """
    if not user_input:
        return False, None, "No domain provided"
    
    # Sanitize input
    domain = sanitize_domain(user_input)
    
    # Check if blacklisted
    if config.is_blacklisted(domain):
        return False, None, f"❌ Domain '{domain}' is blacklisted. We cannot scan government or military domains."
    
    # Validate domain
    if not is_valid_domain(domain):
        # Check if it's an IP
        if is_valid_ip(domain):
            return True, domain, None
        else:
            return False, None, f"❌ Invalid domain: '{domain}'. Please provide a valid domain name (e.g., example.com)"
    
    return True, domain, None


def validate_port_range(port_input: str) -> Tuple[bool, Optional[list], Optional[str]]:
    """
    Validate and parse port range input
    
    Args:
        port_input: Port range string (e.g., "80", "80,443", "1-1000")
        
    Returns:
        Tuple of (is_valid, port_list, error_message)
    """
    try:
        ports = []
        
        # Split by comma for multiple ports/ranges
        parts = port_input.split(',')
        
        for part in parts:
            part = part.strip()
            
            # Check if it's a range (e.g., "1-1000")
            if '-' in part:
                start, end = part.split('-')
                start, end = int(start), int(end)
                
                if start < 1 or end > 65535 or start > end:
                    return False, None, "❌ Invalid port range. Ports must be between 1-65535."
                
                if end - start > config.MAX_PORTS_TO_SCAN:
                    return False, None, f"❌ Port range too large. Maximum {config.MAX_PORTS_TO_SCAN} ports allowed."
                
                ports.extend(range(start, end + 1))
            else:
                # Single port
                port = int(part)
                if port < 1 or port > 65535:
                    return False, None, "❌ Invalid port number. Ports must be between 1-65535."
                ports.append(port)
        
        if len(ports) > config.MAX_PORTS_TO_SCAN:
            return False, None, f"❌ Too many ports. Maximum {config.MAX_PORTS_TO_SCAN} ports allowed."
        
        # Remove duplicates and sort
        ports = sorted(list(set(ports)))
        
        return True, ports, None
        
    except ValueError:
        return False, None, "❌ Invalid port format. Use: 80, 80,443, or 1-1000"


def is_safe_redirect(url: str, target_url: str) -> bool:
    """
    Check if redirect is safe (same domain or trusted)
    
    Args:
        url: Original URL
        target_url: Redirect target URL
        
    Returns:
        True if safe, False otherwise
    """
    try:
        orig_domain = urlparse(url).netloc
        target_domain = urlparse(target_url).netloc
        
        # Same domain is safe
        if orig_domain == target_domain:
            return True
        
        # Check if both domains have same root
        orig_parts = orig_domain.split('.')
        target_parts = target_domain.split('.')
        
        if len(orig_parts) >= 2 and len(target_parts) >= 2:
            if '.'.join(orig_parts[-2:]) == '.'.join(target_parts[-2:]):
                return True
        
        return False
    except:
        return False


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: URL string
        
    Returns:
        Domain name or None
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return sanitize_domain(domain)
    except:
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is private/internal
    
    Args:
        ip: IP address
        
    Returns:
        True if private, False if public
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False


def normalize_subdomain(subdomain: str) -> str:
    """
    Normalize subdomain (remove wildcards, clean up)
    
    Args:
        subdomain: Raw subdomain
        
    Returns:
        Normalized subdomain
    """
    # Remove wildcard
    subdomain = subdomain.replace('*.', '')
    
    # Remove protocol
    subdomain = subdomain.replace('http://', '').replace('https://', '')
    
    # Remove path
    subdomain = subdomain.split('/')[0]
    
    # Lowercase
    subdomain = subdomain.lower().strip()
    
    return subdomain


def validate_email(email: str) -> bool:
    """
    Basic email validation
    
    Args:
        email: Email address
        
    Returns:
        True if valid format, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def extract_emails_from_text(text: str) -> list:
    """
    Extract email addresses from text
    
    Args:
        text: Text to search
        
    Returns:
        List of found email addresses
    """
    pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    emails = re.findall(pattern, text)
    return list(set(emails))  # Remove duplicates


# Validation summary
def validate_scan_input(domain: str, scan_type: str = 'smart') -> dict:
    """
    Comprehensive validation for scan input
    
    Args:
        domain: Domain to scan
        scan_type: Type of scan (quick, smart, deep, ninja)
        
    Returns:
        Dictionary with validation results
    """
    result = {
        'valid': False,
        'domain': None,
        'is_ip': False,
        'warnings': [],
        'errors': []
    }
    
    # Parse and validate domain
    is_valid, clean_domain, error = parse_domain_input(domain)
    
    if not is_valid:
        result['errors'].append(error)
        return result
    
    result['valid'] = True
    result['domain'] = clean_domain
    result['is_ip'] = is_valid_ip(clean_domain)
    
    # Check if it's a private IP
    if result['is_ip'] and is_private_ip(clean_domain):
        result['warnings'].append("⚠️ This is a private IP address. Some checks may not work.")
    
    # Check scan type
    if scan_type not in config.SCAN_MODES:
        result['warnings'].append(f"⚠️ Unknown scan type '{scan_type}', using 'smart' mode.")
    
    return result
