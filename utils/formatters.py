"""
Message formatting utilities for Telegram output
"""

import re
import sys
import os
from typing import List, Optional, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def escape_markdown(text: str) -> str:
    """
    Escape special characters for Telegram MarkdownV2
    Note: For production use, consider using HTML mode instead (parse_mode='HTML')
    as it's more forgiving with special characters.
    
    Args:
        text: Text to escape
        
    Returns:
        Escaped text
    """
    # Characters that need escaping in MarkdownV2
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    
    return text


def create_progress_bar(percentage: float, length: int = 10, filled_char: str = '█', empty_char: str = '░') -> str:
    """
    Create ASCII progress bar
    
    Args:
        percentage: Progress percentage (0-100)
        length: Length of progress bar
        filled_char: Character for filled portion
        empty_char: Character for empty portion
        
    Returns:
        Progress bar string
    """
    percentage = max(0, min(100, percentage))  # Clamp between 0-100
    filled = int((percentage / 100) * length)
    empty = length - filled
    
    bar = filled_char * filled + empty_char * empty
    return f"[{bar}] {percentage:.0f}%"


def format_risk_score(score: int) -> str:
    """
    Format risk score with emoji and label
    
    Args:
        score: Risk score (0-100, higher is better)
        
    Returns:
        Formatted risk score string
    """
    risk_info = config.get_risk_level(score)
    emoji = risk_info['emoji']
    label = risk_info['label']
    
    return f"{emoji} **{score}/100** ({label})"


def format_list(items: List[str], max_items: int = 10, bullet: str = '├─', last_bullet: str = '└─') -> str:
    """
    Format list with tree-style bullets
    
    Args:
        items: List of items to format
        max_items: Maximum items to show before truncating
        bullet: Bullet character for items
        last_bullet: Bullet character for last item
        
    Returns:
        Formatted list string
    """
    if not items:
        return "└─ None found"
    
    result = []
    display_items = items[:max_items]
    
    for i, item in enumerate(display_items):
        if i == len(display_items) - 1 and len(items) <= max_items:
            result.append(f"{last_bullet} {item}")
        else:
            result.append(f"{bullet} {item}")
    
    if len(items) > max_items:
        remaining = len(items) - max_items
        result.append(f"{last_bullet} ... and {remaining} more")
    
    return '\n'.join(result)


def truncate_message(text: str, max_length: int = config.MAX_MESSAGE_LENGTH) -> List[str]:
    """
    Truncate message to fit Telegram's character limit
    Split into multiple messages if needed
    Preserves line breaks to avoid breaking formatting
    
    Args:
        text: Text to truncate
        max_length: Maximum length per message
        
    Returns:
        List of message chunks
    """
    if len(text) <= max_length:
        return [text]
    
    chunks = []
    current_chunk = ""
    
    # Split by lines to avoid breaking formatting
    lines = text.split('\n')
    
    for line in lines:
        # If single line is too long, force split
        if len(line) > max_length:
            if current_chunk:
                chunks.append(current_chunk.rstrip())
                current_chunk = ""
            
            # Split long line into chunks
            for i in range(0, len(line), max_length):
                chunks.append(line[i:i + max_length])
        
        # If adding this line exceeds limit, start new chunk
        elif len(current_chunk) + len(line) + 1 > max_length:
            if current_chunk:
                chunks.append(current_chunk.rstrip())
            current_chunk = line
        
        else:
            if current_chunk:
                current_chunk += '\n' + line
            else:
                current_chunk = line
    
    if current_chunk:
        chunks.append(current_chunk.rstrip())
    
    return chunks


def format_message(title: str, content: Dict[str, Any], emoji: str = '🔍') -> str:
    """
    Format a structured message with title and content
    
    Args:
        title: Message title
        content: Dictionary of content sections
        emoji: Title emoji
        
    Returns:
        Formatted message string
    """
    separator = "━" * 30
    
    message = f"{emoji} **{title}**\n{separator}\n\n"
    
    for section, data in content.items():
        if isinstance(data, dict):
            message += f"**{section}**\n"
            for key, value in data.items():
                message += f"├─ {key}: {value}\n"
            message += "\n"
        elif isinstance(data, list):
            message += f"**{section}**\n"
            message += format_list(data) + "\n\n"
        else:
            message += f"**{section}:** {data}\n\n"
    
    return message.rstrip()


def format_header(title: str, subtitle: Optional[str] = None, emoji: str = '🔍') -> str:
    """
    Format message header
    
    Args:
        title: Main title
        subtitle: Optional subtitle
        emoji: Header emoji
        
    Returns:
        Formatted header
    """
    separator = "━" * 30
    header = f"{emoji} **{title.upper()}**\n{separator}\n"
    
    if subtitle:
        header += f"{subtitle}\n{separator}\n"
    
    return header


def format_section(title: str, items: List[str], emoji: str = '📋') -> str:
    """
    Format a content section
    
    Args:
        title: Section title
        items: List of items in section
        emoji: Section emoji
        
    Returns:
        Formatted section
    """
    section = f"\n{emoji} **{title.upper()}**\n"
    section += "━" * 30 + "\n\n"
    section += format_list(items) + "\n"
    
    return section


def format_dns_results(dns_data: Dict[str, Any]) -> str:
    """
    Format DNS scan results
    
    Args:
        dns_data: DNS scan results
        
    Returns:
        Formatted DNS message
    """
    message = format_header("DNS Analysis", emoji='🌐')
    
    for record_type, records in dns_data.items():
        if records:
            message += f"\n**{record_type} Records:**\n"
            if isinstance(records, list):
                message += format_list([str(r) for r in records]) + "\n"
            else:
                message += f"└─ {records}\n"
    
    return message


def format_subdomain_results(subdomains: Dict[str, List[str]], total: int) -> str:
    """
    Format subdomain enumeration results
    
    Args:
        subdomains: Dictionary of categorized subdomains
        total: Total subdomains found
        
    Returns:
        Formatted subdomain message
    """
    message = format_header(f"Subdomains Found: {total}", emoji='📡')
    
    categories = {
        'production': ('🟢 PRODUCTION', subdomains.get('production', [])),
        'staging': ('🟡 STAGING/DEV', subdomains.get('staging', [])),
        'dead': ('🔴 DEAD/INACTIVE', subdomains.get('dead', [])),
    }
    
    for category, (label, items) in categories.items():
        if items:
            message += f"\n{label} ({len(items)})\n"
            message += format_list(items, max_items=5) + "\n"
    
    return message


def format_port_results(open_ports: List[Dict[str, Any]], closed_count: int, filtered_count: int) -> str:
    """
    Format port scan results
    
    Args:
        open_ports: List of open port dictionaries
        closed_count: Number of closed ports
        filtered_count: Number of filtered ports
        
    Returns:
        Formatted port scan message
    """
    total = len(open_ports) + closed_count + filtered_count
    message = format_header(f"Port Scan Results", emoji='🔌')
    
    message += f"**Scanned:** {total} ports\n"
    message += f"**Open:** {len(open_ports)} | **Closed:** {closed_count} | **Filtered:** {filtered_count}\n\n"
    
    if open_ports:
        # Group by category
        categories = {}
        for port_info in open_ports:
            category = port_info.get('category', 'Other')
            if category not in categories:
                categories[category] = []
            categories[category].append(port_info)
        
        for category, ports in categories.items():
            message += f"**{category.upper()}**\n"
            for port_info in ports[:10]:  # Limit to 10 per category
                port = port_info['port']
                service = port_info.get('service', 'Unknown')
                version = port_info.get('version', '')
                
                line = f"├─ {port}/tcp  {service}"
                if version:
                    line += f"  ({version})"
                message += line + "\n"
            message += "\n"
    else:
        message += "└─ No open ports found\n"
    
    return message


def format_tech_stack(technologies: Dict[str, List[str]]) -> str:
    """
    Format technology detection results
    
    Args:
        technologies: Dictionary of detected technologies by category
        
    Returns:
        Formatted tech stack message
    """
    total = sum(len(techs) for techs in technologies.values())
    message = format_header(f"Technology Stack ({total} detected)", emoji='💻')
    
    category_emojis = {
        'cms': '📦',
        'frameworks': '🎨',
        'programming_languages': '⚙️',
        'web_servers': '🖥️',
        'databases': '🗄️',
        'analytics': '📊',
        'cdn': '☁️',
        'waf': '🛡️',
        'js_libraries': '📚',
    }
    
    for category, techs in technologies.items():
        if techs:
            emoji = category_emojis.get(category, '📌')
            title = category.replace('_', ' ').title()
            message += f"\n{emoji} **{title}**\n"
            message += format_list(techs, max_items=5) + "\n"
    
    return message


def format_security_report(security_data: Dict[str, Any]) -> str:
    """
    Format security analysis results
    
    Args:
        security_data: Security scan results
        
    Returns:
        Formatted security message
    """
    score = security_data.get('score', 0)
    message = format_header("Security Analysis", emoji='🔐')
    
    message += f"\n**Overall Score:** {format_risk_score(score)}\n\n"
    
    # SSL/TLS
    if 'ssl' in security_data:
        ssl = security_data['ssl']
        message += "**SSL/TLS:**\n"
        message += f"├─ Grade: {ssl.get('grade', 'N/A')}\n"
        message += f"├─ Valid: {config.EMOJI['success'] if ssl.get('valid') else config.EMOJI['error']}\n"
        message += f"└─ Expires: {ssl.get('expires_in_days', 'N/A')} days\n\n"
    
    # Security Headers
    if 'headers' in security_data:
        headers = security_data['headers']
        message += "**Security Headers:**\n"
        for header, enabled in headers.items():
            emoji = config.EMOJI['success'] if enabled else config.EMOJI['error']
            message += f"├─ {emoji} {header}\n"
        message += "\n"
    
    # Vulnerabilities
    if 'vulnerabilities' in security_data:
        vulns = security_data['vulnerabilities']
        if vulns:
            message += f"**Vulnerabilities Found:** {len(vulns)}\n"
            for vuln in vulns[:5]:
                severity = vuln.get('severity', 'unknown').upper()
                vuln_type = vuln.get('type', 'Unknown')
                message += f"├─ {severity}: {vuln_type}\n"
            message += "\n"
    
    return message


def format_social_media(social_data: Dict[str, Dict[str, Any]]) -> str:
    """
    Format social media detection results
    
    Args:
        social_data: Social media profiles found
        
    Returns:
        Formatted social media message
    """
    message = format_header("Social Media Footprint", emoji='📱')
    
    platform_emojis = {
        'instagram': '📸',
        'twitter': '🐦',
        'linkedin': '💼',
        'github': '⚙️',
        'facebook': '📘',
        'youtube': '▶️',
        'tiktok': '🎵',
    }
    
    for platform, data in social_data.items():
        if data:
            emoji = platform_emojis.get(platform, '🌐')
            message += f"\n{emoji} **{platform.title()}:** @{data.get('username', 'N/A')}\n"
            
            if 'followers' in data:
                followers = data['followers']
                if followers >= 1000:
                    followers_str = f"{followers/1000:.1f}K"
                else:
                    followers_str = str(followers)
                message += f"├─ Followers: {followers_str}\n"
            
            if 'verified' in data and data['verified']:
                message += f"├─ Verified: {config.EMOJI['success']}\n"
            
            if 'url' in data:
                message += f"└─ {data['url']}\n"
            message += "\n"
    
    return message


def format_ip_intelligence(ip_data: Dict[str, Any]) -> str:
    """
    Format IP intelligence results
    
    Args:
        ip_data: IP information
        
    Returns:
        Formatted IP intelligence message
    """
    message = format_header("IP Intelligence", emoji='🌍')
    
    message += f"**IP Address:** `{ip_data.get('ip', 'N/A')}`\n\n"
    
    if 'geo' in ip_data:
        geo = ip_data['geo']
        message += "**Geolocation:**\n"
        message += f"├─ Country: {geo.get('country', 'N/A')} {geo.get('flag', '')}\n"
        message += f"├─ Region: {geo.get('region', 'N/A')}\n"
        message += f"└─ City: {geo.get('city', 'N/A')}\n\n"
    
    if 'asn' in ip_data:
        asn = ip_data['asn']
        message += "**Network:**\n"
        message += f"├─ ASN: {asn.get('number', 'N/A')}\n"
        message += f"└─ Organization: {asn.get('name', 'N/A')}\n\n"
    
    if 'cloud_provider' in ip_data:
        message += f"**Hosting:** {ip_data['cloud_provider']}\n\n"
    
    return message


def format_quick_summary(domain: str, results: Dict[str, Any]) -> str:
    """
    Format quick scan summary
    
    Args:
        domain: Domain name
        results: Scan results
        
    Returns:
        Formatted summary message
    """
    separator = "━" * 30
    
    message = f"⚡ **QUICK SCAN RESULTS**\n{separator}\n\n"
    message += f"🌐 **{domain}**\n\n"
    
    # Status
    status = results.get('status', {})
    if status.get('online'):
        message += f"{config.EMOJI['success']} Online | "
        message += f"{status.get('response_time', 'N/A')}ms | "
        message += f"{'HTTPS' if status.get('https') else 'HTTP'}\n\n"
    else:
        message += f"{config.EMOJI['error']} Offline or unreachable\n\n"
    
    # Quick stats
    if 'subdomains_count' in results:
        message += f"📡 Subdomains: {results['subdomains_count']}\n"
    
    if 'technologies_count' in results:
        message += f"💻 Technologies: {results['technologies_count']}\n"
    
    if 'security_score' in results:
        message += f"🔐 Security: {format_risk_score(results['security_score'])}\n"
    
    message += f"\n{separator}\n"
    message += f"⏱️ Completed in {results.get('scan_time', 'N/A')}s\n"
    
    return message


def format_error_message(error_type: str, message: str, suggestion: Optional[str] = None) -> str:
    """
    Format error message
    
    Args:
        error_type: Type of error
        message: Error message
        suggestion: Optional suggestion for user
        
    Returns:
        Formatted error message
    """
    msg = f"{config.EMOJI['error']} **{error_type}**\n\n"
    msg += f"{message}\n"
    
    if suggestion:
        msg += f"\n💡 {suggestion}"
    
    return msg


def format_warning_message(warning: str, details: Optional[str] = None) -> str:
    """
    Format warning message
    
    Args:
        warning: Warning text
        details: Optional details
        
    Returns:
        Formatted warning message
    """
    msg = f"{config.EMOJI['warning']} **Warning**\n\n"
    msg += f"{warning}\n"
    
    if details:
        msg += f"\n{details}"
    
    return msg


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_number(num: int) -> str:
    """
    Format large numbers with K/M suffixes
    
    Args:
        num: Number to format
        
    Returns:
        Formatted number string
    """
    if num >= 1_000_000:
        return f"{num/1_000_000:.1f}M"
    elif num >= 1_000:
        return f"{num/1_000:.1f}K"
    else:
        return str(num)


def create_button_row(buttons: List[tuple]) -> str:
    """
    Create inline button hints for messages
    
    Args:
        buttons: List of (label, command) tuples
        
    Returns:
        Button hint string
    """
    return " | ".join([f"[{label}]" for label, _ in buttons])
