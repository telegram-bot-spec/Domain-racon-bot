"""
Enhanced WHOIS lookup module with additional analysis
"""

import whois
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class WhoisScanner:
    """
    Enhanced WHOIS scanner with domain age calculation and analysis
    """
    
    def __init__(self, timeout: int = config.WHOIS_TIMEOUT):
        self.timeout = timeout
    
    async def scan(self, domain: str) -> Dict[str, Any]:
        """
        Perform enhanced WHOIS lookup
        
        Args:
            domain: Domain to lookup
            
        Returns:
            Dictionary with WHOIS information
        """
        results = {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'age_days': None,
            'age_human': None,
            'nameservers': [],
            'status': [],
            'registrant': None,
            'admin': None,
            'tech': None,
            'is_new_domain': False,
            'expires_soon': False,
            'privacy_protected': False,
            'error': None
        }
        
        try:
            # Run WHOIS lookup in executor (blocking operation)
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, lambda: whois.whois(domain))
            
            # Extract registrar
            if hasattr(w, 'registrar') and w.registrar:
                results['registrar'] = w.registrar
            
            # Extract dates
            results['creation_date'] = self._parse_date(w.creation_date)
            results['expiration_date'] = self._parse_date(w.expiration_date)
            results['updated_date'] = self._parse_date(w.updated_date)
            
            # Calculate domain age
            if results['creation_date']:
                age = datetime.now() - results['creation_date']
                results['age_days'] = age.days
                results['age_human'] = self._format_age(age.days)
                
                # Check if domain is newly registered (< 30 days)
                results['is_new_domain'] = age.days < 30
            
            # Check if expires soon (< 30 days)
            if results['expiration_date']:
                days_until_expiry = (results['expiration_date'] - datetime.now()).days
                results['expires_soon'] = days_until_expiry < 30
                results['days_until_expiry'] = days_until_expiry
            
            # Extract nameservers
            if hasattr(w, 'name_servers') and w.name_servers:
                if isinstance(w.name_servers, list):
                    results['nameservers'] = [ns.lower() for ns in w.name_servers if ns]
                else:
                    results['nameservers'] = [str(w.name_servers).lower()]
            
            # Extract status
            if hasattr(w, 'status') and w.status:
                if isinstance(w.status, list):
                    results['status'] = w.status
                else:
                    results['status'] = [w.status]
            
            # Extract contact info (if not redacted)
            results['registrant'] = self._extract_contact(w, 'registrant')
            results['admin'] = self._extract_contact(w, 'admin')
            results['tech'] = self._extract_contact(w, 'tech')
            
            # Check for privacy protection
            results['privacy_protected'] = self._check_privacy_protection(w, results)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _parse_date(self, date_value) -> Optional[datetime]:
        """Parse WHOIS date (can be datetime, list, or string)"""
        if not date_value:
            return None
        
        # If it's a list, take the first element
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        # If it's already a datetime, return it
        if isinstance(date_value, datetime):
            return date_value
        
        # Try to parse string with multiple formats
        if isinstance(date_value, str):
            # Common WHOIS date formats
            date_formats = [
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S',
                '%d-%b-%Y',
                '%d.%m.%Y',
                '%Y/%m/%d',
            ]
            
            for fmt in date_formats:
                try:
                    return datetime.strptime(date_value, fmt)
                except ValueError:
                    continue
        
        return None
    
    def _format_age(self, days: int) -> str:
        """Format domain age in human-readable format"""
        years = days // 365
        remaining_days = days % 365
        months = remaining_days // 30
        
        parts = []
        if years > 0:
            parts.append(f"{years} year{'s' if years != 1 else ''}")
        if months > 0:
            parts.append(f"{months} month{'s' if months != 1 else ''}")
        
        if not parts:
            return f"{days} days"
        
        return ", ".join(parts)
    
    def _extract_contact(self, w, contact_type: str) -> Optional[Dict[str, str]]:
        """Extract contact information (registrant, admin, tech)"""
        contact = {}
        
        # Try different attribute names
        attrs = {
            'name': [f'{contact_type}_name', 'name'],
            'org': [f'{contact_type}_org', 'org', 'organization'],
            'email': [f'{contact_type}_email', 'email', 'emails'],
            'country': [f'{contact_type}_country', 'country'],
        }
        
        for key, possible_attrs in attrs.items():
            for attr in possible_attrs:
                if hasattr(w, attr):
                    value = getattr(w, attr)
                    if value and value != 'REDACTED FOR PRIVACY':
                        if isinstance(value, list):
                            value = value[0] if value else None
                        if value:
                            contact[key] = str(value)
                            break
        
        return contact if contact else None
    
    def _check_privacy_protection(self, w, results: Dict) -> bool:
        """Check if domain uses privacy protection"""
        # Check for common privacy protection indicators
        privacy_indicators = [
            'privacy', 'protected', 'redacted', 'private', 'proxy',
            'whoisguard', 'domains by proxy', 'contact privacy'
        ]
        
        # Check registrant info
        if results['registrant']:
            registrant_str = str(results['registrant']).lower()
            if any(indicator in registrant_str for indicator in privacy_indicators):
                return True
        
        # Check registrar
        if results['registrar']:
            registrar_str = results['registrar'].lower()
            if any(indicator in registrar_str for indicator in privacy_indicators):
                return True
        
        # Check if all contact info is None/redacted
        if not results['registrant'] and not results['admin'] and not results['tech']:
            return True
        
        return False
    
    async def check_availability(self, domain: str) -> Dict[str, Any]:
        """
        Quick check if domain is available for registration
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with availability info
        """
        result = {
            'domain': domain,
            'available': False,
            'registered': False,
            'error': None
        }
        
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, lambda: whois.whois(domain))
            
            # If WHOIS data exists, domain is registered
            if w and (w.creation_date or w.registrar):
                result['registered'] = True
                result['available'] = False
            else:
                result['available'] = True
                
        except Exception as e:
            error_msg = str(e).lower()
            
            # Check for "no match" or "not found" in error
            if any(x in error_msg for x in ['no match', 'not found', 'no entries']):
                result['available'] = True
            else:
                result['error'] = str(e)
        
        return result
    
    def analyze_domain_trust(self, whois_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze domain trustworthiness based on WHOIS data
        
        Args:
            whois_data: WHOIS scan results
            
        Returns:
            Trust analysis
        """
        trust_score = 100  # Start with perfect score
        flags = []
        
        # New domain flag (potentially suspicious)
        if whois_data.get('is_new_domain'):
            trust_score -= 20
            flags.append('Domain registered recently (< 30 days)')
        
        # Very old domain (usually trustworthy)
        if whois_data.get('age_days') and whois_data['age_days'] > 3650:  # 10+ years
            trust_score = min(100, trust_score + 10)
            flags.append('Well-established domain (10+ years old)')
        
        # Expires soon (potentially abandoned)
        if whois_data.get('expires_soon'):
            trust_score -= 10
            flags.append('Domain expires soon')
        
        # Privacy protection (neutral, but worth noting)
        if whois_data.get('privacy_protected'):
            flags.append('Privacy protection enabled')
        
        # No registrar info (suspicious)
        if not whois_data.get('registrar'):
            trust_score -= 15
            flags.append('Missing registrar information')
        
        # Determine trust level
        if trust_score >= 80:
            trust_level = 'High'
        elif trust_score >= 60:
            trust_level = 'Medium'
        elif trust_score >= 40:
            trust_level = 'Low'
        else:
            trust_level = 'Very Low'
        
        return {
            'trust_score': trust_score,
            'trust_level': trust_level,
            'flags': flags
        }
