"""
Multi-source subdomain enumeration module
"""

import asyncio
import aiohttp
import dns.resolver
import sys
import os
from typing import Dict, List, Set, Optional, Any
from urllib.parse import quote

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.validators import normalize_subdomain


class SubdomainHunter:
    """
    Advanced subdomain enumeration using multiple sources
    """
    
    def __init__(self, timeout: int = config.HTTP_TIMEOUT):
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.DNS_TIMEOUT
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def hunt(self, domain: str, mode: str = 'full', validate: bool = True) -> Dict[str, Any]:
        """
        Hunt for subdomains using multiple sources
        
        Args:
            domain: Target domain
            mode: 'basic' (top 100) or 'full' (up to 500)
            validate: Whether to validate and check if subdomains are alive
            
        Returns:
            Dictionary with subdomain results
        """
        if not self.session:
            async with self:
                return await self.hunt(domain, mode, validate)
        
        results = {
            'domain': domain,
            'total': 0,
            'alive': 0,
            'subdomains': [],
            'categorized': {
                'production': [],
                'staging': [],
                'dev': [],
                'dead': []
            },
            'sources': {},
            'errors': []
        }
        
        # Gather subdomains from all sources
        sources = [
            self._query_crtsh(domain),
            self._query_hackertarget(domain),
            self._query_threatcrowd(domain),
        ]
        
        source_results = await asyncio.gather(*sources, return_exceptions=True)
        
        # Combine results
        all_subdomains: Set[str] = set()
        
        source_names = ['crt.sh', 'HackerTarget', 'ThreatCrowd']
        for source_name, result in zip(source_names, source_results):
            if isinstance(result, Exception):
                results['errors'].append(f"{source_name}: {str(result)}")
                results['sources'][source_name] = 0
            else:
                all_subdomains.update(result)
                results['sources'][source_name] = len(result)
        
        # Normalize and clean subdomains
        clean_subdomains = set()
        for sub in all_subdomains:
            normalized = normalize_subdomain(sub)
            if normalized and '*' not in normalized:
                clean_subdomains.add(normalized)
        
        # Limit based on mode
        max_subs = 100 if mode == 'basic' else config.MAX_SUBDOMAINS
        subdomains_list = sorted(list(clean_subdomains))[:max_subs]
        
        results['total'] = len(subdomains_list)
        results['subdomains'] = subdomains_list
        
        # Validate and check if alive (if requested)
        if validate and subdomains_list:
            validated = await self._validate_subdomains(subdomains_list, check_alive=(mode == 'full'))
            results.update(validated)
        
        return results
    
    async def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh certificate transparency logs"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError):
                        # crt.sh sometimes returns HTML when rate limited
                        raise Exception("crt.sh returned non-JSON response (possibly rate limited)")
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        
                        # Handle multiple names in one entry
                        if '\n' in name_value:
                            subdomains.update(name_value.split('\n'))
                        else:
                            subdomains.add(name_value)
        except Exception as e:
            raise Exception(f"crt.sh query failed: {str(e)}")
        
        return subdomains
    
    async def _query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API"""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subdomains = set()
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # Parse response (format: subdomain,ip)
                    for line in text.strip().split('\n'):
                        if ',' in line:
                            subdomain = line.split(',')[0].strip()
                            subdomains.add(subdomain)
        except Exception as e:
            raise Exception(f"HackerTarget query failed: {str(e)}")
        
        return subdomains
    
    async def _query_threatcrowd(self, domain: str) -> Set[str]:
        """Query ThreatCrowd API"""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        subdomains = set()
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('response_code') == '1':
                        subs = data.get('subdomains', [])
                        subdomains.update(subs)
        except Exception as e:
            raise Exception(f"ThreatCrowd query failed: {str(e)}")
        
        return subdomains
    
    async def _validate_subdomains(self, subdomains: List[str], check_alive: bool = True) -> Dict[str, Any]:
        """
        Validate subdomains (DNS resolution) and optionally check if alive
        
        Args:
            subdomains: List of subdomains to validate
            check_alive: Whether to check HTTP(S) responses
            
        Returns:
            Dictionary with validation results
        """
        results = {
            'alive': 0,
            'categorized': {
                'production': [],
                'staging': [],
                'dev': [],
                'dead': []
            }
        }
        
        # Validate DNS in batches
        batch_size = 10  # Reduced from 20 to avoid DNS rate limiting
        validated_subs = []
        
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            tasks = [self._check_dns(sub) for sub in batch]
            dns_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for subdomain, has_dns in zip(batch, dns_results):
                if has_dns and not isinstance(has_dns, Exception):
                    validated_subs.append(subdomain)
        
        # Check if alive (HTTP/HTTPS)
        if check_alive and validated_subs:
            alive_tasks = [self._check_alive(sub) for sub in validated_subs]
            alive_results = await asyncio.gather(*alive_tasks, return_exceptions=True)
            
            for subdomain, alive_info in zip(validated_subs, alive_results):
                if isinstance(alive_info, Exception) or not alive_info:
                    results['categorized']['dead'].append(subdomain)
                else:
                    results['alive'] += 1
                    
                    # Categorize based on subdomain name
                    sub_lower = subdomain.lower()
                    if any(x in sub_lower for x in ['staging', 'stage', 'stg']):
                        results['categorized']['staging'].append({
                            'subdomain': subdomain,
                            'status': alive_info.get('status'),
                            'https': alive_info.get('https')
                        })
                    elif any(x in sub_lower for x in ['dev', 'test', 'uat', 'qa']):
                        results['categorized']['dev'].append({
                            'subdomain': subdomain,
                            'status': alive_info.get('status'),
                            'https': alive_info.get('https')
                        })
                    else:
                        results['categorized']['production'].append({
                            'subdomain': subdomain,
                            'status': alive_info.get('status'),
                            'https': alive_info.get('https')
                        })
        else:
            # If not checking alive, put all validated in production
            results['categorized']['production'] = validated_subs
        
        return results
    
    async def _check_dns(self, subdomain: str) -> bool:
        """Check if subdomain resolves via DNS"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(subdomain, 'A')
            )
            return True
        except:
            return False
    
    async def _check_alive(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Check if subdomain responds to HTTP/HTTPS
        
        Returns:
            Dictionary with status info or None
        """
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            
            try:
                async with self.session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=True,
                    ssl=False  # Don't verify SSL for speed
                ) as response:
                    return {
                        'protocol': protocol,
                        'status': response.status,
                        'https': protocol == 'https'
                    }
            except:
                continue
        
        return None
    
    async def brute_force_common(self, domain: str) -> Set[str]:
        """
        Brute force common subdomain names
        
        Args:
            domain: Target domain
            
        Returns:
            Set of found subdomains
        """
        common_names = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'portal', 'blog',
            'api', 'dev', 'staging', 'stage', 'test', 'demo', 'beta', 'app', 'mobile',
            'shop', 'store', 'cdn', 'static', 'assets', 'media', 'images', 'img', 'news',
            'support', 'help', 'docs', 'documentation', 'wiki', 'forum', 'community',
            'm', 'secure', 'vpn', 'remote', 'cloud', 'dashboard', 'panel', 'manage',
        ]
        
        found = set()
        tasks = []
        
        for name in common_names:
            subdomain = f"{name}.{domain}"
            tasks.append(self._check_dns(subdomain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for name, exists in zip(common_names, results):
            if exists and not isinstance(exists, Exception):
                found.add(f"{name}.{domain}")
        
        return found
