"""
IP intelligence and geolocation module
"""

import asyncio
import aiohttp
import socket
from typing import Dict, List, Optional, Any
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class IPIntelligence:
    """
    IP geolocation, ASN lookup, and reputation checking
    """
    
    def __init__(self, timeout: int = config.HTTP_TIMEOUT):
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Complete IP intelligence analysis
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with IP intelligence
        """
        if not self.session:
            async with self:
                return await self.analyze(domain)
        
        results = {
            'domain': domain,
            'ip': None,
            'ipv6': None,
            'geolocation': None,
            'asn': None,
            'hosting': None,
            'cloud_provider': None,
            'reverse_dns': None,
            'reverse_ip': [],
            'is_cdn': False,
            'is_cloud': False,
            'error': None
        }
        
        try:
            # Resolve domain to IP
            results['ip'] = await self._resolve_domain(domain)
            
            if not results['ip']:
                results['error'] = "Failed to resolve domain to IP"
                return results
            
            # Get geolocation data
            geo_data = await self._get_geolocation(results['ip'])
            if geo_data:
                results['geolocation'] = geo_data.get('geo')
                results['asn'] = geo_data.get('asn')
                results['hosting'] = geo_data.get('isp')
            
            # Detect cloud provider
            results['cloud_provider'] = self._detect_cloud_provider(results)
            results['is_cloud'] = results['cloud_provider'] is not None
            
            # Check if CDN
            results['is_cdn'] = self._detect_cdn(results)
            
            # Reverse DNS lookup
            results['reverse_dns'] = await self._reverse_dns(results['ip'])
            
            # Reverse IP lookup (other domains on same IP)
            results['reverse_ip'] = await self._reverse_ip_lookup(results['ip'])
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IPv4 address"""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyname(domain)
            )
            return ip
        except:
            return None
    
    async def _get_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation data from ip-api.com (free, 45 req/min)
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with geolocation data
        """
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('status') == 'success':
                        return {
                            'geo': {
                                'country': data.get('country'),
                                'country_code': data.get('countryCode'),
                                'region': data.get('regionName'),
                                'city': data.get('city'),
                                'lat': data.get('lat'),
                                'lon': data.get('lon'),
                                'timezone': data.get('timezone'),
                                'zip': data.get('zip')
                            },
                            'asn': {
                                'number': data.get('as', '').split()[0] if data.get('as') else None,
                                'name': data.get('asname'),
                                'org': data.get('org')
                            },
                            'isp': data.get('isp')
                        }
        except:
            pass
        
        return None
    
    def _detect_cloud_provider(self, ip_data: Dict[str, Any]) -> Optional[str]:
        """
        Detect cloud provider based on ASN and ISP info
        
        Args:
            ip_data: IP intelligence data
            
        Returns:
            Cloud provider name or None
        """
        asn = ip_data.get('asn', {})
        isp = ip_data.get('hosting', '').lower() if ip_data.get('hosting') else ''
        asn_name = asn.get('name', '').lower() if asn else ''
        asn_org = asn.get('org', '').lower() if asn else ''
        
        # Check for major cloud providers
        cloud_providers = {
            'AWS': ['amazon', 'aws', 'ec2'],
            'Google Cloud': ['google cloud', 'gcp', 'google llc'],
            'Microsoft Azure': ['microsoft azure', 'azure', 'microsoft corporation'],
            'Cloudflare': ['cloudflare'],
            'DigitalOcean': ['digitalocean'],
            'Linode': ['linode'],
            'Vultr': ['vultr'],
            'Hetzner': ['hetzner'],
            'OVH': ['ovh'],
            'Alibaba Cloud': ['alibaba', 'aliyun'],
            'Oracle Cloud': ['oracle'],
            'IBM Cloud': ['ibm', 'softlayer'],
        }
        
        search_text = f"{isp} {asn_name} {asn_org}"
        
        for provider, keywords in cloud_providers.items():
            if any(keyword in search_text for keyword in keywords):
                return provider
        
        return None
    
    def _detect_cdn(self, ip_data: Dict[str, Any]) -> bool:
        """
        Detect if IP belongs to a CDN
        
        Args:
            ip_data: IP intelligence data
            
        Returns:
            True if CDN detected
        """
        asn = ip_data.get('asn', {})
        isp = ip_data.get('hosting', '').lower() if ip_data.get('hosting') else ''
        asn_name = asn.get('name', '').lower() if asn else ''
        
        cdn_keywords = [
            'cloudflare', 'akamai', 'fastly', 'cloudfront', 'cdn77',
            'stackpath', 'bunny', 'keycdn', 'maxcdn', 'imperva'
        ]
        
        search_text = f"{isp} {asn_name}"
        
        return any(keyword in search_text for keyword in cdn_keywords)
    
    async def _reverse_dns(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None
        """
        try:
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip)[0]
            )
            return hostname
        except:
            return None
    
    async def _reverse_ip_lookup(self, ip: str) -> List[str]:
        """
        Find other domains hosted on the same IP (using HackerTarget)
        
        Args:
            ip: IP address
            
        Returns:
            List of domains on same IP
        """
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        domains = []
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # Parse response
                    if 'error' not in text.lower():
                        domains = [line.strip() for line in text.split('\n') if line.strip()]
                        # Limit to 20 domains
                        domains = domains[:20]
        except:
            pass
        
        return domains
    
    async def check_blacklists(self, ip: str) -> Dict[str, Any]:
        """
        Check if IP is on common blacklists
        
        Args:
            ip: IP address to check
            
        Returns:
            Blacklist check results
        """
        results = {
            'ip': ip,
            'blacklisted': False,
            'blacklists': [],
            'checked': 0,
            'listed': 0
        }
        
        # Common DNS blacklists (RBLs)
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            'dnsbl.sorbs.net',
            'spam.dnsbl.sorbs.net'
        ]
        
        # Reverse IP for DNSBL lookup
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        tasks = []
        for bl in blacklists:
            query = f"{reversed_ip}.{bl}"
            tasks.append(self._check_dnsbl(query, bl))
        
        bl_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        results['checked'] = len(blacklists)
        
        for bl_name, is_listed in zip(blacklists, bl_results):
            if not isinstance(is_listed, Exception) and is_listed:
                results['listed'] += 1
                results['blacklists'].append(bl_name)
        
        results['blacklisted'] = results['listed'] > 0
        
        return results
    
    async def _check_dnsbl(self, query: str, bl_name: str) -> bool:
        """Check if domain exists in DNSBL"""
        try:
            loop = asyncio.get_event_loop()
            # Add timeout to prevent hanging
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.gethostbyname(query)
                ),
                timeout=3  # 3 second timeout
            )
            return True  # Listed if resolves
        except (socket.gaierror, asyncio.TimeoutError):
            return False  # Not listed if doesn't resolve or timeout
    
    async def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Get comprehensive IP reputation score
        
        Args:
            ip: IP address
            
        Returns:
            Reputation data
        """
        reputation = {
            'ip': ip,
            'score': 100,  # Start with perfect score
            'risk_level': 'Low',
            'factors': []
        }
        
        # Check blacklists
        blacklist_results = await self.check_blacklists(ip)
        
        if blacklist_results['blacklisted']:
            reputation['score'] -= 30
            reputation['factors'].append(
                f"Listed on {blacklist_results['listed']} blacklist(s)"
            )
        
        # Get IP info
        ip_info = await self.analyze(ip)
        
        # Check if residential vs datacenter
        if ip_info.get('is_cloud'):
            reputation['factors'].append(f"Cloud hosting ({ip_info.get('cloud_provider')})")
        
        if ip_info.get('is_cdn'):
            reputation['factors'].append("CDN detected")
        
        # Determine risk level
        if reputation['score'] >= 80:
            reputation['risk_level'] = 'Low'
        elif reputation['score'] >= 60:
            reputation['risk_level'] = 'Medium'
        elif reputation['score'] >= 40:
            reputation['risk_level'] = 'High'
        else:
            reputation['risk_level'] = 'Critical'
        
        return reputation
