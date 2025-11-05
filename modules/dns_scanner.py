"""
DNS scanning and analysis module
"""

import dns.resolver
import dns.reversename
import dns.dnssec
import asyncio
import sys
import os
from typing import Dict, List, Optional, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class DNSScanner:
    """
    Comprehensive DNS analysis scanner
    """
    
    def __init__(self, timeout: int = config.DNS_TIMEOUT):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    async def scan(self, domain: str, mode: str = 'full') -> Dict[str, Any]:
        """
        Perform DNS scan
        
        Args:
            domain: Domain to scan
            mode: Scan mode ('basic', 'full')
            
        Returns:
            Dictionary with DNS results
        """
        results = {
            'domain': domain,
            'records': {},
            'nameservers': [],
            'dnssec': None,
            'spf': None,
            'dmarc': None,
            'errors': []
        }
        
        # Determine which record types to query
        if mode == 'basic':
            record_types = ['A', 'AAAA', 'MX', 'NS']
        else:
            record_types = config.DNS_RECORD_TYPES
        
        # Query all record types concurrently
        tasks = []
        for record_type in record_types:
            tasks.append(self._query_record(domain, record_type))
        
        records = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for record_type, result in zip(record_types, records):
            if isinstance(result, Exception):
                results['errors'].append(f"{record_type}: {str(result)}")
            elif result:
                results['records'][record_type] = result
        
        # Parse special records
        if 'TXT' in results['records']:
            txt_records = results['records']['TXT']
            results['spf'] = self._parse_spf(txt_records)
            results['dmarc'] = await self._get_dmarc(domain)
        
        if 'NS' in results['records']:
            results['nameservers'] = results['records']['NS']
        
        # Check DNSSEC (only in full mode)
        if mode == 'full':
            results['dnssec'] = await self._check_dnssec(domain)
        
        return results
    
    async def _query_record(self, domain: str, record_type: str) -> Optional[List[str]]:
        """Query a specific DNS record type"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, record_type)
            )
            
            results = []
            for rdata in answers:
                if record_type == 'MX':
                    results.append({
                        'priority': rdata.preference,
                        'host': str(rdata.exchange).rstrip('.')
                    })
                elif record_type == 'SOA':
                    results.append({
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    })
                elif record_type == 'TXT':
                    # Join TXT record parts
                    txt_value = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                    results.append(txt_value)
                else:
                    results.append(str(rdata).rstrip('.'))
            
            return results if results else None
            
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            raise Exception(f"Timeout querying {record_type}")
        except Exception as e:
            raise Exception(f"Error: {str(e)}")
    
    def _parse_spf(self, txt_records: List[str]) -> Optional[Dict[str, Any]]:
        """Parse SPF record from TXT records"""
        for record in txt_records:
            if record.startswith('v=spf1'):
                spf_data = {
                    'record': record,
                    'mechanisms': [],
                    'includes': [],
                    'all': None
                }
                
                parts = record.split()
                for part in parts[1:]:  # Skip 'v=spf1'
                    if part.startswith('include:'):
                        spf_data['includes'].append(part.split(':')[1])
                    elif part in ['+all', '-all', '~all', '?all']:
                        spf_data['all'] = part
                    else:
                        spf_data['mechanisms'].append(part)
                
                return spf_data
        
        return None
    
    async def _get_dmarc(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DMARC record"""
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            txt_records = await self._query_record(dmarc_domain, 'TXT')
            if txt_records:
                for record in txt_records:
                    if record.startswith('v=DMARC1'):
                        dmarc_data = {
                            'record': record,
                            'policy': None,
                            'subdomain_policy': None,
                            'percentage': 100,
                            'rua': [],
                            'ruf': []
                        }
                        
                        # Parse DMARC tags
                        tags = record.split(';')
                        for tag in tags:
                            tag = tag.strip()
                            if tag.startswith('p='):
                                dmarc_data['policy'] = tag.split('=')[1]
                            elif tag.startswith('sp='):
                                dmarc_data['subdomain_policy'] = tag.split('=')[1]
                            elif tag.startswith('pct='):
                                dmarc_data['percentage'] = int(tag.split('=')[1])
                            elif tag.startswith('rua='):
                                dmarc_data['rua'] = tag.split('=')[1].split(',')
                            elif tag.startswith('ruf='):
                                dmarc_data['ruf'] = tag.split('=')[1].split(',')
                        
                        return dmarc_data
        except:
            pass
        
        return None
    
    async def _check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check if DNSSEC is enabled"""
        result = {
            'enabled': False,
            'has_dnskey': False,
            'error': None
        }
        
        try:
            loop = asyncio.get_event_loop()
            
            # Try to get DNSKEY record
            dnskey = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, 'DNSKEY')
            )
            
            result['enabled'] = len(dnskey) > 0
            result['has_dnskey'] = len(dnskey) > 0
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def check_propagation(self, domain: str, nameservers: List[str] = None) -> Dict[str, Any]:
        """
        Check DNS propagation across multiple nameservers
        
        Args:
            domain: Domain to check
            nameservers: List of nameserver IPs (default: major public DNS)
            
        Returns:
            Dictionary with propagation results
        """
        if not nameservers:
            nameservers = [
                ('8.8.8.8', 'Google'),
                ('1.1.1.1', 'Cloudflare'),
                ('208.67.222.222', 'OpenDNS'),
                ('9.9.9.9', 'Quad9'),
            ]
        
        results = {}
        
        for ns, name in nameservers:
            try:
                custom_resolver = dns.resolver.Resolver()
                custom_resolver.nameservers = [ns]
                custom_resolver.timeout = self.timeout
                custom_resolver.lifetime = self.timeout
                
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None,
                    lambda: custom_resolver.resolve(domain, 'A')
                )
                
                ips = [str(rdata) for rdata in answers]
                results[name] = {
                    'nameserver': ns,
                    'resolved': True,
                    'ips': ips
                }
                
            except Exception as e:
                results[name] = {
                    'nameserver': ns,
                    'resolved': False,
                    'error': str(e)
                }
        
        # Check if all nameservers agree
        all_ips = set()
        for result in results.values():
            if result.get('resolved'):
                all_ips.update(result.get('ips', []))
        
        consistent = len(set(tuple(r.get('ips', [])) for r in results.values() if r.get('resolved'))) <= 1
        
        return {
            'nameservers': results,
            'consistent': consistent,
            'unique_ips': list(all_ips)
        }
    
    async def reverse_dns(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None
        """
        try:
            loop = asyncio.get_event_loop()
            addr = dns.reversename.from_address(ip)
            
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(addr, 'PTR')
            )
            
            if answers:
                return str(answers[0]).rstrip('.')
                
        except:
            pass
        
        return None
