"""
Async port scanner with service detection and banner grabbing
"""

import asyncio
import socket
from typing import Dict, List, Optional, Any, Tuple
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class PortScanner:
    """
    Advanced async port scanner with service detection
    """
    
    def __init__(self, timeout: float = config.PORT_SCAN_TIMEOUT, parallel: int = config.PARALLEL_PORT_SCANS):
        self.timeout = timeout
        self.parallel = parallel
    
    async def scan(self, domain: str, ports: Optional[List[int]] = None, mode: str = 'quick') -> Dict[str, Any]:
        """
        Scan ports on target domain
        
        Args:
            domain: Target domain or IP
            ports: List of ports to scan (None = use defaults)
            mode: 'quick' (top 20), 'full' (100 ports), 'custom' (user defined)
            
        Returns:
            Dictionary with scan results
        """
        results = {
            'domain': domain,
            'ip': None,
            'total_scanned': 0,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'categorized': {},
            'critical_findings': [],
            'error': None
        }
        
        try:
            # Resolve domain to IP
            results['ip'] = await self._resolve_domain(domain)
            
            if not results['ip']:
                results['error'] = "Failed to resolve domain to IP"
                return results
            
            # Determine which ports to scan
            if ports is None:
                if mode == 'quick':
                    ports = list(config.COMMON_PORTS.keys())[:20]
                elif mode == 'full':
                    ports = list(config.COMMON_PORTS.keys())[:100]
                else:  # custom or default
                    ports = list(config.COMMON_PORTS.keys())
            
            results['total_scanned'] = len(ports)
            
            # Scan ports in parallel batches
            open_ports = []
            
            for i in range(0, len(ports), self.parallel):
                batch = ports[i:i + self.parallel]
                batch_results = await asyncio.gather(
                    *[self._scan_port(results['ip'], port) for port in batch],
                    return_exceptions=True
                )
                
                for port, is_open in zip(batch, batch_results):
                    if isinstance(is_open, Exception):
                        results['filtered_ports'].append(port)
                    elif is_open:
                        open_ports.append(port)
                    else:
                        results['closed_ports'].append(port)
            
            # Get detailed info for open ports
            if open_ports:
                port_details = await asyncio.gather(
                    *[self._get_port_details(results['ip'], port) for port in open_ports],
                    return_exceptions=True
                )
                
                for port, details in zip(open_ports, port_details):
                    if not isinstance(details, Exception):
                        results['open_ports'].append(details)
                    else:
                        # Add basic info if detailed scan failed
                        results['open_ports'].append({
                            'port': port,
                            'service': config.COMMON_PORTS.get(port, 'Unknown'),
                            'state': 'open'
                        })
            
            # Categorize open ports
            results['categorized'] = self._categorize_ports(results['open_ports'])
            
            # Identify critical security findings
            results['critical_findings'] = self._identify_critical_findings(results['open_ports'])
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyname(domain)
            )
            return ip
        except:
            return None
    
    async def _scan_port(self, ip: str, port: int) -> bool:
        """
        Check if a port is open
        
        Args:
            ip: Target IP
            port: Port number
            
        Returns:
            True if open, False if closed
        """
        try:
            # Create connection with timeout
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except asyncio.TimeoutError:
            return False
        except ConnectionRefusedError:
            return False
        except:
            return False
    
    async def _get_port_details(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Get detailed information about an open port
        
        Args:
            ip: Target IP
            port: Port number
            
        Returns:
            Dictionary with port details
        """
        details = {
            'port': port,
            'service': config.COMMON_PORTS.get(port, 'Unknown'),
            'state': 'open',
            'banner': None,
            'version': None,
            'protocol': 'tcp'
        }
        
        # Try to grab banner
        banner = await self._grab_banner(ip, port)
        if banner:
            details['banner'] = banner
            
            # Try to identify service and version from banner
            service_info = self._parse_banner(banner, port)
            if service_info:
                details.update(service_info)
        
        return details
    
    async def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """
        Grab service banner
        
        Args:
            ip: Target IP
            port: Port number
            
        Returns:
            Banner string or None
        """
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2)
            
            # Try to read banner (some services send immediately)
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=1)
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                
                writer.close()
                await writer.wait_closed()
                
                if banner_str:
                    return banner_str
                    
            except asyncio.TimeoutError:
                # Some services need a request first
                # Try common probes
                probes = {
                    80: b'GET / HTTP/1.0\r\n\r\n',
                    443: b'GET / HTTP/1.0\r\n\r\n',
                    21: b'\r\n',
                    22: b'\r\n',
                    25: b'EHLO test\r\n',
                }
                
                if port in probes:
                    writer.write(probes[port])
                    await writer.drain()
                    
                    banner = await asyncio.wait_for(reader.read(1024), timeout=1)
                    banner_str = banner.decode('utf-8', errors='ignore').strip()
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    return banner_str if banner_str else None
            
        except:
            pass
        
        return None
    
    def _parse_banner(self, banner: str, port: int) -> Optional[Dict[str, str]]:
        """
        Parse banner to identify service and version
        
        Args:
            banner: Banner string
            port: Port number
            
        Returns:
            Dictionary with service info
        """
        banner_lower = banner.lower()
        
        # Common service signatures
        signatures = {
            'ssh': {
                'patterns': ['ssh', 'openssh'],
                'service': 'SSH',
                'version_regex': r'openssh[_-]?([\d.]+)'
            },
            'http': {
                'patterns': ['http', 'server:'],
                'service': 'HTTP',
                'version_regex': None
            },
            'ftp': {
                'patterns': ['ftp', 'filezilla', 'proftpd', 'vsftpd'],
                'service': 'FTP',
                'version_regex': r'([\d.]+)'
            },
            'smtp': {
                'patterns': ['smtp', 'postfix', 'exim', 'sendmail'],
                'service': 'SMTP',
                'version_regex': r'([\d.]+)'
            },
            'mysql': {
                'patterns': ['mysql'],
                'service': 'MySQL',
                'version_regex': r'([\d.]+)'
            },
            'postgresql': {
                'patterns': ['postgresql'],
                'service': 'PostgreSQL',
                'version_regex': r'([\d.]+)'
            },
            'redis': {
                'patterns': ['redis'],
                'service': 'Redis',
                'version_regex': r'redis_version:([\d.]+)'
            },
            'mongodb': {
                'patterns': ['mongodb'],
                'service': 'MongoDB',
                'version_regex': r'([\d.]+)'
            },
            'nginx': {
                'patterns': ['nginx'],
                'service': 'Nginx',
                'version_regex': r'nginx/([\d.]+)'
            },
            'apache': {
                'patterns': ['apache'],
                'service': 'Apache',
                'version_regex': r'apache/([\d.]+)'
            },
        }
        
        for sig_name, sig_data in signatures.items():
            if any(pattern in banner_lower for pattern in sig_data['patterns']):
                result = {'service': sig_data['service']}
                
                # Try to extract version
                if sig_data.get('version_regex'):
                    import re
                    match = re.search(sig_data['version_regex'], banner_lower)
                    if match:
                        result['version'] = match.group(1)
                
                return result
        
        return None
    
    def _categorize_ports(self, open_ports: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """
        Categorize open ports by service type
        
        Args:
            open_ports: List of open port dictionaries
            
        Returns:
            Categorized ports
        """
        categories = {
            'web': [],
            'database': [],
            'mail': [],
            'ssh': [],
            'ftp': [],
            'other': []
        }
        
        web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090]
        db_ports = [1433, 1521, 3306, 5432, 5984, 6379, 7474, 8529, 9042, 9200, 27017, 27018, 28017]
        mail_ports = [25, 110, 143, 465, 587, 993, 995]
        ssh_ports = [22, 2222]
        ftp_ports = [21, 69, 115]
        
        for port_info in open_ports:
            port = port_info['port']
            
            if port in web_ports:
                categories['web'].append(port_info)
            elif port in db_ports:
                categories['database'].append(port_info)
            elif port in mail_ports:
                categories['mail'].append(port_info)
            elif port in ssh_ports:
                categories['ssh'].append(port_info)
            elif port in ftp_ports:
                categories['ftp'].append(port_info)
            else:
                categories['other'].append(port_info)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _identify_critical_findings(self, open_ports: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Identify critical security findings
        
        Args:
            open_ports: List of open ports
            
        Returns:
            List of critical findings
        """
        findings = []
        
        # Critical exposed services
        dangerous_ports = {
            3306: ('MySQL', 'Database exposed to internet'),
            5432: ('PostgreSQL', 'Database exposed to internet'),
            1433: ('MS SQL Server', 'Database exposed to internet'),
            27017: ('MongoDB', 'Database exposed to internet'),
            6379: ('Redis', 'Redis exposed without authentication'),
            9200: ('Elasticsearch', 'Elasticsearch exposed to internet'),
            5984: ('CouchDB', 'CouchDB exposed to internet'),
            2375: ('Docker', 'Docker API exposed without TLS'),
            5900: ('VNC', 'VNC remote access exposed'),
            5901: ('VNC', 'VNC remote access exposed (alt port)'),
            3389: ('RDP', 'Remote Desktop exposed to internet'),
            23: ('Telnet', 'Insecure Telnet protocol enabled'),
            445: ('SMB', 'SMB file sharing exposed'),
            139: ('NetBIOS', 'NetBIOS exposed to internet'),
            21: ('FTP', 'FTP exposed (consider SFTP instead)'),
        }
        
        for port_info in open_ports:
            port = port_info['port']
            
            if port in dangerous_ports:
                service, description = dangerous_ports[port]
                findings.append({
                    'severity': 'Critical',
                    'port': port,
                    'service': service,
                    'issue': description,
                    'recommendation': f'Firewall port {port} or restrict access to trusted IPs only'
                })
            
            # Check for outdated/vulnerable versions
            version = port_info.get('version')
            service = port_info.get('service', '')
            
            if version and 'OpenSSH' in service:
                # Example: Check for old OpenSSH versions
                try:
                    # Handle versions like "8.9p1" by removing non-numeric suffixes
                    version_clean = version.split('p')[0].split('_')[0]
                    version_parts = version_clean.split('.')
                    
                    if len(version_parts) >= 2:
                        major, minor = int(version_parts[0]), int(version_parts[1])
                        if major < 7 or (major == 7 and minor < 4):
                            findings.append({
                                'severity': 'High',
                                'port': port,
                                'service': service,
                                'issue': f'Outdated OpenSSH version {version}',
                                'recommendation': 'Update OpenSSH to latest version'
                            })
                except (ValueError, IndexError):
                    # Skip version check if parsing fails
                    pass
        
        return findings
    
    async def scan_specific_port(self, domain: str, port: int) -> Dict[str, Any]:
        """
        Scan a specific port with detailed analysis
        
        Args:
            domain: Target domain
            port: Port to scan
            
        Returns:
            Detailed port information
        """
        result = {
            'domain': domain,
            'ip': None,
            'port': port,
            'state': 'closed',
            'error': None
        }
        
        try:
            # Resolve domain
            result['ip'] = await self._resolve_domain(domain)
            
            if not result['ip']:
                result['error'] = "Failed to resolve domain"
                return result
            
            # Scan port
            is_open = await self._scan_port(result['ip'], port)
            
            if is_open:
                result['state'] = 'open'
                details = await self._get_port_details(result['ip'], port)
                result.update(details)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
