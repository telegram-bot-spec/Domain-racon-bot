"""
Security analysis module - Headers, SSL, Cookies, Vulnerabilities
"""

import asyncio
import aiohttp
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class SecurityAnalyzer:
    """
    Comprehensive security analysis
    """
    
    def __init__(self, timeout: int = config.HTTP_TIMEOUT):
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def analyze(self, domain: str, mode: str = 'full') -> Dict[str, Any]:
        """
        Perform comprehensive security analysis
        
        Args:
            domain: Target domain
            mode: 'basic' or 'full'
            
        Returns:
            Dictionary with security analysis
        """
        if not self.session:
            async with self:
                return await self.analyze(domain, mode)
        
        # Ensure domain has protocol
        if not domain.startswith('http'):
            url = f"https://{domain}"
        else:
            url = domain
        
        results = {
            'url': url,
            'score': 0,
            'grade': 'F',
            'ssl': {},
            'headers': {},
            'cookies': {},
            'vulnerabilities': [],
            'recommendations': [],
            'error': None
        }
        
        try:
            # Fetch page with all security info
            async with self.session.get(url, ssl=False, allow_redirects=True) as response:
                headers = dict(response.headers)
                cookies = response.cookies
                final_url = str(response.url)
                
                results['final_url'] = final_url
                results['https'] = final_url.startswith('https://')
                
                # Analyze SSL/TLS
                if results['https']:
                    parsed = urlparse(final_url)
                    results['ssl'] = await self._analyze_ssl(parsed.netloc)
                
                # Analyze security headers
                results['headers'] = self._analyze_headers(headers)
                
                # Analyze cookies
                results['cookies'] = self._analyze_cookies(cookies)
                
                # Check for common vulnerabilities
                if mode == 'full':
                    results['vulnerabilities'] = await self._check_vulnerabilities(url, headers)
                
                # Calculate security score
                results['score'] = self._calculate_score(results)
                results['grade'] = self._calculate_grade(results['score'])
                
                # Generate recommendations
                results['recommendations'] = self._generate_recommendations(results)
                
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _analyze_ssl(self, hostname: str) -> Dict[str, Any]:
        """
        Analyze SSL/TLS configuration
        
        Args:
            hostname: Domain hostname
            
        Returns:
            SSL analysis results
        """
        ssl_info = {
            'enabled': False,
            'version': None,
            'cipher': None,
            'certificate': {},
            'grade': 'F',
            'issues': []
        }
        
        try:
            loop = asyncio.get_event_loop()
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to server
            def get_ssl_info():
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return cert, cipher, version
            
            cert, cipher, version = await loop.run_in_executor(None, get_ssl_info)
            
            ssl_info['enabled'] = True
            ssl_info['version'] = version
            ssl_info['cipher'] = {
                'name': cipher[0] if cipher else None,
                'protocol': cipher[1] if cipher else None,
                'bits': cipher[2] if cipher else None
            }
            
            # Parse certificate
            if cert:
                ssl_info['certificate'] = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'valid_from': cert.get('notBefore'),
                    'valid_until': cert.get('notAfter'),
                    'san': cert.get('subjectAltName', [])
                }
                
                # Check certificate validity
                try:
                    valid_until = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                    days_left = (valid_until - datetime.now()).days
                    ssl_info['certificate']['days_until_expiry'] = days_left
                    
                    if days_left < 0:
                        ssl_info['issues'].append('Certificate expired')
                    elif days_left < 30:
                        ssl_info['issues'].append(f'Certificate expires in {days_left} days')
                except:
                    pass
            
            # Grade SSL configuration
            if version == 'TLSv1.3':
                ssl_info['grade'] = 'A+'
            elif version == 'TLSv1.2':
                ssl_info['grade'] = 'A'
            elif version == 'TLSv1.1':
                ssl_info['grade'] = 'B'
                ssl_info['issues'].append('TLS 1.1 is deprecated')
            else:
                ssl_info['grade'] = 'C'
                ssl_info['issues'].append('Weak TLS version')
            
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze security headers
        
        Args:
            headers: HTTP headers
            
        Returns:
            Header analysis
        """
        header_analysis = {
            'score': 0,
            'total': 10,
            'present': [],
            'missing': [],
            'details': {}
        }
        
        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'name': 'HSTS',
                'description': 'Forces HTTPS connections',
                'severity': 'high'
            },
            'Content-Security-Policy': {
                'name': 'CSP',
                'description': 'Prevents XSS and injection attacks',
                'severity': 'high'
            },
            'X-Frame-Options': {
                'name': 'X-Frame-Options',
                'description': 'Prevents clickjacking',
                'severity': 'medium'
            },
            'X-Content-Type-Options': {
                'name': 'X-Content-Type-Options',
                'description': 'Prevents MIME type sniffing',
                'severity': 'medium'
            },
            'X-XSS-Protection': {
                'name': 'X-XSS-Protection',
                'description': 'XSS filter (deprecated but still useful)',
                'severity': 'low'
            },
            'Referrer-Policy': {
                'name': 'Referrer-Policy',
                'description': 'Controls referrer information',
                'severity': 'medium'
            },
            'Permissions-Policy': {
                'name': 'Permissions-Policy',
                'description': 'Controls browser features',
                'severity': 'medium'
            },
            'Cross-Origin-Opener-Policy': {
                'name': 'COOP',
                'description': 'Isolates browsing context',
                'severity': 'low'
            },
            'Cross-Origin-Embedder-Policy': {
                'name': 'COEP',
                'description': 'Prevents loading cross-origin resources',
                'severity': 'low'
            },
            'Cross-Origin-Resource-Policy': {
                'name': 'CORP',
                'description': 'Controls resource sharing',
                'severity': 'low'
            },
        }
        
        for header, info in security_headers.items():
            if header in headers:
                header_analysis['score'] += 1
                header_analysis['present'].append(info['name'])
                header_analysis['details'][info['name']] = {
                    'value': headers[header],
                    'severity': info['severity']
                }
            else:
                header_analysis['missing'].append(info['name'])
        
        return header_analysis
    
    def _analyze_cookies(self, cookies) -> Dict[str, Any]:
        """
        Analyze cookie security
        
        Args:
            cookies: Response cookies
            
        Returns:
            Cookie analysis
        """
        cookie_analysis = {
            'total': len(cookies),
            'secure': 0,
            'httponly': 0,
            'samesite': 0,
            'issues': []
        }
        
        for cookie in cookies.values():
            # Check Secure flag
            if cookie.get('secure'):
                cookie_analysis['secure'] += 1
            else:
                cookie_analysis['issues'].append(
                    f"Cookie '{cookie.key}' missing Secure flag"
                )
            
            # Check HttpOnly flag
            if cookie.get('httponly'):
                cookie_analysis['httponly'] += 1
            else:
                cookie_analysis['issues'].append(
                    f"Cookie '{cookie.key}' missing HttpOnly flag"
                )
            
            # Check SameSite attribute
            if cookie.get('samesite'):
                cookie_analysis['samesite'] += 1
            else:
                cookie_analysis['issues'].append(
                    f"Cookie '{cookie.key}' missing SameSite attribute"
                )
        
        return cookie_analysis
    
    async def _check_vulnerabilities(self, url: str, headers: Dict[str, str]) -> List[Dict]:
        """
        Check for common vulnerabilities
        
        Args:
            url: Target URL
            headers: Response headers
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        # Check for clickjacking vulnerability
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            vulnerabilities.append({
                'type': 'Clickjacking',
                'severity': 'Medium',
                'description': 'Site can be embedded in frames, allowing clickjacking attacks'
            })
        
        # Check for MIME sniffing
        if 'X-Content-Type-Options' not in headers:
            vulnerabilities.append({
                'type': 'MIME Sniffing',
                'severity': 'Low',
                'description': 'Browser may interpret files as different type than declared'
            })
        
        # Check for missing HSTS
        if url.startswith('https://') and 'Strict-Transport-Security' not in headers:
            vulnerabilities.append({
                'type': 'Missing HSTS',
                'severity': 'High',
                'description': 'HTTPS connections not enforced, vulnerable to downgrade attacks'
            })
        
        # Check server information disclosure
        if 'Server' in headers:
            server = headers['Server']
            if any(char.isdigit() for char in server):
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'description': f"Server version disclosed: {server}"
                })
        
        # Check for weak CSP
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy'].lower()
            if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                vulnerabilities.append({
                    'type': 'Weak CSP',
                    'severity': 'Medium',
                    'description': 'CSP allows unsafe-inline or unsafe-eval'
                })
        
        # Check CORS configuration
        if 'Access-Control-Allow-Origin' in headers:
            cors = headers['Access-Control-Allow-Origin']
            if cors == '*':
                vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'Medium',
                    'description': 'CORS allows requests from any origin'
                })
        
        return vulnerabilities
    
    def _calculate_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100)"""
        score = 100
        
        # SSL/TLS (30 points)
        if not results.get('https'):
            score -= 30
        elif results.get('ssl'):
            ssl = results['ssl']
            if ssl.get('grade') == 'A+':
                pass  # No deduction
            elif ssl.get('grade') == 'A':
                score -= 5
            elif ssl.get('grade') == 'B':
                score -= 10
            else:
                score -= 20
            
            # Deduct for SSL issues
            score -= len(ssl.get('issues', [])) * 5
        
        # Security Headers (40 points)
        headers = results.get('headers', {})
        if headers:
            header_score = (headers.get('score', 0) / headers.get('total', 10)) * 40
            score = score - 40 + header_score
        else:
            score -= 40
        
        # Cookies (15 points)
        cookies = results.get('cookies', {})
        if cookies and cookies.get('total', 0) > 0:
            cookie_ratio = (
                cookies.get('secure', 0) + 
                cookies.get('httponly', 0) + 
                cookies.get('samesite', 0)
            ) / (cookies.get('total', 1) * 3)
            score = score - 15 + (cookie_ratio * 15)
        
        # Vulnerabilities (15 points)
        vulns = results.get('vulnerabilities', [])
        for vuln in vulns:
            if vuln.get('severity') == 'High':
                score -= 5
            elif vuln.get('severity') == 'Medium':
                score -= 3
            else:
                score -= 1
        
        return max(0, min(100, int(score)))
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score"""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # HTTPS recommendation
        if not results.get('https'):
            recommendations.append('Enable HTTPS with a valid SSL certificate')
        
        # SSL recommendations
        ssl = results.get('ssl', {})
        if ssl.get('version') not in ['TLSv1.3', 'TLSv1.2']:
            recommendations.append('Upgrade to TLS 1.2 or TLS 1.3')
        
        # Header recommendations
        headers = results.get('headers', {})
        missing = headers.get('missing', [])
        
        if 'HSTS' in missing:
            recommendations.append('Add Strict-Transport-Security header with long max-age')
        if 'CSP' in missing:
            recommendations.append('Implement Content-Security-Policy to prevent XSS attacks')
        if 'X-Frame-Options' in missing:
            recommendations.append('Add X-Frame-Options: DENY to prevent clickjacking')
        if 'X-Content-Type-Options' in missing:
            recommendations.append('Add X-Content-Type-Options: nosniff')
        if 'Permissions-Policy' in missing:
            recommendations.append('Add Permissions-Policy header to control browser features')
        
        # Cookie recommendations
        cookies = results.get('cookies', {})
        if cookies.get('issues'):
            recommendations.append('Set Secure, HttpOnly, and SameSite flags on all cookies')
        
        # Vulnerability-based recommendations
        vulns = results.get('vulnerabilities', [])
        for vuln in vulns:
            if vuln.get('type') == 'CORS Misconfiguration':
                recommendations.append('Restrict CORS to specific trusted origins')
            elif vuln.get('type') == 'Information Disclosure':
                recommendations.append('Hide server version information in headers')
        
        return recommendations
