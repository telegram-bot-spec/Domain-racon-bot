"""
Technology stack detection module (Wappalyzer-style)
"""

import asyncio
import aiohttp
import re
import hashlib
from typing import Dict, List, Set, Optional, Any
from bs4 import BeautifulSoup
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class TechDetector:
    """
    Detect technologies used by a website
    """
    
    def __init__(self, timeout: int = config.HTTP_TIMEOUT):
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.user_agents = config.USER_AGENTS
        
    async def __aenter__(self):
        """Async context manager entry"""
        headers = {'User-Agent': self.user_agents[0]}
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def detect(self, domain: str, mode: str = 'full') -> Dict[str, Any]:
        """
        Detect technologies used by domain
        
        Args:
            domain: Target domain
            mode: 'basic' or 'full'
            
        Returns:
            Dictionary with detected technologies
        """
        if not self.session:
            async with self:
                return await self.detect(domain, mode)
        
        # Ensure domain has protocol
        if not domain.startswith('http'):
            url = f"https://{domain}"
        else:
            url = domain
        
        results = {
            'url': url,
            'technologies': {},
            'total_detected': 0,
            'categories': {},
            'server_info': {},
            'vulnerabilities': [],
            'error': None
        }
        
        try:
            # Fetch page
            async with self.session.get(url, ssl=False, allow_redirects=True) as response:
                html = await response.text()
                headers = dict(response.headers)
                cookies = response.cookies
                status_code = response.status
                final_url = str(response.url)
                
                results['final_url'] = final_url
                results['status_code'] = status_code
                
                # Detect from headers
                header_techs = self._detect_from_headers(headers)
                
                # Detect from HTML
                html_techs = self._detect_from_html(html)
                
                # Detect from cookies
                cookie_techs = self._detect_from_cookies(cookies)
                
                # Combine all detections
                all_techs = {**header_techs, **html_techs, **cookie_techs}
                
                # Categorize technologies
                for tech_name, tech_info in all_techs.items():
                    category = tech_info.get('category', 'Other')
                    
                    if category not in results['categories']:
                        results['categories'][category] = []
                    
                    results['categories'][category].append({
                        'name': tech_name,
                        'version': tech_info.get('version'),
                        'confidence': tech_info.get('confidence', 'high')
                    })
                
                results['technologies'] = all_techs
                results['total_detected'] = len(all_techs)
                
                # Extract server info
                results['server_info'] = {
                    'server': headers.get('Server'),
                    'powered_by': headers.get('X-Powered-By'),
                    'framework': headers.get('X-Framework'),
                    'generator': self._extract_generator(html)
                }
                
                # Check for known vulnerabilities in detected versions
                if mode == 'full':
                    results['vulnerabilities'] = self._check_vulnerabilities(all_techs)
                
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _detect_from_headers(self, headers: Dict[str, str]) -> Dict[str, Dict]:
        """Detect technologies from HTTP headers"""
        detected = {}
        
        # Server header
        server = headers.get('Server', '').lower()
        if server:
            if 'nginx' in server:
                version = self._extract_version(server, r'nginx[/\s]?([\d.]+)')
                detected['Nginx'] = {'category': 'Web Servers', 'version': version}
            elif 'apache' in server:
                version = self._extract_version(server, r'apache[/\s]?([\d.]+)')
                detected['Apache'] = {'category': 'Web Servers', 'version': version}
            elif 'iis' in server or 'microsoft' in server:
                version = self._extract_version(server, r'iis[/\s]?([\d.]+)')
                detected['IIS'] = {'category': 'Web Servers', 'version': version}
            elif 'litespeed' in server:
                detected['LiteSpeed'] = {'category': 'Web Servers'}
            elif 'cloudflare' in server:
                detected['Cloudflare'] = {'category': 'CDN'}
        
        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '').lower()
        if powered_by:
            if 'php' in powered_by:
                version = self._extract_version(powered_by, r'php[/\s]?([\d.]+)')
                detected['PHP'] = {'category': 'Programming Languages', 'version': version}
            elif 'asp.net' in powered_by:
                version = self._extract_version(powered_by, r'asp\.net[/\s]?([\d.]+)')
                detected['ASP.NET'] = {'category': 'Frameworks', 'version': version}
            elif 'express' in powered_by:
                detected['Express'] = {'category': 'Frameworks'}
        
        # Framework headers
        if 'X-Framework' in headers:
            detected[headers['X-Framework']] = {'category': 'Frameworks'}
        
        # CDN/WAF detection
        if 'CF-RAY' in headers or 'cf-ray' in headers:
            detected['Cloudflare'] = {'category': 'CDN'}
        
        if 'X-Amz-Cf-Id' in headers:
            detected['AWS CloudFront'] = {'category': 'CDN'}
        
        if 'X-Fastly-Request-ID' in headers:
            detected['Fastly'] = {'category': 'CDN'}
        
        return detected
    
    def _detect_from_html(self, html: str) -> Dict[str, Dict]:
        """Detect technologies from HTML content"""
        detected = {}
        html_lower = html.lower()
        
        # CMS Detection
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
            'Joomla': [r'joomla', r'/components/com_'],
            'Drupal': [r'drupal', r'sites/default/files'],
            'Shopify': [r'cdn.shopify.com', r'shopify'],
            'Wix': [r'wix.com', r'parastorage'],
            'Squarespace': [r'squarespace'],
            'Magento': [r'magento', r'mage/cookies.js'],
            'PrestaShop': [r'prestashop'],
            'OpenCart': [r'catalog/view/theme'],
            'Ghost': [r'ghost.org', r'content/themes/'],
        }
        
        for cms, patterns in cms_patterns.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                detected[cms] = {'category': 'CMS'}
                
                # Try to detect version
                if cms == 'WordPress':
                    version = self._extract_version(html, r'wp-(?:includes|content)/.*?ver=([\d.]+)')
                    if version:
                        detected[cms]['version'] = version
        
        # JavaScript Frameworks
        js_frameworks = {
            'React': [r'react', r'_reactRoot'],
            'Vue.js': [r'vue\.js', r'data-v-'],
            'Angular': [r'ng-', r'angular'],
            'jQuery': [r'jquery', r'\$\.fn\.jquery'],
            'Next.js': [r'__next', r'_next/static'],
            'Nuxt.js': [r'__nuxt'],
            'Svelte': [r'svelte'],
            'Ember.js': [r'ember'],
        }
        
        for framework, patterns in js_frameworks.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                detected[framework] = {'category': 'JavaScript Frameworks'}
        
        # CSS Frameworks
        css_frameworks = {
            'Bootstrap': [r'bootstrap'],
            'Tailwind CSS': [r'tailwind'],
            'Foundation': [r'foundation'],
            'Bulma': [r'bulma'],
            'Materialize': [r'materialize'],
        }
        
        for framework, patterns in css_frameworks.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                detected[framework] = {'category': 'UI Frameworks'}
        
        # Analytics & Tracking
        analytics = {
            'Google Analytics': [r'google-analytics\.com', r'gtag\(', r'ga\('],
            'Google Tag Manager': [r'googletagmanager\.com'],
            'Facebook Pixel': [r'facebook\.com/tr', r'fbq\('],
            'Hotjar': [r'hotjar'],
            'Mixpanel': [r'mixpanel'],
            'Segment': [r'segment\.com'],
            'Intercom': [r'intercom'],
        }
        
        for tool, patterns in analytics.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                detected[tool] = {'category': 'Analytics'}
        
        # Payment Processors
        payment = {
            'Stripe': [r'stripe'],
            'PayPal': [r'paypal'],
            'Square': [r'squareup'],
        }
        
        for processor, patterns in payment.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                detected[processor] = {'category': 'Payment'}
        
        # Parse HTML with BeautifulSoup for meta tags
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Generator meta tag
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                content = generator['content']
                detected[content] = {'category': 'CMS'}
        except (AttributeError, TypeError):
            # Handle parsing errors gracefully
            pass
        
        return detected
    
    def _detect_from_cookies(self, cookies) -> Dict[str, Dict]:
        """Detect technologies from cookies"""
        detected = {}
        
        cookie_patterns = {
            'PHP': ['phpsessid'],
            'ASP.NET': ['asp.net_sessionid', 'aspsessionid'],
            'Laravel': ['laravel_session'],
            'Django': ['sessionid', 'csrftoken'],
            'Express': ['connect.sid'],
            'Rails': ['_session_id'],
            'Craft CMS': ['craftsessionid'],
        }
        
        cookie_names = [cookie.key.lower() for cookie in cookies.values()]
        
        for tech, patterns in cookie_patterns.items():
            if any(pattern in cookie_names for pattern in patterns):
                detected[tech] = {'category': 'Frameworks'}
        
        return detected
    
    def _extract_version(self, text: str, pattern: str) -> Optional[str]:
        """Extract version number from text using regex"""
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    def _extract_generator(self, html: str) -> Optional[str]:
        """Extract generator from meta tag"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                return generator['content']
        except (AttributeError, TypeError):
            pass
        return None
    
    def _check_vulnerabilities(self, technologies: Dict[str, Dict]) -> List[Dict]:
        """
        Check for known vulnerabilities in detected versions
        Note: This is a simple check. In production, integrate with CVE databases.
        """
        vulnerabilities = []
        
        # Known vulnerable versions (simplified example)
        known_vulns = {
            'jQuery': {
                '3.5.1': ['CVE-2020-11022', 'CVE-2020-11023'],
                '3.4.1': ['CVE-2020-11022', 'CVE-2020-11023'],
                '1.12.4': ['Multiple XSS vulnerabilities'],
            },
            'WordPress': {
                '5.8.0': ['CVE-2021-39200'],
                '5.7.0': ['CVE-2021-29447'],
            },
            'PHP': {
                '7.4.0': ['CVE-2019-11048'],
                '7.3.0': ['CVE-2019-11043'],
            },
        }
        
        for tech_name, tech_info in technologies.items():
            version = tech_info.get('version')
            
            if tech_name in known_vulns and version in known_vulns[tech_name]:
                cves = known_vulns[tech_name][version]
                vulnerabilities.append({
                    'technology': tech_name,
                    'version': version,
                    'cves': cves,
                    'severity': 'Medium'
                })
        
        return vulnerabilities
