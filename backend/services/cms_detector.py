"""
CMS Detection Engine

Detects Content Management Systems through:
- Content fingerprinting
- Path patterns
- Meta tag analysis
- Generator tags
- Specific file signatures
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import re


@dataclass
class CMSDetection:
    """CMS detection result"""
    detected: bool
    cms_name: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    themes: List[str] = field(default_factory=list)


class CMSDetector:
    """
    Detects Content Management Systems and their components.
    
    Detection methods:
    1. Meta tags and generator tags
    2. URL patterns
    3. File signatures
    4. HTML structure patterns
    5. JavaScript library fingerprints
    """
    
    # CMS generator patterns
    GENERATOR_PATTERNS = {
        'wordpress': [
            r'WordPress\s+([\d.]+)',
            r'<meta name="generator" content="WordPress\s+([\d.]+)',
        ],
        'drupal': [
            r'Drupal\s+([\d.]+)',
            r'<meta name="Generator" content="Drupal\s+([\d.]+)',
        ],
        'joomla': [
            r'Joomla!\s+([\d.]+)',
            r'<meta name="generator" content="Joomla!\s+([\d.]+)',
        ],
        'magento': [
            r'Magento',
            r'<meta name="generator" content="Magento',
        ],
        'shopify': [
            r'Shopify',
            r'shopify\.com',
        ],
        'wix': [
            r'Wix\.com',
            r'static\.wixstatic\.com',
        ],
        'squarespace': [
            r'Squarespace',
            r'static\.squarespace\.com',
        ],
        'prestashop': [
            r'PrestaShop',
        ],
        'opencart': [
            r'OpenCart',
        ],
        'typo3': [
            r'TYPO3',
        ],
    }
    
    # Path-based signatures
    PATH_SIGNATURES = {
        'wordpress': [
            '/wp-content/',
            '/wp-includes/',
            '/wp-admin/',
            '/wp-json/',
            'xmlrpc.php',
        ],
        'drupal': [
            '/sites/default/',
            '/sites/all/',
            '/modules/',
            '/themes/',
            '?q=node/',
        ],
        'joomla': [
            '/components/',
            '/modules/',
            '/templates/',
            '/administrator/',
            '/index.php?option=',
        ],
        'magento': [
            '/skin/frontend/',
            '/js/mage/',
            '/media/catalog/',
            '/customer/account/',
        ],
        'shopify': [
            '/cdn.shopify.com/',
            '/checkout.shopify.com/',
            'myshopify.com',
        ],
        'wix': [
            'wixstatic.com',
            'wix.com',
            '/_partials/',
        ],
        'typo3': [
            '/typo3/',
            '/typo3conf/',
            '/fileadmin/',
        ],
        'opencart': [
            '/catalog/view/',
            '/image/cache/',
            'route=product/product',
        ],
    }
    
    # Header-based signatures
    HEADER_SIGNATURES = {
        'X-Powered-CMS': {
            r'WordPress': 'wordpress',
            r'Drupal': 'drupal',
            r'Joomla': 'joomla',
        },
        'X-Drupal-Cache': {
            r'.*': 'drupal',
        },
        'X-Drupal-Dynamic-Cache': {
            r'.*': 'drupal',
        },
    }
    
    # Cookie patterns
    COOKIE_PATTERNS = {
        'wordpress': ['wordpress_logged_in_', 'wp-settings-', 'wordpress_test_cookie'],
        'drupal': ['SESS', 'SSESS'],
        'joomla': ['joomla_'],
        'magento': ['frontend', 'CUSTOMER', 'EXTERNAL_NO_CACHE'],
        'prestashop': ['PrestaShop-'],
    }
    
    def __init__(self):
        """Initialize CMS detector"""
        pass
    
    def detect(self, headers: Dict[str, str], cookies: Dict[str, str],
               body: Optional[str] = None, url: str = "") -> CMSDetection:
        """
        Detect CMS from HTTP response data.
        
        Args:
            headers: Response headers
            cookies: Response cookies
            body: Response body (HTML)
            url: Request URL
            
        Returns:
            CMSDetection with results
        """
        detections = []
        
        # Header-based detection
        header_detections = self._detect_from_headers(headers)
        detections.extend(header_detections)
        
        # Cookie-based detection
        cookie_detections = self._detect_from_cookies(cookies)
        detections.extend(cookie_detections)
        
        # URL path detection
        url_detections = self._detect_from_url(url)
        detections.extend(url_detections)
        
        # Body content detection
        if body:
            body_detections = self._detect_from_body(body)
            detections.extend(body_detections)
        
        # Aggregate results
        if detections:
            # Consolidate by CMS name
            cms_scores = {}
            for det in detections:
                cms = det['cms']
                if cms not in cms_scores:
                    cms_scores[cms] = {
                        'confidence': 0.0,
                        'indicators': [],
                        'version': det.get('version'),
                    }
                cms_scores[cms]['confidence'] += det['confidence']
                cms_scores[cms]['indicators'].extend(det['indicators'])
                if det.get('version'):
                    cms_scores[cms]['version'] = det['version']
            
            # Get best match
            best_cms = max(cms_scores.items(), key=lambda x: x[1]['confidence'])
            cms_name, data = best_cms
            
            # Detect plugins/themes if applicable
            plugins, themes = [], []
            if body and cms_name == 'wordpress':
                plugins = self._detect_wordpress_plugins(body)
                themes = self._detect_wordpress_themes(body)
            
            return CMSDetection(
                detected=True,
                cms_name=cms_name,
                version=data['version'],
                confidence=min(1.0, data['confidence']),
                indicators=data['indicators'],
                plugins=plugins,
                themes=themes
            )
        
        return CMSDetection(detected=False)
    
    def _detect_from_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """Detect CMS from HTTP headers"""
        detections = []
        
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        for header_name, patterns in self.HEADER_SIGNATURES.items():
            header_key = header_name.lower()
            if header_key in normalized_headers:
                value = normalized_headers[header_key]
                for pattern, cms_name in patterns.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        detections.append({
                            'cms': cms_name,
                            'confidence': 0.7,
                            'indicators': [f'Header: {header_name}={value}'],
                            'version': None
                        })
        
        return detections
    
    def _detect_from_cookies(self, cookies: Dict[str, str]) -> List[Dict]:
        """Detect CMS from cookies"""
        detections = []
        
        for cms_name, cookie_patterns in self.COOKIE_PATTERNS.items():
            for cookie_name in cookies.keys():
                for pattern in cookie_patterns:
                    if pattern in cookie_name or cookie_name.startswith(pattern):
                        detections.append({
                            'cms': cms_name,
                            'confidence': 0.5,
                            'indicators': [f'Cookie: {cookie_name}'],
                            'version': None
                        })
        
        return detections
    
    def _detect_from_url(self, url: str) -> List[Dict]:
        """Detect CMS from URL patterns"""
        detections = []
        
        for cms_name, path_patterns in self.PATH_SIGNATURES.items():
            for pattern in path_patterns:
                if pattern in url:
                    detections.append({
                        'cms': cms_name,
                        'confidence': 0.4,
                        'indicators': [f'URL pattern: {pattern}'],
                        'version': None
                    })
        
        return detections
    
    def _detect_from_body(self, body: str) -> List[Dict]:
        """Detect CMS from HTML body"""
        detections = []
        
        # Generator tag detection
        for cms_name, patterns in self.GENERATOR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    detections.append({
                        'cms': cms_name,
                        'confidence': 0.8,
                        'indicators': [f'Generator tag: {match.group(0)}'],
                        'version': version
                    })
        
        # Path signatures in content
        for cms_name, path_patterns in self.PATH_SIGNATURES.items():
            for pattern in path_patterns:
                if pattern in body:
                    detections.append({
                        'cms': cms_name,
                        'confidence': 0.3,
                        'indicators': [f'Body contains: {pattern}'],
                        'version': None
                    })
        
        return detections
    
    def _detect_wordpress_plugins(self, body: str) -> List[str]:
        """Detect WordPress plugins from HTML"""
        plugins = set()
        
        # Plugin path pattern
        plugin_pattern = r'/wp-content/plugins/([^/\'"]+)'
        matches = re.findall(plugin_pattern, body)
        plugins.update(matches)
        
        return list(plugins)
    
    def _detect_wordpress_themes(self, body: str) -> List[str]:
        """Detect WordPress themes from HTML"""
        themes = set()
        
        # Theme path pattern
        theme_pattern = r'/wp-content/themes/([^/\'"]+)'
        matches = re.findall(theme_pattern, body)
        themes.update(matches)
        
        return list(themes)
    
    def get_security_advice(self, cms_name: str, version: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Get security testing advice for detected CMS.
        
        Args:
            cms_name: Name of detected CMS
            version: Version (optional)
            
        Returns:
            Dictionary with testing recommendations
        """
        advice = {
            'wordpress': {
                'common_issues': [
                    'Plugin vulnerabilities',
                    'Theme vulnerabilities',
                    'XML-RPC abuse',
                    'User enumeration',
                    'Weak admin credentials',
                ],
                'test_paths': [
                    '/wp-admin/',
                    '/wp-login.php',
                    '/xmlrpc.php',
                    '/wp-json/wp/v2/users',
                    '/?rest_route=/wp/v2/users',
                ],
                'focus_areas': ['Plugins', 'Themes', 'Authentication', 'REST API'],
            },
            'drupal': {
                'common_issues': [
                    'Module vulnerabilities',
                    'SQL injection (Drupalgeddon)',
                    'Remote code execution',
                    'Access bypass',
                ],
                'test_paths': [
                    '/user/login',
                    '/admin/',
                    '/?q=admin',
                    '/node/1',
                ],
                'focus_areas': ['Modules', 'Node access', 'Forms', 'Authentication'],
            },
            'joomla': {
                'common_issues': [
                    'Component vulnerabilities',
                    'SQL injection',
                    'File upload issues',
                    'Session hijacking',
                ],
                'test_paths': [
                    '/administrator/',
                    '/index.php?option=com_users',
                    '/components/',
                ],
                'focus_areas': ['Components', 'Extensions', 'Authentication'],
            },
        }
        
        return advice.get(cms_name, {
            'common_issues': ['Check for known CVEs'],
            'test_paths': ['/admin/', '/login'],
            'focus_areas': ['Authentication', 'Input validation'],
        })
