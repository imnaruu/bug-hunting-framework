"""
Technology Detection Engine

Passive technology detection for web applications including:
- Backend languages and frameworks
- Template engines
- Web servers
- API styles

Uses headers, response patterns, and error messages - no active probing.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import re
from collections import defaultdict


@dataclass
class DetectedTechnology:
    """Represents a detected technology with confidence score."""
    
    name: str
    category: str  # 'language', 'framework', 'template_engine', 'web_server', 'api_style'
    version: Optional[str] = None
    confidence: float = 0.0  # 0.0 to 1.0
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class TechStack:
    """Complete technology stack detection result."""
    
    languages: List[DetectedTechnology] = field(default_factory=list)
    frameworks: List[DetectedTechnology] = field(default_factory=list)
    template_engines: List[DetectedTechnology] = field(default_factory=list)
    web_servers: List[DetectedTechnology] = field(default_factory=list)
    api_styles: List[DetectedTechnology] = field(default_factory=list)
    raw_indicators: Dict[str, List[str]] = field(default_factory=dict)


class TechDetector:
    """
    Technology detection engine using passive analysis.
    
    Identifies web technologies through headers, error messages,
    response patterns, and file extensions without active probing.
    """
    
    # Header-based detection patterns
    HEADER_SIGNATURES = {
        'X-Powered-By': {
            r'PHP/(\d+\.\d+\.\d+)': ('PHP', 'language'),
            r'Express': ('Express', 'framework'),
            r'ASP\.NET': ('ASP.NET', 'framework'),
            r'Servlet': ('Java Servlet', 'framework'),
            r'Rails': ('Ruby on Rails', 'framework'),
        },
        'Server': {
            r'nginx/(\d+\.\d+\.\d+)': ('nginx', 'web_server'),
            r'Apache/(\d+\.\d+\.\d+)': ('Apache', 'web_server'),
            r'Microsoft-IIS/(\d+\.\d+)': ('IIS', 'web_server'),
            r'LiteSpeed': ('LiteSpeed', 'web_server'),
            r'Caddy': ('Caddy', 'web_server'),
            r'cloudflare': ('Cloudflare', 'web_server'),
        },
        'X-AspNet-Version': {
            r'(\d+\.\d+\.\d+)': ('ASP.NET', 'framework'),
        },
        'X-AspNetMvc-Version': {
            r'(\d+\.\d+)': ('ASP.NET MVC', 'framework'),
        },
        'X-Django-Version': {
            r'(\d+\.\d+\.\d+)': ('Django', 'framework'),
        },
        'X-Framework': {
            r'Laravel': ('Laravel', 'framework'),
            r'Symfony': ('Symfony', 'framework'),
        },
    }
    
    # Cookie-based detection
    COOKIE_SIGNATURES = {
        'PHPSESSID': ('PHP', 'language', 0.9),
        'JSESSIONID': ('Java', 'language', 0.9),
        'ASP.NET_SessionId': ('ASP.NET', 'framework', 0.95),
        'csrftoken': ('Django', 'framework', 0.7),
        'laravel_session': ('Laravel', 'framework', 0.95),
        'connect.sid': ('Express', 'framework', 0.8),
        '_rails_session': ('Ruby on Rails', 'framework', 0.9),
    }
    
    # Content-based detection patterns
    CONTENT_PATTERNS = {
        # Framework error pages
        r'Django\s+version\s+(\d+\.\d+\.\d+)': ('Django', 'framework', 0.95),
        r'Laravel\s+(\d+\.\d+\.\d+)': ('Laravel', 'framework', 0.95),
        r'Symfony\s+(\d+\.\d+\.\d+)': ('Symfony', 'framework', 0.9),
        r'Spring\s+Framework\s+(\d+\.\d+\.\d+)': ('Spring', 'framework', 0.95),
        r'Flask\s+(\d+\.\d+\.\d+)': ('Flask', 'framework', 0.9),
        r'Express\s+(\d+\.\d+\.\d+)': ('Express', 'framework', 0.85),
        
        # Template engines
        r'\{%.*?%\}': ('Jinja2/Django Template', 'template_engine', 0.7),
        r'\{\{.*?\}\}': ('Handlebars/Mustache/Vue', 'template_engine', 0.6),
        r'<%=.*?%>': ('EJS/ERB', 'template_engine', 0.7),
        r'@yield\(': ('Blade', 'template_engine', 0.8),
        r'th:': ('Thymeleaf', 'template_engine', 0.85),
        
        # Error messages
        r'Warning:.*?in\s+/.*?\.php': ('PHP', 'language', 0.9),
        r'Fatal error:.*?\.php': ('PHP', 'language', 0.95),
        r'Traceback.*?\.py"': ('Python', 'language', 0.9),
        r'at\s+.*?\.java:\d+': ('Java', 'language', 0.9),
        r'Error.*?\.rb:\d+': ('Ruby', 'language', 0.85),
        r'at\s+.*?\.js:\d+': ('Node.js', 'language', 0.7),
        
        # API patterns
        r'"__typename"': ('GraphQL', 'api_style', 0.8),
        r'<soap:Envelope': ('SOAP', 'api_style', 0.95),
        r'<wsdl:definitions': ('SOAP', 'api_style', 0.95),
    }
    
    # File extension mapping
    EXTENSION_MAPPING = {
        '.php': ('PHP', 'language', 0.95),
        '.jsp': ('Java', 'language', 0.9),
        '.aspx': ('ASP.NET', 'framework', 0.95),
        '.do': ('Java/Struts', 'framework', 0.8),
        '.action': ('Java/Struts', 'framework', 0.8),
        '.py': ('Python', 'language', 0.7),
        '.rb': ('Ruby', 'language', 0.7),
        '.cfm': ('ColdFusion', 'language', 0.95),
    }
    
    def __init__(self):
        """Initialize technology detector."""
        self.detection_cache: Dict[str, TechStack] = {}
    
    def detect(
        self,
        url: str,
        headers: Dict[str, str],
        body: str = "",
        cookies: Optional[Dict[str, str]] = None
    ) -> TechStack:
        """
        Detect technologies from HTTP response data.
        
        Args:
            url: Request URL for extension analysis
            headers: Response headers
            body: Response body content
            cookies: Cookie dictionary
            
        Returns:
            TechStack with all detected technologies
        """
        tech_stack = TechStack()
        indicators: Dict[str, List[str]] = defaultdict(list)
        detected: Dict[str, DetectedTechnology] = {}
        
        # Detect from headers
        self._detect_from_headers(headers, detected, indicators)
        
        # Detect from cookies
        if cookies:
            self._detect_from_cookies(cookies, detected, indicators)
        
        # Detect from URL/extensions
        self._detect_from_url(url, detected, indicators)
        
        # Detect from body content
        if body:
            self._detect_from_content(body, detected, indicators)
        
        # Categorize detected technologies
        for tech in detected.values():
            if tech.category == 'language':
                tech_stack.languages.append(tech)
            elif tech.category == 'framework':
                tech_stack.frameworks.append(tech)
            elif tech.category == 'template_engine':
                tech_stack.template_engines.append(tech)
            elif tech.category == 'web_server':
                tech_stack.web_servers.append(tech)
            elif tech.category == 'api_style':
                tech_stack.api_styles.append(tech)
        
        # Sort by confidence
        for tech_list in [
            tech_stack.languages,
            tech_stack.frameworks,
            tech_stack.template_engines,
            tech_stack.web_servers,
            tech_stack.api_styles
        ]:
            tech_list.sort(key=lambda t: t.confidence, reverse=True)
        
        tech_stack.raw_indicators = dict(indicators)
        return tech_stack
    
    def _detect_from_headers(
        self,
        headers: Dict[str, str],
        detected: Dict[str, DetectedTechnology],
        indicators: Dict[str, List[str]]
    ) -> None:
        """Detect technologies from HTTP headers."""
        for header_name, patterns in self.HEADER_SIGNATURES.items():
            header_value = headers.get(header_name, '')
            if not header_value:
                continue
            
            for pattern, (tech_name, category) in patterns.items():
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    key = f"{tech_name}:{category}"
                    
                    if key not in detected:
                        detected[key] = DetectedTechnology(
                            name=tech_name,
                            category=category,
                            version=version,
                            confidence=0.95,
                            indicators=[f"Header: {header_name}={header_value}"]
                        )
                    else:
                        detected[key].confidence = min(1.0, detected[key].confidence + 0.05)
                        detected[key].indicators.append(f"Header: {header_name}={header_value}")
                    
                    if version:
                        detected[key].version = version
                    
                    indicators[tech_name].append(f"{header_name}: {header_value}")
    
    def _detect_from_cookies(
        self,
        cookies: Dict[str, str],
        detected: Dict[str, DetectedTechnology],
        indicators: Dict[str, List[str]]
    ) -> None:
        """Detect technologies from cookies."""
        for cookie_name in cookies.keys():
            if cookie_name in self.COOKIE_SIGNATURES:
                tech_name, category, confidence = self.COOKIE_SIGNATURES[cookie_name]
                key = f"{tech_name}:{category}"
                
                if key not in detected:
                    detected[key] = DetectedTechnology(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        indicators=[f"Cookie: {cookie_name}"]
                    )
                else:
                    detected[key].confidence = min(1.0, detected[key].confidence + 0.05)
                    detected[key].indicators.append(f"Cookie: {cookie_name}")
                
                indicators[tech_name].append(f"Cookie: {cookie_name}")
    
    def _detect_from_url(
        self,
        url: str,
        detected: Dict[str, DetectedTechnology],
        indicators: Dict[str, List[str]]
    ) -> None:
        """Detect technologies from URL patterns and extensions."""
        for ext, (tech_name, category, confidence) in self.EXTENSION_MAPPING.items():
            if ext in url.lower():
                key = f"{tech_name}:{category}"
                
                if key not in detected:
                    detected[key] = DetectedTechnology(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        indicators=[f"URL extension: {ext}"]
                    )
                else:
                    detected[key].confidence = min(1.0, detected[key].confidence + 0.05)
                    detected[key].indicators.append(f"URL extension: {ext}")
                
                indicators[tech_name].append(f"URL contains: {ext}")
    
    def _detect_from_content(
        self,
        body: str,
        detected: Dict[str, DetectedTechnology],
        indicators: Dict[str, List[str]]
    ) -> None:
        """Detect technologies from response body content."""
        # Limit content analysis to first 50KB to avoid performance issues
        content_sample = body[:51200]
        
        for pattern, (tech_name, category, confidence) in self.CONTENT_PATTERNS.items():
            matches = re.finditer(pattern, content_sample, re.IGNORECASE | re.DOTALL)
            for match in matches:
                version = match.group(1) if match.groups() else None
                key = f"{tech_name}:{category}"
                
                if key not in detected:
                    detected[key] = DetectedTechnology(
                        name=tech_name,
                        category=category,
                        version=version,
                        confidence=confidence,
                        indicators=[f"Content pattern: {pattern[:50]}"]
                    )
                else:
                    detected[key].confidence = min(1.0, detected[key].confidence + 0.05)
                    detected[key].indicators.append(f"Content pattern match")
                
                if version and not detected[key].version:
                    detected[key].version = version
                
                indicators[tech_name].append(f"Content pattern: {match.group(0)[:100]}")
                break  # Only count first match per pattern
    
    def get_summary(self, tech_stack: TechStack) -> Dict[str, Any]:
        """
        Get human-readable summary of detected technologies.
        
        Args:
            tech_stack: Detected technology stack
            
        Returns:
            Summary dictionary with categorized technologies
        """
        return {
            'languages': [
                {
                    'name': t.name,
                    'version': t.version,
                    'confidence': f"{t.confidence:.0%}"
                }
                for t in tech_stack.languages
            ],
            'frameworks': [
                {
                    'name': t.name,
                    'version': t.version,
                    'confidence': f"{t.confidence:.0%}"
                }
                for t in tech_stack.frameworks
            ],
            'template_engines': [
                {
                    'name': t.name,
                    'confidence': f"{t.confidence:.0%}"
                }
                for t in tech_stack.template_engines
            ],
            'web_servers': [
                {
                    'name': t.name,
                    'version': t.version,
                    'confidence': f"{t.confidence:.0%}"
                }
                for t in tech_stack.web_servers
            ],
            'api_styles': [
                {
                    'name': t.name,
                    'confidence': f"{t.confidence:.0%}"
                }
                for t in tech_stack.api_styles
            ]
        }
