"""
Security Header Analysis Service

Analyzes HTTP security headers, cookie attributes, CORS configuration,
and identifies information disclosure issues.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum
import re


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class HeaderFinding:
    """Represents a security header finding."""
    
    title: str
    severity: Severity
    description: str
    header: Optional[str] = None
    current_value: Optional[str] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class HeaderAnalysisResult:
    """Complete header analysis result."""
    
    findings: List[HeaderFinding] = field(default_factory=list)
    security_score: float = 0.0  # 0-100
    missing_headers: List[str] = field(default_factory=list)
    present_headers: List[str] = field(default_factory=list)
    info_disclosure: List[str] = field(default_factory=list)
    cookie_issues: List[HeaderFinding] = field(default_factory=list)
    cors_issues: List[HeaderFinding] = field(default_factory=list)


class HeaderAnalyzer:
    """
    Analyzes HTTP headers for security issues.
    
    Checks security headers, cookie attributes, CORS configuration,
    and information disclosure without active probing.
    """
    
    # Required security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': Severity.HIGH,
            'description': 'HSTS header missing - connections may not be forced over HTTPS',
            'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'score_weight': 15
        },
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'description': 'X-Frame-Options missing - site may be vulnerable to clickjacking',
            'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
            'score_weight': 10
        },
        'X-Content-Type-Options': {
            'severity': Severity.MEDIUM,
            'description': 'X-Content-Type-Options missing - MIME sniffing attacks possible',
            'recommendation': 'Add: X-Content-Type-Options: nosniff',
            'score_weight': 10
        },
        'Content-Security-Policy': {
            'severity': Severity.HIGH,
            'description': 'CSP header missing - XSS and injection attacks not mitigated',
            'recommendation': "Add CSP header with appropriate directives",
            'score_weight': 20
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'description': 'X-XSS-Protection header missing (deprecated but may help older browsers)',
            'recommendation': 'Add: X-XSS-Protection: 1; mode=block',
            'score_weight': 5
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Referrer-Policy missing - referrer information may leak',
            'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
            'score_weight': 5
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'description': 'Permissions-Policy missing - browser features not restricted',
            'recommendation': 'Add Permissions-Policy to restrict unnecessary features',
            'score_weight': 5
        },
    }
    
    # Information disclosure headers
    INFO_DISCLOSURE_HEADERS = {
        'X-Powered-By': 'Technology information disclosure',
        'Server': 'Server version information disclosure',
        'X-AspNet-Version': 'ASP.NET version disclosure',
        'X-AspNetMvc-Version': 'ASP.NET MVC version disclosure',
        'X-Drupal-Cache': 'Drupal information disclosure',
        'X-Generator': 'Framework/CMS disclosure',
        'X-Debug-Token': 'Debug mode enabled',
        'X-Debug-Token-Link': 'Debug mode enabled',
    }
    
    # Dangerous header values
    DANGEROUS_VALUES = {
        'Access-Control-Allow-Origin': [
            (r'^\*$', 'Wildcard CORS - allows any origin', Severity.HIGH),
            (r'^null$', 'CORS allows null origin - potential sandbox escape', Severity.MEDIUM),
        ],
        'Access-Control-Allow-Credentials': [
            (r'^true$', 'CORS credentials enabled - check origin validation', Severity.MEDIUM),
        ],
        'X-Frame-Options': [
            (r'^ALLOW$', 'X-Frame-Options set to ALLOW - clickjacking possible', Severity.MEDIUM),
        ],
    }
    
    def __init__(self):
        """Initialize header analyzer."""
        pass
    
    def analyze(
        self,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        is_https: bool = False
    ) -> HeaderAnalysisResult:
        """
        Analyze HTTP headers for security issues.
        
        Args:
            headers: Response headers dictionary
            cookies: Cookie dictionary (optional)
            is_https: Whether request was over HTTPS
            
        Returns:
            HeaderAnalysisResult with all findings
        """
        result = HeaderAnalysisResult()
        
        # Normalize header names (case-insensitive)
        normalized_headers = {k.lower(): (k, v) for k, v in headers.items()}
        
        # Check for missing security headers
        self._check_missing_headers(normalized_headers, result)
        
        # Check for dangerous header values
        self._check_dangerous_values(normalized_headers, result)
        
        # Check CSP configuration
        self._analyze_csp(normalized_headers, result)
        
        # Check CORS configuration
        self._analyze_cors(normalized_headers, result)
        
        # Check information disclosure
        self._check_info_disclosure(headers, result)
        
        # Analyze cookies
        if cookies:
            self._analyze_cookies(cookies, is_https, result)
        
        # Calculate security score
        self._calculate_security_score(result)
        
        # Sort findings by severity
        result.findings.sort(key=lambda f: (
            ['critical', 'high', 'medium', 'low', 'info'].index(f.severity.value),
            f.title
        ))
        
        return result
    
    def _check_missing_headers(
        self,
        normalized_headers: Dict[str, tuple],
        result: HeaderAnalysisResult
    ) -> None:
        """Check for missing security headers."""
        for header_name, config in self.SECURITY_HEADERS.items():
            if header_name.lower() not in normalized_headers:
                result.missing_headers.append(header_name)
                result.findings.append(HeaderFinding(
                    title=f'Missing {header_name}',
                    severity=config['severity'],
                    description=config['description'],
                    header=header_name,
                    recommendation=config['recommendation']
                ))
            else:
                result.present_headers.append(header_name)
    
    def _check_dangerous_values(
        self,
        normalized_headers: Dict[str, tuple],
        result: HeaderAnalysisResult
    ) -> None:
        """Check for dangerous header values."""
        for header_name, patterns in self.DANGEROUS_VALUES.items():
            header_key = header_name.lower()
            if header_key in normalized_headers:
                original_name, value = normalized_headers[header_key]
                for pattern, description, severity in patterns:
                    if re.match(pattern, value.strip(), re.IGNORECASE):
                        result.findings.append(HeaderFinding(
                            title=f'Insecure {header_name}',
                            severity=severity,
                            description=description,
                            header=header_name,
                            current_value=value,
                            recommendation=f'Review and restrict {header_name} configuration'
                        ))
    
    def _analyze_csp(
        self,
        normalized_headers: Dict[str, tuple],
        result: HeaderAnalysisResult
    ) -> None:
        """Analyze Content Security Policy configuration."""
        csp_key = 'content-security-policy'
        if csp_key not in normalized_headers:
            return
        
        _, csp_value = normalized_headers[csp_key]
        
        # Check for unsafe directives
        if 'unsafe-inline' in csp_value:
            result.findings.append(HeaderFinding(
                title='CSP allows unsafe-inline',
                severity=Severity.MEDIUM,
                description='CSP contains unsafe-inline which reduces XSS protection',
                header='Content-Security-Policy',
                current_value=csp_value,
                recommendation='Remove unsafe-inline and use nonces or hashes instead'
            ))
        
        if 'unsafe-eval' in csp_value:
            result.findings.append(HeaderFinding(
                title='CSP allows unsafe-eval',
                severity=Severity.MEDIUM,
                description='CSP contains unsafe-eval which allows dangerous JS evaluation',
                header='Content-Security-Policy',
                current_value=csp_value,
                recommendation='Remove unsafe-eval if possible'
            ))
        
        # Check for wildcard sources
        if re.search(r'\*(?!\.)|\s+\*\s+', csp_value):
            result.findings.append(HeaderFinding(
                title='CSP uses wildcard sources',
                severity=Severity.MEDIUM,
                description='CSP uses wildcards which may allow untrusted resources',
                header='Content-Security-Policy',
                current_value=csp_value,
                recommendation='Specify explicit trusted sources instead of wildcards'
            ))
    
    def _analyze_cors(
        self,
        normalized_headers: Dict[str, tuple],
        result: HeaderAnalysisResult
    ) -> None:
        """Analyze CORS configuration."""
        acao_key = 'access-control-allow-origin'
        acac_key = 'access-control-allow-credentials'
        
        has_acao = acao_key in normalized_headers
        has_acac = acac_key in normalized_headers
        
        if not has_acao:
            return
        
        _, acao_value = normalized_headers[acao_key]
        
        # Check for wildcard with credentials
        if has_acac:
            _, acac_value = normalized_headers[acac_key]
            if acao_value.strip() == '*' and acac_value.strip().lower() == 'true':
                finding = HeaderFinding(
                    title='Insecure CORS Configuration',
                    severity=Severity.CRITICAL,
                    description='CORS allows any origin with credentials - critical security issue',
                    header='Access-Control-Allow-Origin',
                    current_value=f'Origin: {acao_value}, Credentials: {acac_value}',
                    recommendation='Never use wildcard origin with credentials enabled. Validate origins explicitly.'
                )
                result.findings.append(finding)
                result.cors_issues.append(finding)
        
        # Check for reflected origin
        if '://' in acao_value and acao_value.strip() != '*':
            finding = HeaderFinding(
                title='CORS Origin Reflection',
                severity=Severity.MEDIUM,
                description='CORS origin may be reflected from request - verify proper validation',
                header='Access-Control-Allow-Origin',
                current_value=acao_value,
                recommendation='Ensure origin is validated against whitelist before reflection'
            )
            result.cors_issues.append(finding)
    
    def _check_info_disclosure(
        self,
        headers: Dict[str, str],
        result: HeaderAnalysisResult
    ) -> None:
        """Check for information disclosure headers."""
        for header_name, description in self.INFO_DISCLOSURE_HEADERS.items():
            if header_name in headers:
                value = headers[header_name]
                result.info_disclosure.append(f'{header_name}: {value}')
                result.findings.append(HeaderFinding(
                    title=f'Information Disclosure: {header_name}',
                    severity=Severity.INFO,
                    description=description,
                    header=header_name,
                    current_value=value,
                    recommendation=f'Consider removing or obfuscating {header_name} header'
                ))
    
    def _analyze_cookies(
        self,
        cookies: Dict[str, str],
        is_https: bool,
        result: HeaderAnalysisResult
    ) -> None:
        """Analyze cookie security attributes."""
        for cookie_name, cookie_value in cookies.items():
            issues = []
            
            # Check for Secure flag
            if is_https and 'Secure' not in cookie_value:
                issues.append('Missing Secure flag')
            
            # Check for HttpOnly flag
            if 'HttpOnly' not in cookie_value:
                issues.append('Missing HttpOnly flag')
            
            # Check for SameSite attribute
            if 'SameSite' not in cookie_value:
                issues.append('Missing SameSite attribute')
            elif 'SameSite=None' in cookie_value:
                issues.append('SameSite=None (requires Secure flag)')
            
            if issues:
                severity = Severity.MEDIUM
                if 'session' in cookie_name.lower() or 'auth' in cookie_name.lower():
                    severity = Severity.HIGH
                
                finding = HeaderFinding(
                    title=f'Insecure Cookie: {cookie_name}',
                    severity=severity,
                    description=', '.join(issues),
                    header='Set-Cookie',
                    current_value=cookie_name,
                    recommendation='Add Secure, HttpOnly, and SameSite attributes to cookies'
                )
                result.findings.append(finding)
                result.cookie_issues.append(finding)
    
    def _calculate_security_score(self, result: HeaderAnalysisResult) -> None:
        """Calculate overall security score (0-100)."""
        base_score = 100.0
        
        # Deduct points for missing headers
        for header in result.missing_headers:
            if header in self.SECURITY_HEADERS:
                base_score -= self.SECURITY_HEADERS[header]['score_weight']
        
        # Deduct points for findings
        severity_penalties = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 15,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0
        }
        
        for finding in result.findings:
            if finding.severity in severity_penalties:
                base_score -= severity_penalties[finding.severity] * 0.5
        
        result.security_score = max(0.0, min(100.0, base_score))
    
    def get_summary(self, result: HeaderAnalysisResult) -> Dict[str, Any]:
        """
        Get human-readable summary of analysis.
        
        Args:
            result: Analysis result
            
        Returns:
            Summary dictionary
        """
        return {
            'security_score': f'{result.security_score:.1f}/100',
            'total_findings': len(result.findings),
            'by_severity': {
                'critical': len([f for f in result.findings if f.severity == Severity.CRITICAL]),
                'high': len([f for f in result.findings if f.severity == Severity.HIGH]),
                'medium': len([f for f in result.findings if f.severity == Severity.MEDIUM]),
                'low': len([f for f in result.findings if f.severity == Severity.LOW]),
                'info': len([f for f in result.findings if f.severity == Severity.INFO]),
            },
            'missing_security_headers': result.missing_headers,
            'info_disclosure_count': len(result.info_disclosure),
            'cookie_issues': len(result.cookie_issues),
            'cors_issues': len(result.cors_issues),
        }
