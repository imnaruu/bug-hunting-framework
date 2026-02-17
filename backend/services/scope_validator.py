"""
Scope Validation Service

This service ensures all testing remains within defined scope boundaries.
Core principle: Never test what you're not supposed to test.
"""
from typing import List, Tuple
from urllib.parse import urlparse
import re


class ScopeValidator:
    """Validates targets against defined scope"""
    
    def __init__(self):
        self.authorized_domains: List[str] = []
        self.authorized_patterns: List[str] = []
        self.blacklist: List[str] = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.",  # Link-local
            "10.",  # Private
            "172.16.",  # Private
            "192.168.",  # Private
        ]
    
    def add_authorized_domain(self, domain: str):
        """Add domain to scope"""
        domain = domain.lower().strip()
        if domain not in self.authorized_domains:
            self.authorized_domains.append(domain)
    
    def add_authorized_pattern(self, pattern: str):
        """Add regex pattern to scope"""
        if pattern not in self.authorized_patterns:
            self.authorized_patterns.append(pattern)
    
    def is_in_scope(self, url: str) -> Tuple[bool, str, List[str]]:
        """
        Check if URL is within defined scope
        
        Returns:
            Tuple of (is_valid, message, warnings)
        """
        warnings = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check blacklist first
            for blacklisted in self.blacklist:
                if blacklisted in domain:
                    return False, f"Target is blacklisted: {blacklisted}", warnings
            
            # If no domains set, warn but allow (testing mode)
            if not self.authorized_domains and not self.authorized_patterns:
                warnings.append("No scope defined - all targets allowed (unsafe)")
                return True, "No scope restrictions configured", warnings
            
            # Check exact domain match
            if domain in self.authorized_domains:
                return True, "Domain is in scope", warnings
            
            # Check subdomain match
            for auth_domain in self.authorized_domains:
                if domain.endswith(f".{auth_domain}"):
                    return True, f"Subdomain of: {auth_domain}", warnings
            
            # Check pattern match
            for pattern in self.authorized_patterns:
                if re.match(pattern, url):
                    return True, f"Matches pattern: {pattern}", warnings
            
            return False, "Target is not in defined scope", warnings
            
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}", warnings
    
    def get_scope_boundaries(self) -> List[str]:
        """Get current scope boundaries"""
        boundaries = []
        boundaries.extend([f"Domain: {d}" for d in self.authorized_domains])
        boundaries.extend([f"Pattern: {p}" for p in self.authorized_patterns])
        return boundaries


# Global scope validator instance
scope_validator = ScopeValidator()
