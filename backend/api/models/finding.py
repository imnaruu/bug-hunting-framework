"""
Finding and Vulnerability Data Models
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class VulnerabilityType(str, Enum):
    """Vulnerability classification"""
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    SSTI = "ssti"
    IDOR = "idor"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    INFO_DISCLOSURE = "info_disclosure"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    OTHER = "other"


class Severity(str, Enum):
    """Finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    """Confidence in finding"""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HYPOTHESIS = "hypothesis"


class Finding(BaseModel):
    """Security finding/vulnerability model"""
    id: Optional[str] = None
    target_id: str
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: Severity
    confidence: ConfidenceLevel
    
    # Technical details
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    http_method: str = "GET"
    
    # Evidence
    evidence: List[str] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)
    
    # Impact
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    attack_scenario: Optional[str] = None
    
    # Metadata
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    
    # Remediation
    remediation: Optional[str] = None
    remediation_complexity: Optional[str] = None
    
    # Timestamps
    discovered_at: datetime = Field(default_factory=lambda: datetime.now())
    updated_at: datetime = Field(default_factory=lambda: datetime.now())
    verified_at: Optional[datetime] = None
    
    # Status
    status: str = "open"
    false_positive: bool = False
    
    # Correlation
    related_findings: List[str] = Field(default_factory=list)
    attack_chain_id: Optional[str] = None


class FindingRequest(BaseModel):
    """Request to create/update a finding"""
    target_id: str
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: Severity
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    http_method: str = "GET"
    evidence: List[str] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    """Finding response"""
    finding: Finding
    confidence_score: Optional[Dict[str, Any]] = None


class FindingListResponse(BaseModel):
    """Finding list response"""
    findings: List[Finding]
    total: int
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_type: Dict[str, int] = Field(default_factory=dict)
