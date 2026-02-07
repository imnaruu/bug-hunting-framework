"""
Baseline Data Models
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class ResponseProfile(BaseModel):
    """HTTP response profile"""
    status_code: int
    content_length: int
    response_time: float  # milliseconds
    headers: Dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None


class BaselineMetrics(BaseModel):
    """Baseline behavioral metrics"""
    # Response characteristics
    avg_response_time: float
    std_response_time: float
    avg_content_length: int
    std_content_length: int
    
    # Status codes
    status_code_distribution: Dict[int, int] = Field(default_factory=dict)
    common_status_codes: List[int] = Field(default_factory=list)
    
    # Headers
    common_headers: Dict[str, str] = Field(default_factory=dict)
    security_headers: Dict[str, Any] = Field(default_factory=dict)
    
    # Patterns
    error_patterns: List[str] = Field(default_factory=list)
    success_patterns: List[str] = Field(default_factory=list)


class SecurityHeaders(BaseModel):
    """Security header analysis"""
    csp: Optional[str] = None
    csp_effective: bool = False
    csp_issues: List[str] = Field(default_factory=list)
    
    hsts: Optional[str] = None
    hsts_enabled: bool = False
    hsts_max_age: Optional[int] = None
    
    x_frame_options: Optional[str] = None
    clickjacking_protection: bool = False
    
    x_content_type_options: Optional[str] = None
    mime_sniffing_protection: bool = False
    
    cors_policy: Optional[str] = None
    cors_issues: List[str] = Field(default_factory=list)
    
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    cookie_issues: List[str] = Field(default_factory=list)


class Baseline(BaseModel):
    """Behavioral baseline for a target"""
    id: Optional[str] = None
    target_id: str
    url: str
    
    # Metrics
    metrics: BaselineMetrics
    security_headers: SecurityHeaders
    
    # Technology detection
    technologies: List[str] = Field(default_factory=list)
    
    # Metadata
    sample_size: int = 0
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class BaselineRequest(BaseModel):
    """Request to capture baseline"""
    target_id: str
    url: str
    sample_size: int = 10


class BaselineResponse(BaseModel):
    """Baseline response"""
    baseline: Baseline
    insights: List[str] = Field(default_factory=list)
    risk_hypotheses: List[str] = Field(default_factory=list)
