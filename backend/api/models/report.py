"""
Report Data Models
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from backend.api.models.finding import Finding, Severity


class ReportFormat(str, Enum):
    """Report output format"""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"


class ReportStatus(str, Enum):
    """Report status"""
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    SUBMITTED = "submitted"
    RETEST = "retest"
    CLOSED = "closed"


class AttackChain(BaseModel):
    """Attack chain model"""
    id: Optional[str] = None
    name: str
    description: str
    findings: List[str] = Field(default_factory=list)  # Finding IDs
    steps: List[str] = Field(default_factory=list)
    business_impact: str
    severity: Severity
    exploitability: str


class Report(BaseModel):
    """Security report model"""
    id: Optional[str] = None
    title: str
    target_id: str
    target_url: str
    
    # Executive summary
    executive_summary: str
    scope: str
    methodology: str
    
    # Findings
    findings: List[Finding] = Field(default_factory=list)
    attack_chains: List[AttackChain] = Field(default_factory=list)
    
    # Statistics
    total_findings: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_type: Dict[str, int] = Field(default_factory=dict)
    
    # Recommendations
    key_recommendations: List[str] = Field(default_factory=list)
    remediation_priority: List[str] = Field(default_factory=list)
    
    # Metadata
    format: ReportFormat = ReportFormat.MARKDOWN
    status: ReportStatus = ReportStatus.DRAFT
    version: str = "1.0"
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now())
    updated_at: datetime = Field(default_factory=lambda: datetime.now())
    submitted_at: Optional[datetime] = None
    
    # Retest
    retest_date: Optional[datetime] = None
    retest_notes: Optional[str] = None


class ReportRequest(BaseModel):
    """Request to generate a report"""
    target_id: str
    title: str
    executive_summary: Optional[str] = None
    scope: Optional[str] = None
    format: ReportFormat = ReportFormat.MARKDOWN
    include_attack_chains: bool = True


class ReportResponse(BaseModel):
    """Report response"""
    report: Report
    download_url: Optional[str] = None


class RetestRequest(BaseModel):
    """Retest request"""
    report_id: str
    finding_id: str
    status: str  # fixed, not_fixed, partially_fixed
    notes: str
    evidence: List[str] = Field(default_factory=list)


class RetestResponse(BaseModel):
    """Retest response"""
    report_id: str
    finding_id: str
    status: str
    message: str
