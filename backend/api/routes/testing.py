"""
Testing API Routes

Endpoints for running vulnerability decision trees and managing findings.
Supports XSS, SQLi, SSRF, and SSTI testing workflows.
"""
from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from backend.services.decision_trees.xss import XSSDecisionTree
from backend.services.decision_trees.sqli import SQLiDecisionTree
from backend.services.decision_trees.ssrf import SSRFDecisionTree
from backend.services.decision_trees.ssti import SSTIDecisionTree
from backend.api.models.finding import (
    Finding,
    FindingRequest,
    FindingResponse,
    FindingListResponse,
    VulnerabilityType,
    Severity,
    ConfidenceLevel
)


router = APIRouter(prefix="/testing", tags=["testing"])

# In-memory storage
findings: Dict[str, Finding] = {}


# Request/Response Models
class XSSTestRequest(BaseModel):
    """Request to run XSS decision tree"""
    target_id: str
    url: str
    endpoint: str
    parameter: str
    initial_payload: Optional[str] = None
    context: Optional[str] = None  # html, attribute, javascript, url


class SQLiTestRequest(BaseModel):
    """Request to run SQLi decision tree"""
    target_id: str
    url: str
    endpoint: str
    parameter: str
    initial_payload: Optional[str] = None
    db_type: Optional[str] = None  # mysql, postgresql, mssql, oracle


class SSRFTestRequest(BaseModel):
    """Request to run SSRF decision tree"""
    target_id: str
    url: str
    endpoint: str
    parameter: str
    initial_payload: Optional[str] = None
    protocol: Optional[str] = None  # http, file, gopher, etc.


class SSTITestRequest(BaseModel):
    """Request to run SSTI decision tree"""
    target_id: str
    url: str
    endpoint: str
    parameter: str
    initial_payload: Optional[str] = None
    template_engine: Optional[str] = None  # jinja2, twig, freemarker, etc.


class VulnerabilityTestResult(BaseModel):
    """Vulnerability test result"""
    vulnerable: bool
    vulnerability_type: str
    severity: str
    confidence: str
    evidence: List[str]
    payloads_tested: List[str]
    successful_payload: Optional[str] = None
    remediation: str
    next_steps: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TestResponse(BaseModel):
    """Test execution response"""
    test_id: str
    target_id: str
    result: VulnerabilityTestResult
    finding_id: Optional[str] = None
    timestamp: datetime


# Routes
@router.post("/xss", response_model=TestResponse, status_code=status.HTTP_200_OK)
async def run_xss_test(request: XSSTestRequest):
    """
    Run XSS decision tree testing workflow.
    
    Executes systematic XSS testing using a decision tree approach,
    adapting payloads based on response analysis and context detection.
    """
    try:
        tree = XSSDecisionTree()
        
        # Run decision tree
        result = await tree.execute(
            url=request.url,
            endpoint=request.endpoint,
            parameter=request.parameter,
            initial_payload=request.initial_payload,
            context=request.context
        )
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=result.get("vulnerable", False),
            vulnerability_type="xss",
            severity=result.get("severity", "medium"),
            confidence=result.get("confidence", "medium"),
            evidence=result.get("evidence", []),
            payloads_tested=result.get("payloads_tested", []),
            successful_payload=result.get("successful_payload"),
            remediation=result.get("remediation", "Implement proper input validation and output encoding"),
            next_steps=result.get("next_steps", []),
            metadata=result.get("metadata", {})
        )
        
        # Create finding if vulnerable
        finding_id = None
        if result.get("vulnerable", False):
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.XSS,
                title=f"Cross-Site Scripting (XSS) in {request.parameter}",
                description=result.get("description", "XSS vulnerability detected"),
                severity=Severity(result.get("severity", "medium")),
                confidence=ConfidenceLevel(result.get("confidence", "medium")),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=result.get("successful_payload"),
                evidence=result.get("evidence", []),
                remediation=result.get("remediation", ""),
                discovered_at=datetime.now()
            )
            findings[finding_id] = finding
        
        test_id = str(uuid.uuid4())
        return TestResponse(
            test_id=test_id,
            target_id=request.target_id,
            result=test_result,
            finding_id=finding_id,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"XSS testing failed: {str(e)}"
        )


@router.post("/sqli", response_model=TestResponse, status_code=status.HTTP_200_OK)
async def run_sqli_test(request: SQLiTestRequest):
    """
    Run SQL injection decision tree testing workflow.
    
    Executes systematic SQLi testing using a decision tree approach,
    adapting to database type and error messages.
    """
    try:
        tree = SQLiDecisionTree()
        
        # Run decision tree
        result = await tree.execute(
            url=request.url,
            endpoint=request.endpoint,
            parameter=request.parameter,
            initial_payload=request.initial_payload,
            db_type=request.db_type
        )
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=result.get("vulnerable", False),
            vulnerability_type="sqli",
            severity=result.get("severity", "high"),
            confidence=result.get("confidence", "medium"),
            evidence=result.get("evidence", []),
            payloads_tested=result.get("payloads_tested", []),
            successful_payload=result.get("successful_payload"),
            remediation=result.get("remediation", "Use parameterized queries or prepared statements"),
            next_steps=result.get("next_steps", []),
            metadata=result.get("metadata", {})
        )
        
        # Create finding if vulnerable
        finding_id = None
        if result.get("vulnerable", False):
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.SQLI,
                title=f"SQL Injection in {request.parameter}",
                description=result.get("description", "SQL injection vulnerability detected"),
                severity=Severity(result.get("severity", "high")),
                confidence=ConfidenceLevel(result.get("confidence", "medium")),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=result.get("successful_payload"),
                evidence=result.get("evidence", []),
                remediation=result.get("remediation", ""),
                discovered_at=datetime.now()
            )
            findings[finding_id] = finding
        
        test_id = str(uuid.uuid4())
        return TestResponse(
            test_id=test_id,
            target_id=request.target_id,
            result=test_result,
            finding_id=finding_id,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SQLi testing failed: {str(e)}"
        )


@router.post("/ssrf", response_model=TestResponse, status_code=status.HTTP_200_OK)
async def run_ssrf_test(request: SSRFTestRequest):
    """
    Run SSRF decision tree testing workflow.
    
    Executes systematic SSRF testing using a decision tree approach,
    testing various protocols and bypass techniques.
    """
    try:
        tree = SSRFDecisionTree()
        
        # Run decision tree
        result = await tree.execute(
            url=request.url,
            endpoint=request.endpoint,
            parameter=request.parameter,
            initial_payload=request.initial_payload,
            protocol=request.protocol
        )
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=result.get("vulnerable", False),
            vulnerability_type="ssrf",
            severity=result.get("severity", "high"),
            confidence=result.get("confidence", "medium"),
            evidence=result.get("evidence", []),
            payloads_tested=result.get("payloads_tested", []),
            successful_payload=result.get("successful_payload"),
            remediation=result.get("remediation", "Implement URL whitelist and disable unnecessary protocols"),
            next_steps=result.get("next_steps", []),
            metadata=result.get("metadata", {})
        )
        
        # Create finding if vulnerable
        finding_id = None
        if result.get("vulnerable", False):
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.SSRF,
                title=f"Server-Side Request Forgery (SSRF) in {request.parameter}",
                description=result.get("description", "SSRF vulnerability detected"),
                severity=Severity(result.get("severity", "high")),
                confidence=ConfidenceLevel(result.get("confidence", "medium")),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=result.get("successful_payload"),
                evidence=result.get("evidence", []),
                remediation=result.get("remediation", ""),
                discovered_at=datetime.now()
            )
            findings[finding_id] = finding
        
        test_id = str(uuid.uuid4())
        return TestResponse(
            test_id=test_id,
            target_id=request.target_id,
            result=test_result,
            finding_id=finding_id,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SSRF testing failed: {str(e)}"
        )


@router.post("/ssti", response_model=TestResponse, status_code=status.HTTP_200_OK)
async def run_ssti_test(request: SSTITestRequest):
    """
    Run SSTI decision tree testing workflow.
    
    Executes systematic SSTI testing using a decision tree approach,
    detecting template engine and crafting appropriate payloads.
    """
    try:
        tree = SSTIDecisionTree()
        
        # Run decision tree
        result = await tree.execute(
            url=request.url,
            endpoint=request.endpoint,
            parameter=request.parameter,
            initial_payload=request.initial_payload,
            template_engine=request.template_engine
        )
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=result.get("vulnerable", False),
            vulnerability_type="ssti",
            severity=result.get("severity", "high"),
            confidence=result.get("confidence", "medium"),
            evidence=result.get("evidence", []),
            payloads_tested=result.get("payloads_tested", []),
            successful_payload=result.get("successful_payload"),
            remediation=result.get("remediation", "Avoid rendering user input in templates; use sandboxing"),
            next_steps=result.get("next_steps", []),
            metadata=result.get("metadata", {})
        )
        
        # Create finding if vulnerable
        finding_id = None
        if result.get("vulnerable", False):
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.SSTI,
                title=f"Server-Side Template Injection (SSTI) in {request.parameter}",
                description=result.get("description", "SSTI vulnerability detected"),
                severity=Severity(result.get("severity", "high")),
                confidence=ConfidenceLevel(result.get("confidence", "medium")),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=result.get("successful_payload"),
                evidence=result.get("evidence", []),
                remediation=result.get("remediation", ""),
                discovered_at=datetime.now()
            )
            findings[finding_id] = finding
        
        test_id = str(uuid.uuid4())
        return TestResponse(
            test_id=test_id,
            target_id=request.target_id,
            result=test_result,
            finding_id=finding_id,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SSTI testing failed: {str(e)}"
        )


@router.get("/findings", response_model=FindingListResponse, status_code=status.HTTP_200_OK)
async def list_findings(
    target_id: Optional[str] = Query(None, description="Filter by target ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    vulnerability_type: Optional[str] = Query(None, description="Filter by vulnerability type"),
    status: Optional[str] = Query(None, description="Filter by status")
):
    """
    List all findings with optional filtering.
    
    Returns all discovered vulnerabilities with statistics
    grouped by severity and type.
    """
    try:
        # Start with all findings
        filtered_findings = list(findings.values())
        
        # Apply filters
        if target_id:
            filtered_findings = [f for f in filtered_findings if f.target_id == target_id]
        
        if severity:
            filtered_findings = [f for f in filtered_findings if f.severity.value == severity.lower()]
        
        if vulnerability_type:
            filtered_findings = [f for f in filtered_findings if f.vulnerability_type.value == vulnerability_type.lower()]
        
        if status:
            filtered_findings = [f for f in filtered_findings if f.status == status.lower()]
        
        # Calculate statistics
        by_severity = {}
        by_type = {}
        
        for finding in filtered_findings:
            # Count by severity
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # Count by type
            vtype = finding.vulnerability_type.value
            by_type[vtype] = by_type.get(vtype, 0) + 1
        
        return FindingListResponse(
            findings=filtered_findings,
            total=len(filtered_findings),
            by_severity=by_severity,
            by_type=by_type
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list findings: {str(e)}"
        )
