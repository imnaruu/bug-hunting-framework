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
        # Create test function for decision tree
        import httpx
        
        async def make_request(payload: str) -> str:
            """Make HTTP request with payload"""
            try:
                async with httpx.AsyncClient() as client:
                    params = {request.parameter: payload}
                    response = await client.get(request.url, params=params, timeout=10.0)
                    return response.text
            except Exception as e:
                return f"Error: {str(e)}"
        
        # Initialize decision tree with test function
        tree = XSSDecisionTree(test_function=lambda p: "")  # Placeholder, will use async
        
        # Run manual decision tree logic for async context
        # Step 1: Check reflection
        marker = "xss_test_12345"
        response = await make_request(marker)
        reflected = marker in response
        
        vulnerable = False
        successful_payload = None
        payloads_tested = [marker]
        evidence = []
        
        if reflected:
            evidence.append(f"Input reflected with marker: {marker}")
            
            # Step 2: Try basic XSS payloads
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                request.initial_payload if request.initial_payload else None
            ]
            
            for payload in xss_payloads:
                if payload:
                    payloads_tested.append(payload)
                    test_response = await make_request(payload)
                    
                    # Check if payload executed or is present unencoded
                    if payload in test_response or "<script>" in test_response:
                        vulnerable = True
                        successful_payload = payload
                        evidence.append(f"Successful payload: {payload}")
                        break
        
        # Determine severity and confidence
        severity = "medium" if vulnerable else "info"
        confidence = "high" if vulnerable else "low"
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=vulnerable,
            vulnerability_type="xss",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            payloads_tested=payloads_tested,
            successful_payload=successful_payload,
            remediation="Implement proper input validation and output encoding",
            next_steps=["Verify exploit in different browsers", "Test for DOM-based XSS"] if vulnerable else [],
            metadata={"reflected": reflected, "context": request.context or "unknown"}
        )
        
        # Create finding if vulnerable
        finding_id = None
        if vulnerable:
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.XSS,
                title=f"Cross-Site Scripting (XSS) in {request.parameter}",
                description=f"XSS vulnerability detected in parameter '{request.parameter}'. Input is reflected and can execute JavaScript.",
                severity=Severity(severity),
                confidence=ConfidenceLevel(confidence),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=successful_payload,
                evidence=evidence,
                remediation="Implement proper input validation and output encoding",
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
        import httpx
        
        async def make_request(payload: str) -> tuple:
            """Make HTTP request with payload, return (response, status, time)"""
            try:
                async with httpx.AsyncClient() as client:
                    params = {request.parameter: payload}
                    import time
                    start = time.time()
                    response = await client.get(request.url, params=params, timeout=10.0)
                    elapsed = (time.time() - start) * 1000
                    return response.text, response.status_code, elapsed
            except Exception as e:
                return f"Error: {str(e)}", 500, 0
        
        # Run SQLi tests
        vulnerable = False
        successful_payload = None
        payloads_tested = []
        evidence = []
        
        # Test payloads
        sqli_payloads = [
            "'",  # Error-based detection
            "' OR '1'='1",  # Boolean-based
            "' AND '1'='2",  # Boolean-based
            "' UNION SELECT NULL--",  # Union-based
            "'; WAITFOR DELAY '00:00:05'--",  # Time-based
            request.initial_payload if request.initial_payload else None
        ]
        
        baseline_response, baseline_status, baseline_time = await make_request("normal")
        
        for payload in sqli_payloads:
            if payload:
                payloads_tested.append(payload)
                test_response, test_status, test_time = await make_request(payload)
                
                # Check for SQL errors
                sql_errors = [
                    "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
                    "syntax error", "database error", "odbc", "jdbc"
                ]
                
                if any(err in test_response.lower() for err in sql_errors):
                    vulnerable = True
                    successful_payload = payload
                    evidence.append(f"SQL error detected with payload: {payload}")
                    break
                
                # Check for time-based SQLi
                if "WAITFOR" in payload and test_time > baseline_time + 4000:
                    vulnerable = True
                    successful_payload = payload
                    evidence.append(f"Time delay detected: {test_time}ms vs {baseline_time}ms")
                    break
        
        # Determine severity and confidence
        severity = "high" if vulnerable else "info"
        confidence = "medium" if vulnerable else "low"
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=vulnerable,
            vulnerability_type="sqli",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            payloads_tested=payloads_tested,
            successful_payload=successful_payload,
            remediation="Use parameterized queries or prepared statements",
            next_steps=["Enumerate database", "Extract sensitive data"] if vulnerable else [],
            metadata={"db_type": request.db_type or "unknown"}
        )
        
        # Create finding if vulnerable
        finding_id = None
        if vulnerable:
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.SQLI,
                title=f"SQL Injection in {request.parameter}",
                description=f"SQL injection vulnerability detected in parameter '{request.parameter}'. Database errors or anomalies detected.",
                severity=Severity(severity),
                confidence=ConfidenceLevel(confidence),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=successful_payload,
                evidence=evidence,
                remediation="Use parameterized queries or prepared statements",
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
        import httpx
        
        async def make_request(payload: str) -> tuple:
            """Make HTTP request with payload, return (response, status)"""
            try:
                async with httpx.AsyncClient() as client:
                    params = {request.parameter: payload}
                    response = await client.get(request.url, params=params, timeout=10.0)
                    return response.text, response.status_code
            except Exception as e:
                return f"Error: {str(e)}", 500
        
        # Run SSRF tests
        vulnerable = False
        successful_payload = None
        payloads_tested = []
        evidence = []
        
        # Test payloads for internal network access
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://[::1]",  # IPv6 localhost
            "file:///etc/passwd",
            request.initial_payload if request.initial_payload else None
        ]
        
        for payload in ssrf_payloads:
            if payload:
                payloads_tested.append(payload)
                test_response, test_status = await make_request(payload)
                
                # Check for SSRF indicators
                ssrf_indicators = [
                    "root:", "localhost", "127.0.0.1", 
                    "ami-id", "instance-id", "local-ipv4"
                ]
                
                if any(indicator in test_response.lower() for indicator in ssrf_indicators):
                    vulnerable = True
                    successful_payload = payload
                    evidence.append(f"SSRF detected with payload: {payload}")
                    evidence.append(f"Response contains internal data")
                    break
        
        # Determine severity and confidence
        severity = "high" if vulnerable else "info"
        confidence = "medium" if vulnerable else "low"
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=vulnerable,
            vulnerability_type="ssrf",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            payloads_tested=payloads_tested,
            successful_payload=successful_payload,
            remediation="Implement URL whitelist and disable unnecessary protocols",
            next_steps=["Access cloud metadata", "Scan internal network"] if vulnerable else [],
            metadata={"protocol": request.protocol or "http"}
        )
        
        # Create finding if vulnerable
        finding_id = None
        if vulnerable:
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.SSRF,
                title=f"Server-Side Request Forgery (SSRF) in {request.parameter}",
                description=f"SSRF vulnerability detected in parameter '{request.parameter}'. Server can be forced to make requests to internal resources.",
                severity=Severity(severity),
                confidence=ConfidenceLevel(confidence),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=successful_payload,
                evidence=evidence,
                remediation="Implement URL whitelist and disable unnecessary protocols",
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
        import httpx
        
        async def make_request(payload: str) -> str:
            """Make HTTP request with payload"""
            try:
                async with httpx.AsyncClient() as client:
                    params = {request.parameter: payload}
                    response = await client.get(request.url, params=params, timeout=10.0)
                    return response.text
            except Exception as e:
                return f"Error: {str(e)}"
        
        # Run SSTI tests
        vulnerable = False
        successful_payload = None
        payloads_tested = []
        evidence = []
        detected_engine = None
        
        # Test payloads for different template engines
        ssti_payloads = [
            "{{7*7}}",  # Jinja2, Twig
            "${7*7}",  # FreeMarker, Velocity
            "<%= 7*7 %>",  # ERB
            "#{7*7}",  # Ruby
            request.initial_payload if request.initial_payload else None
        ]
        
        for payload in ssti_payloads:
            if payload:
                payloads_tested.append(payload)
                test_response = await make_request(payload)
                
                # Check if expression evaluated (7*7 = 49)
                if "49" in test_response and payload.replace("7*7", "49") != payload:
                    vulnerable = True
                    successful_payload = payload
                    evidence.append(f"Template expression evaluated: {payload} -> 49")
                    
                    # Detect engine
                    if "{{" in payload:
                        detected_engine = "Jinja2 or Twig"
                    elif "${" in payload:
                        detected_engine = "FreeMarker or Velocity"
                    elif "<%=" in payload:
                        detected_engine = "ERB"
                    
                    break
        
        # Determine severity and confidence
        severity = "high" if vulnerable else "info"
        confidence = "high" if vulnerable else "low"
        
        # Create test result
        test_result = VulnerabilityTestResult(
            vulnerable=vulnerable,
            vulnerability_type="ssti",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            payloads_tested=payloads_tested,
            successful_payload=successful_payload,
            remediation="Avoid rendering user input in templates; use sandboxing",
            next_steps=["Achieve RCE", "Read sensitive files"] if vulnerable else [],
            metadata={"template_engine": detected_engine or request.template_engine or "unknown"}
        )
        
        # Create finding if vulnerable
        finding_id = None
        if vulnerable:
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                target_id=request.target_id,
                vulnerability_type=VulnerabilityType.SSTI,
                title=f"Server-Side Template Injection (SSTI) in {request.parameter}",
                description=f"SSTI vulnerability detected in parameter '{request.parameter}'. Template expressions are being evaluated.",
                severity=Severity(severity),
                confidence=ConfidenceLevel(confidence),
                endpoint=request.endpoint,
                parameter=request.parameter,
                payload=successful_payload,
                evidence=evidence,
                remediation="Avoid rendering user input in templates; use sandboxing",
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
