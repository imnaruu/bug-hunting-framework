"""
SSRF Decision Tree Module
Implements hypothesis-driven testing methodology for Server-Side Request Forgery vulnerabilities.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, Any
import re


class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability detection"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class SSRFType(Enum):
    """Types of SSRF vulnerabilities"""
    FULL_RESPONSE = "full_response"  # Response content is disclosed
    BLIND = "blind"  # No response disclosure, but request is made
    PARTIAL = "partial"  # Partial information disclosure
    UNKNOWN = "unknown"


@dataclass
class TestResult:
    """Structure for test step results"""
    step: int
    description: str
    payload: str
    expected: str
    actual: str
    success: bool
    confidence: ConfidenceLevel
    next_action: str
    evidence: dict[str, Any]


class SSRFDecisionTree:
    """
    SSRF vulnerability testing decision tree.
    Follows human security researcher reasoning patterns.
    Uses safe testing with controlled endpoints only.
    """
    
    def __init__(self, test_function: Callable[[str], tuple[str, int]]):
        """
        Initialize SSRF decision tree.
        
        Args:
            test_function: Function that takes URL and returns (response, status_code)
        """
        self.test_function = test_function
        self.results: list[TestResult] = []
        self.ssrf_type: Optional[SSRFType] = None
        self.controlled_domain = "example.com"  # Safe, controlled test domain
        
    def step1_test_external_fetch(self) -> TestResult:
        """
        Step 1: Test if application fetches external resources.
        
        Returns:
            TestResult with external fetch test outcome
        """
        # Test with a safe, well-known public endpoint
        test_url = f"http://{self.controlled_domain}"
        
        response, status_code = self.test_function(test_url)
        
        # Check for indicators that a fetch was attempted
        fetch_attempted = self._check_fetch_indicators(response, status_code, test_url)
        
        result = TestResult(
            step=1,
            description="Test if app fetches external resources",
            payload=test_url,
            expected="Application attempts to fetch the URL",
            actual=f"Fetch {'attempted' if fetch_attempted else 'not attempted'}",
            success=fetch_attempted,
            confidence=ConfidenceLevel.LOW if fetch_attempted else ConfidenceLevel.NONE,
            next_action="Proceed to step 2: Test if destination is controllable" if fetch_attempted
                       else "Application does not fetch external resources",
            evidence={
                "test_url": test_url,
                "status_code": status_code,
                "response_length": len(response),
                "fetch_attempted": fetch_attempted
            }
        )
        
        self.results.append(result)
        return result
    
    def _check_fetch_indicators(self, response: str, status_code: int, test_url: str) -> bool:
        """Check if application attempted to fetch the URL"""
        indicators = [
            status_code == 200,  # Successful response
            "example.com" in response.lower(),  # Domain appears in response
            len(response) > 0,  # Non-empty response
            status_code not in [400, 404, 500],  # Not an error
        ]
        
        # At least 2 indicators should be true
        return sum(indicators) >= 2
    
    def step2_test_destination_control(self) -> TestResult:
        """
        Step 2: Test if destination URL is controllable.
        
        Returns:
            TestResult with destination control test outcome
        """
        # Test with different controlled domains
        test_domains = [
            "test1.example.com",
            "test2.example.com",
            "alternate.example.com"
        ]
        
        responses = []
        for domain in test_domains:
            test_url = f"http://{domain}"
            response, status_code = self.test_function(test_url)
            responses.append({
                "domain": domain,
                "response": response,
                "status": status_code,
                "contains_domain": domain in response.lower()
            })
        
        # Check if different domains produce different responses
        destination_controllable = self._check_destination_control(responses)
        
        result = TestResult(
            step=2,
            description="Test if destination is controllable",
            payload=f"Tested domains: {', '.join(test_domains)}",
            expected="Different destinations produce different responses",
            actual=f"Destination {'controllable' if destination_controllable else 'not controllable'}",
            success=destination_controllable,
            confidence=ConfidenceLevel.MEDIUM if destination_controllable else ConfidenceLevel.LOW,
            next_action="Proceed to step 3: Test for blind interaction" if destination_controllable
                       else "Destination may be hardcoded or filtered",
            evidence={
                "test_domains": test_domains,
                "responses": [
                    {
                        "domain": r["domain"],
                        "status": r["status"],
                        "contains_domain": r["contains_domain"]
                    }
                    for r in responses
                ],
                "destination_controllable": destination_controllable
            }
        )
        
        self.results.append(result)
        return result
    
    def _check_destination_control(self, responses: list[dict]) -> bool:
        """Check if destination is controllable based on responses"""
        # Check if responses differ
        unique_responses = set(r["response"] for r in responses)
        
        # Check if each domain appears in its respective response
        domain_reflection = sum(1 for r in responses if r["contains_domain"])
        
        return len(unique_responses) > 1 or domain_reflection >= 2
    
    def step3_test_blind_interaction(self, collaborator_url: Optional[str] = None) -> TestResult:
        """
        Step 3: Test for blind SSRF using out-of-band interaction.
        Similar to Burp Collaborator approach.
        
        Args:
            collaborator_url: Optional URL of controlled server for interaction testing
            
        Returns:
            TestResult with blind interaction test outcome
        """
        if not collaborator_url:
            # Use a placeholder - in real testing, this would be a Burp Collaborator
            # or similar service that logs requests
            collaborator_url = f"http://test.{self.controlled_domain}/unique-id-12345"
        
        # Send request with collaborator URL
        response, status_code = self.test_function(collaborator_url)
        
        # In a real scenario, you would check the collaborator server logs
        # For this implementation, we check for indicators in the response
        blind_interaction = self._check_blind_indicators(response, status_code)
        
        if blind_interaction:
            self.ssrf_type = SSRFType.BLIND
        
        result = TestResult(
            step=3,
            description="Test for blind interaction (Burp Collaborator style)",
            payload=collaborator_url,
            expected="Server makes request to controlled endpoint",
            actual=f"Blind interaction {'detected' if blind_interaction else 'not detected'}",
            success=blind_interaction,
            confidence=ConfidenceLevel.MEDIUM if blind_interaction else ConfidenceLevel.LOW,
            next_action="Proceed to step 4: Test for response disclosure" if blind_interaction
                       else "Check collaborator logs manually for delayed interactions",
            evidence={
                "collaborator_url": collaborator_url,
                "status_code": status_code,
                "response_indicators": blind_interaction,
                "note": "In real testing, check collaborator server logs for incoming requests"
            }
        )
        
        self.results.append(result)
        return result
    
    def _check_blind_indicators(self, response: str, status_code: int) -> bool:
        """Check for indicators of blind SSRF"""
        # Indicators that server attempted the request
        indicators = [
            status_code in [200, 204],  # Successful status
            len(response) >= 0,  # Any response (even empty)
            "success" in response.lower(),
            "fetched" in response.lower(),
            "loaded" in response.lower(),
        ]
        
        return any(indicators)
    
    def step4_test_response_disclosure(self) -> TestResult:
        """
        Step 4: Test for response content disclosure.
        
        Returns:
            TestResult with response disclosure test outcome
        """
        # Test with a URL that would return distinctive content
        test_url = f"http://{self.controlled_domain}/test-content-marker-12345"
        
        response, status_code = self.test_function(test_url)
        
        # Check if response contains content from the fetched URL
        # Look for distinctive markers that would indicate content disclosure
        response_disclosed = self._check_response_disclosure(response, test_url)
        
        if response_disclosed:
            self.ssrf_type = SSRFType.FULL_RESPONSE
        elif self.ssrf_type == SSRFType.BLIND:
            pass  # Already set to BLIND
        else:
            self.ssrf_type = SSRFType.PARTIAL
        
        confidence = ConfidenceLevel.CONFIRMED if response_disclosed else \
                    (ConfidenceLevel.HIGH if self.ssrf_type == SSRFType.BLIND else ConfidenceLevel.MEDIUM)
        
        result = TestResult(
            step=4,
            description="Test for response disclosure",
            payload=test_url,
            expected="Response content from target URL disclosed",
            actual=f"Response {'disclosed' if response_disclosed else 'not disclosed'}",
            success=response_disclosed,
            confidence=confidence,
            next_action="Full SSRF with response disclosure confirmed" if response_disclosed
                       else f"SSRF type: {self.ssrf_type.value if self.ssrf_type else 'unknown'}",
            evidence={
                "test_url": test_url,
                "status_code": status_code,
                "response_length": len(response),
                "response_disclosed": response_disclosed,
                "ssrf_type": self.ssrf_type.value if self.ssrf_type else "unknown"
            }
        )
        
        self.results.append(result)
        return result
    
    def _check_response_disclosure(self, response: str, test_url: str) -> bool:
        """Check if response contains fetched content"""
        # Look for indicators that external content was included
        disclosure_patterns = [
            r"<!DOCTYPE html",  # HTML content
            r"<html",
            r"<body",
            r"content-type",
            test_url.split("/")[-1],  # URL marker
            r"HTTP/\d\.\d",  # HTTP response headers
        ]
        
        for pattern in disclosure_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        
        # Check if response is significantly larger (suggesting content inclusion)
        return len(response) > 1000
    
    def execute(self) -> dict[str, Any]:
        """
        Execute the full SSRF decision tree.
        
        Returns:
            Summary of all test results and final verdict
        """
        # Step 1: Test external fetch
        step1 = self.step1_test_external_fetch()
        if not step1.success:
            return self._generate_summary(ConfidenceLevel.NONE,
                                         "Application does not fetch external resources")
        
        # Step 2: Test destination control
        step2 = self.step2_test_destination_control()
        if not step2.success:
            return self._generate_summary(ConfidenceLevel.LOW,
                                         "Destination URL may not be controllable")
        
        # Step 3: Test blind interaction
        step3 = self.step3_test_blind_interaction()
        
        # Step 4: Test response disclosure
        step4 = self.step4_test_response_disclosure()
        
        # Determine final verdict
        if step4.success:
            verdict = "SSRF with full response disclosure confirmed"
            confidence = ConfidenceLevel.CONFIRMED
        elif step3.success:
            verdict = "Blind SSRF confirmed"
            confidence = ConfidenceLevel.HIGH
        elif step2.success:
            verdict = "Potential SSRF - destination controllable"
            confidence = ConfidenceLevel.MEDIUM
        else:
            verdict = "SSRF unlikely"
            confidence = ConfidenceLevel.LOW
        
        return self._generate_summary(confidence, verdict)
    
    def _generate_summary(self, confidence: ConfidenceLevel, verdict: str) -> dict[str, Any]:
        """Generate test summary"""
        return {
            "verdict": verdict,
            "confidence": confidence.value,
            "ssrf_type": self.ssrf_type.value if self.ssrf_type else "none",
            "total_steps": len(self.results),
            "results": [
                {
                    "step": r.step,
                    "description": r.description,
                    "payload": r.payload,
                    "success": r.success,
                    "confidence": r.confidence.value,
                    "next_action": r.next_action,
                    "evidence": r.evidence
                }
                for r in self.results
            ],
            "warning": "Use only controlled endpoints for testing. Never target internal infrastructure without authorization."
        }
