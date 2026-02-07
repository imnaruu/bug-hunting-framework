"""
XSS Decision Tree Module
Implements hypothesis-driven testing methodology for Cross-Site Scripting vulnerabilities.
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


class ReflectionContext(Enum):
    """Context types where input can be reflected"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"
    JSON = "json"
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


class XSSDecisionTree:
    """
    XSS vulnerability testing decision tree.
    Follows human security researcher reasoning patterns.
    """
    
    def __init__(self, test_function: Callable[[str], str]):
        """
        Initialize XSS decision tree.
        
        Args:
            test_function: Function that takes payload and returns response
        """
        self.test_function = test_function
        self.results: list[TestResult] = []
        self.reflection_context: Optional[ReflectionContext] = None
        
    def step1_check_reflection(self, marker: str = "xss_test_12345") -> TestResult:
        """
        Step 1: Check if input is reflected in response.
        
        Args:
            marker: Unique marker to test reflection
            
        Returns:
            TestResult with reflection check outcome
        """
        response = self.test_function(marker)
        reflected = marker in response
        
        result = TestResult(
            step=1,
            description="Check if input is reflected in response",
            payload=marker,
            expected="Marker appears in response",
            actual=f"Marker {'found' if reflected else 'not found'} in response",
            success=reflected,
            confidence=ConfidenceLevel.LOW if reflected else ConfidenceLevel.NONE,
            next_action="Proceed to step 2: Identify reflection context" if reflected 
                       else "Input not reflected - XSS unlikely in this parameter",
            evidence={
                "reflected": reflected,
                "marker": marker,
                "response_length": len(response)
            }
        )
        
        self.results.append(result)
        return result
    
    def step2_identify_context(self, marker: str = "xss_test_12345") -> TestResult:
        """
        Step 2: Identify the context where input is reflected.
        
        Args:
            marker: Unique marker used in step 1
            
        Returns:
            TestResult with identified context
        """
        response = self.test_function(marker)
        
        # Analyze context
        context = self._analyze_context(response, marker)
        self.reflection_context = context
        
        result = TestResult(
            step=2,
            description="Identify reflection context (HTML, JS, attribute, etc.)",
            payload=marker,
            expected="Context identified from response analysis",
            actual=f"Context identified as: {context.value}",
            success=context != ReflectionContext.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            next_action=f"Proceed to step 3: Test {context.value} encoding",
            evidence={
                "context": context.value,
                "marker": marker
            }
        )
        
        self.results.append(result)
        return result
    
    def _analyze_context(self, response: str, marker: str) -> ReflectionContext:
        """Analyze where and how the marker appears in the response"""
        if marker not in response:
            return ReflectionContext.UNKNOWN
            
        # Find marker position and surrounding context
        idx = response.find(marker)
        before = response[max(0, idx-50):idx]
        after = response[idx+len(marker):min(len(response), idx+len(marker)+50)]
        
        # Check for JavaScript context
        if re.search(r'<script[^>]*>', before, re.IGNORECASE) and \
           re.search(r'</script>', after, re.IGNORECASE):
            return ReflectionContext.JAVASCRIPT
        
        # Check for HTML attribute
        if re.search(r'<[^>]+$', before) and re.search(r'^[^<]*>', after):
            if '"' in before or "'" in before:
                return ReflectionContext.HTML_ATTRIBUTE
        
        # Check for CSS context
        if re.search(r'<style[^>]*>', before, re.IGNORECASE) and \
           re.search(r'</style>', after, re.IGNORECASE):
            return ReflectionContext.CSS
        
        # Check for JSON context
        if re.search(r'[{,]\s*"[^"]*"\s*:\s*"[^"]*$', before) and \
           re.search(r'^[^"]*"', after):
            return ReflectionContext.JSON
        
        # Default to HTML body
        return ReflectionContext.HTML_BODY
    
    def step3_test_encoding(self) -> TestResult:
        """
        Step 3: Test context-appropriate encoding/filtering.
        
        Returns:
            TestResult with encoding test outcome
        """
        if not self.reflection_context:
            raise ValueError("Must run step2_identify_context first")
        
        # Select context-appropriate test payload
        payload = self._get_encoding_test_payload(self.reflection_context)
        response = self.test_function(payload)
        
        # Check if payload is encoded/filtered
        encoded = self._check_encoding(response, payload, self.reflection_context)
        
        result = TestResult(
            step=3,
            description=f"Test {self.reflection_context.value} encoding",
            payload=payload,
            expected="Special characters properly encoded",
            actual=f"Payload {'encoded/filtered' if encoded else 'not encoded'}",
            success=not encoded,  # Success means vulnerability found
            confidence=ConfidenceLevel.MEDIUM if not encoded else ConfidenceLevel.LOW,
            next_action="Proceed to step 4: Test minimal execution payload" if not encoded
                       else "Encoding applied - try alternative context or payload",
            evidence={
                "context": self.reflection_context.value,
                "payload": payload,
                "encoded": encoded
            }
        )
        
        self.results.append(result)
        return result
    
    def _get_encoding_test_payload(self, context: ReflectionContext) -> str:
        """Get appropriate test payload for context"""
        payloads = {
            ReflectionContext.HTML_BODY: "<test>",
            ReflectionContext.HTML_ATTRIBUTE: '"><test>',
            ReflectionContext.JAVASCRIPT: "';test;'",
            ReflectionContext.CSS: "*/test/*",
            ReflectionContext.JSON: '","test":"',
            ReflectionContext.URL: "javascript:test",
            ReflectionContext.UNKNOWN: "<test>"
        }
        return payloads.get(context, "<test>")
    
    def _check_encoding(self, response: str, payload: str, context: ReflectionContext) -> bool:
        """Check if payload was encoded"""
        # Check for common encoding patterns
        if context == ReflectionContext.HTML_BODY:
            return "&lt;test&gt;" in response or "\\u003ctest\\u003e" in response
        elif context == ReflectionContext.HTML_ATTRIBUTE:
            return "&quot;&gt;&lt;" in response or payload not in response
        elif context == ReflectionContext.JAVASCRIPT:
            return "\\'" in response or "\\u0027" in response
        elif context == ReflectionContext.JSON:
            return '\\"' in response
        
        return payload not in response
    
    def step4_test_execution(self) -> TestResult:
        """
        Step 4: Test minimal payload to prove browser execution.
        Uses safe, minimal payloads only.
        
        Returns:
            TestResult with execution test outcome
        """
        if not self.reflection_context:
            raise ValueError("Must run step2_identify_context first")
        
        # Get minimal, safe execution payload
        payload = self._get_execution_payload(self.reflection_context)
        response = self.test_function(payload)
        
        # Check if payload appears unencoded (would execute in browser)
        would_execute = self._check_execution_potential(response, payload, self.reflection_context)
        
        confidence = ConfidenceLevel.CONFIRMED if would_execute else ConfidenceLevel.MEDIUM
        
        result = TestResult(
            step=4,
            description="Test minimal payload to prove browser execution",
            payload=payload,
            expected="Payload would execute in browser context",
            actual=f"Payload {'would execute' if would_execute else 'would not execute'}",
            success=would_execute,
            confidence=confidence,
            next_action="XSS confirmed - document vulnerability" if would_execute
                       else "Further testing needed with alternative payloads",
            evidence={
                "context": self.reflection_context.value,
                "payload": payload,
                "would_execute": would_execute,
                "response_snippet": response[:200] if len(response) > 200 else response
            }
        )
        
        self.results.append(result)
        return result
    
    def _get_execution_payload(self, context: ReflectionContext) -> str:
        """Get minimal, safe execution payload for context"""
        payloads = {
            ReflectionContext.HTML_BODY: "<img src=x>",
            ReflectionContext.HTML_ATTRIBUTE: '" onclick="return 1',
            ReflectionContext.JAVASCRIPT: "';var xss=1;'",
            ReflectionContext.CSS: "*/}body{background:red}/*",
            ReflectionContext.JSON: '","xss":"1"}',
            ReflectionContext.URL: "javascript:void(1)",
            ReflectionContext.UNKNOWN: "<img src=x>"
        }
        return payloads.get(context, "<img src=x>")
    
    def _check_execution_potential(self, response: str, payload: str, 
                                   context: ReflectionContext) -> bool:
        """Check if payload would execute in browser"""
        # Check if payload appears in executable form
        if context == ReflectionContext.HTML_BODY:
            return "<img" in response and "src=" in response
        elif context == ReflectionContext.HTML_ATTRIBUTE:
            return 'onclick=' in response or payload in response
        elif context == ReflectionContext.JAVASCRIPT:
            return "var xss" in response or ";'" in response
        elif context == ReflectionContext.JSON:
            return '"xss"' in response
        
        return payload in response
    
    def execute(self) -> dict[str, Any]:
        """
        Execute the full XSS decision tree.
        
        Returns:
            Summary of all test results and final verdict
        """
        # Step 1: Check reflection
        step1 = self.step1_check_reflection()
        if not step1.success:
            return self._generate_summary(ConfidenceLevel.NONE, 
                                         "Input not reflected - XSS unlikely")
        
        # Step 2: Identify context
        step2 = self.step2_identify_context()
        if not step2.success:
            return self._generate_summary(ConfidenceLevel.LOW,
                                         "Context could not be identified")
        
        # Step 3: Test encoding
        step3 = self.step3_test_encoding()
        if not step3.success:
            return self._generate_summary(ConfidenceLevel.LOW,
                                         "Encoding/filtering detected")
        
        # Step 4: Test execution
        step4 = self.step4_test_execution()
        
        final_confidence = step4.confidence
        verdict = "XSS vulnerability confirmed" if step4.success else "XSS unlikely"
        
        return self._generate_summary(final_confidence, verdict)
    
    def _generate_summary(self, confidence: ConfidenceLevel, verdict: str) -> dict[str, Any]:
        """Generate test summary"""
        return {
            "verdict": verdict,
            "confidence": confidence.value,
            "total_steps": len(self.results),
            "context": self.reflection_context.value if self.reflection_context else "unknown",
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
            ]
        }
