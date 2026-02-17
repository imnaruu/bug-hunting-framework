"""
SSTI Decision Tree Module
Implements hypothesis-driven testing methodology for Server-Side Template Injection vulnerabilities.
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


class TemplateEngine(Enum):
    """Detected template engines"""
    JINJA2 = "jinja2"  # Python
    MAKO = "mako"  # Python
    TORNADO = "tornado"  # Python
    TWIG = "twig"  # PHP
    SMARTY = "smarty"  # PHP
    FREEMARKER = "freemarker"  # Java
    VELOCITY = "velocity"  # Java
    THYMELEAF = "thymeleaf"  # Java
    ERB = "erb"  # Ruby
    HANDLEBARS = "handlebars"  # JavaScript
    MUSTACHE = "mustache"  # JavaScript
    PUG = "pug"  # JavaScript
    EJS = "ejs"  # JavaScript
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


class SSTIDecisionTree:
    """
    SSTI vulnerability testing decision tree.
    Follows human security researcher reasoning patterns.
    Uses only safe mathematical expressions - never executes commands.
    """
    
    def __init__(self, test_function: Callable[[str], str]):
        """
        Initialize SSTI decision tree.
        
        Args:
            test_function: Function that takes payload and returns response
        """
        self.test_function = test_function
        self.results: list[TestResult] = []
        self.template_engine: Optional[TemplateEngine] = None
        
    def step1_confirm_template_engine(self) -> TestResult:
        """
        Step 1: Confirm template engine via error messages.
        
        Returns:
            TestResult with template engine detection outcome
        """
        # Test payloads designed to trigger template engine errors
        error_payloads = [
            "{{",
            "{%",
            "${",
            "<%",
            "#{",
            "[[",
        ]
        
        detected_engines = []
        
        for payload in error_payloads:
            response = self.test_function(payload)
            
            # Check for template engine error patterns
            engine = self._detect_engine_from_error(response)
            if engine != TemplateEngine.UNKNOWN:
                detected_engines.append({
                    "payload": payload,
                    "engine": engine.value,
                    "evidence": self._extract_error_snippet(response)
                })
        
        if detected_engines:
            # Use the most specific detection
            self.template_engine = TemplateEngine(detected_engines[0]["engine"])
        
        has_detection = len(detected_engines) > 0
        
        result = TestResult(
            step=1,
            description="Confirm template engine via error messages",
            payload=", ".join(error_payloads),
            expected="Template engine identified from error messages",
            actual=f"{'Engine detected: ' + self.template_engine.value if has_detection else 'No engine detected'}",
            success=has_detection,
            confidence=ConfidenceLevel.MEDIUM if has_detection else ConfidenceLevel.NONE,
            next_action="Proceed to step 2: Test engine-specific syntax" if has_detection
                       else "Try alternative detection methods",
            evidence={
                "detected_engines": detected_engines,
                "count": len(detected_engines)
            }
        )
        
        self.results.append(result)
        return result
    
    def _detect_engine_from_error(self, response: str) -> TemplateEngine:
        """Detect template engine from error messages"""
        error_patterns = {
            TemplateEngine.JINJA2: [
                r"jinja2\.",
                r"TemplateSyntaxError",
                r"jinja2\.exceptions",
            ],
            TemplateEngine.MAKO: [
                r"mako\.",
                r"MakoException",
                r"mako\.template",
            ],
            TemplateEngine.TWIG: [
                r"Twig_Error",
                r"Twig\\",
                r"Twig_Template",
            ],
            TemplateEngine.SMARTY: [
                r"Smarty_",
                r"Smarty::",
                r"smarty\.class",
            ],
            TemplateEngine.FREEMARKER: [
                r"freemarker\.",
                r"FreeMarker",
                r"TemplateException",
            ],
            TemplateEngine.VELOCITY: [
                r"velocity",
                r"VelocityEngine",
                r"org\.apache\.velocity",
            ],
            TemplateEngine.THYMELEAF: [
                r"thymeleaf",
                r"TemplateProcessingException",
                r"org\.thymeleaf",
            ],
            TemplateEngine.ERB: [
                r"erb",
                r"ActionView",
                r"SyntaxError.*erb",
            ],
            TemplateEngine.HANDLEBARS: [
                r"handlebars",
                r"Handlebars\.compile",
            ],
            TemplateEngine.PUG: [
                r"pug",
                r"jade",
                r"pug:compile",
            ],
            TemplateEngine.EJS: [
                r"ejs",
                r"ejs:compile",
            ],
        }
        
        for engine, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return engine
        
        return TemplateEngine.UNKNOWN
    
    def _extract_error_snippet(self, response: str) -> str:
        """Extract error snippet from response"""
        # Look for common error indicators
        error_markers = ["error", "exception", "syntax", "template"]
        
        for marker in error_markers:
            idx = response.lower().find(marker)
            if idx != -1:
                start = max(0, idx - 30)
                end = min(len(response), idx + 100)
                return response[start:end]
        
        return response[:200] if len(response) > 200 else response
    
    def step2_test_engine_syntax(self) -> TestResult:
        """
        Step 2: Test engine-specific syntax with safe expressions.
        
        Returns:
            TestResult with syntax test outcome
        """
        if not self.template_engine:
            # Try generic payloads if engine not detected
            self.template_engine = TemplateEngine.UNKNOWN
        
        # Get engine-specific test payloads
        test_payloads = self._get_syntax_payloads(self.template_engine)
        
        syntax_works = False
        successful_payload = None
        
        for payload_info in test_payloads:
            payload = payload_info["payload"]
            expected_result = payload_info["expected"]
            
            response = self.test_function(payload)
            
            # Check if expected result appears in response
            if expected_result in response:
                syntax_works = True
                successful_payload = payload_info
                break
        
        result = TestResult(
            step=2,
            description=f"Test {self.template_engine.value} syntax",
            payload=f"Tested {len(test_payloads)} engine-specific payloads",
            expected="Mathematical expression evaluated correctly",
            actual=f"Syntax {'works' if syntax_works else 'does not work'} - "
                   f"{successful_payload['expected'] if successful_payload else 'no match'}",
            success=syntax_works,
            confidence=ConfidenceLevel.HIGH if syntax_works else ConfidenceLevel.LOW,
            next_action="Proceed to step 3: Observe behavioral changes" if syntax_works
                       else "Try alternative template engines or payloads",
            evidence={
                "engine": self.template_engine.value,
                "successful_payload": successful_payload,
                "tested_count": len(test_payloads)
            }
        )
        
        self.results.append(result)
        return result
    
    def _get_syntax_payloads(self, engine: TemplateEngine) -> list[dict[str, str]]:
        """Get engine-specific test payloads"""
        payloads_by_engine = {
            TemplateEngine.JINJA2: [
                {"payload": "{{7*7}}", "expected": "49"},
                {"payload": "{{7*'7'}}", "expected": "7777777"},
            ],
            TemplateEngine.MAKO: [
                {"payload": "${7*7}", "expected": "49"},
                {"payload": "${7*7}", "expected": "49"},
            ],
            TemplateEngine.TWIG: [
                {"payload": "{{7*7}}", "expected": "49"},
                {"payload": "{{7*'7'}}", "expected": "7777777"},
            ],
            TemplateEngine.SMARTY: [
                {"payload": "{7*7}", "expected": "49"},
                {"payload": "{$smarty.version}", "expected": "Smarty"},
            ],
            TemplateEngine.FREEMARKER: [
                {"payload": "${7*7}", "expected": "49"},
                {"payload": "#{7*7}", "expected": "49"},
            ],
            TemplateEngine.VELOCITY: [
                {"payload": "#set($x=7*7)$x", "expected": "49"},
            ],
            TemplateEngine.THYMELEAF: [
                {"payload": "[[${7*7}]]", "expected": "49"},
            ],
            TemplateEngine.ERB: [
                {"payload": "<%=7*7%>", "expected": "49"},
            ],
            TemplateEngine.HANDLEBARS: [
                {"payload": "{{7*7}}", "expected": "49"},
            ],
            TemplateEngine.PUG: [
                {"payload": "#{7*7}", "expected": "49"},
            ],
            TemplateEngine.EJS: [
                {"payload": "<%=7*7%>", "expected": "49"},
            ],
            TemplateEngine.UNKNOWN: [
                {"payload": "{{7*7}}", "expected": "49"},
                {"payload": "${7*7}", "expected": "49"},
                {"payload": "<%=7*7%>", "expected": "49"},
                {"payload": "#{7*7}", "expected": "49"},
            ],
        }
        
        return payloads_by_engine.get(engine, payloads_by_engine[TemplateEngine.UNKNOWN])
    
    def step3_observe_behavioral_changes(self) -> TestResult:
        """
        Step 3: Observe behavioral changes with different inputs.
        
        Returns:
            TestResult with behavioral observation outcome
        """
        # Test multiple mathematical expressions to observe consistent behavior
        test_cases = [
            {"payload": self._get_payload_for_engine("7*7"), "expected": "49"},
            {"payload": self._get_payload_for_engine("8*8"), "expected": "64"},
            {"payload": self._get_payload_for_engine("6+6"), "expected": "12"},
            {"payload": self._get_payload_for_engine("10-3"), "expected": "7"},
        ]
        
        successful_tests = []
        
        for test_case in test_cases:
            response = self.test_function(test_case["payload"])
            
            if test_case["expected"] in response:
                successful_tests.append({
                    "payload": test_case["payload"],
                    "expected": test_case["expected"],
                    "found": True
                })
        
        consistent_behavior = len(successful_tests) >= 3  # At least 3 out of 4
        
        result = TestResult(
            step=3,
            description="Observe behavioral changes with different inputs",
            payload=f"Tested {len(test_cases)} different expressions",
            expected="Consistent template evaluation across multiple inputs",
            actual=f"{len(successful_tests)}/{len(test_cases)} expressions evaluated correctly",
            success=consistent_behavior,
            confidence=ConfidenceLevel.HIGH if consistent_behavior else ConfidenceLevel.MEDIUM,
            next_action="Proceed to step 4: Confirm with safe expressions" if consistent_behavior
                       else "Behavioral consistency unclear - additional testing needed",
            evidence={
                "test_cases": len(test_cases),
                "successful": len(successful_tests),
                "successful_tests": successful_tests,
                "consistency": consistent_behavior
            }
        )
        
        self.results.append(result)
        return result
    
    def _get_payload_for_engine(self, expression: str) -> str:
        """Get properly formatted payload for detected engine"""
        if not self.template_engine or self.template_engine == TemplateEngine.UNKNOWN:
            return f"{{{{{expression}}}}}"  # Try Jinja2/Twig syntax
        
        syntax_map = {
            TemplateEngine.JINJA2: f"{{{{{expression}}}}}",
            TemplateEngine.MAKO: f"${{{expression}}}",
            TemplateEngine.TWIG: f"{{{{{expression}}}}}",
            TemplateEngine.SMARTY: f"{{{expression}}}",
            TemplateEngine.FREEMARKER: f"${{{expression}}}",
            TemplateEngine.VELOCITY: f"#set($x={expression})$x",
            TemplateEngine.THYMELEAF: f"[[${{{expression}}}]]",
            TemplateEngine.ERB: f"<%={expression}%>",
            TemplateEngine.HANDLEBARS: f"{{{{{expression}}}}}",
            TemplateEngine.PUG: f"#{{{expression}}}",
            TemplateEngine.EJS: f"<%={expression}%>",
        }
        
        return syntax_map.get(self.template_engine, f"{{{{{expression}}}}}")
    
    def step4_confirm_safe_execution(self) -> TestResult:
        """
        Step 4: Confirm with safe mathematical expressions only.
        Never executes commands or accesses files.
        
        Returns:
            TestResult with final confirmation
        """
        # Final confirmation with a more complex but safe expression
        complex_expression = "(7*7)+(8*8)"  # Should equal 113
        expected_result = "113"
        
        payload = self._get_payload_for_engine(complex_expression)
        response = self.test_function(payload)
        
        confirmed = expected_result in response
        
        confidence = ConfidenceLevel.CONFIRMED if confirmed else ConfidenceLevel.HIGH
        
        result = TestResult(
            step=4,
            description="Confirm SSTI with safe mathematical expression",
            payload=payload,
            expected=f"Expression evaluates to {expected_result}",
            actual=f"SSTI {'confirmed' if confirmed else 'likely'} - "
                   f"Result: {expected_result if confirmed else 'not found'}",
            success=confirmed,
            confidence=confidence,
            next_action="SSTI vulnerability confirmed - document findings" if confirmed
                       else "SSTI likely but not fully confirmed",
            evidence={
                "engine": self.template_engine.value if self.template_engine else "unknown",
                "payload": payload,
                "expected": expected_result,
                "confirmed": confirmed,
                "warning": "Never execute commands or access files in SSTI testing"
            }
        )
        
        self.results.append(result)
        return result
    
    def execute(self) -> dict[str, Any]:
        """
        Execute the full SSTI decision tree.
        
        Returns:
            Summary of all test results and final verdict
        """
        # Step 1: Confirm template engine
        step1 = self.step1_confirm_template_engine()
        
        # Step 2: Test engine syntax
        step2 = self.step2_test_engine_syntax()
        if not step2.success:
            return self._generate_summary(ConfidenceLevel.LOW,
                                         "Template syntax not confirmed")
        
        # Step 3: Observe behavioral changes
        step3 = self.step3_observe_behavioral_changes()
        if not step3.success:
            return self._generate_summary(ConfidenceLevel.MEDIUM,
                                         "Behavioral consistency unclear")
        
        # Step 4: Final confirmation
        step4 = self.step4_confirm_safe_execution()
        
        verdict = "SSTI vulnerability confirmed" if step4.success else "SSTI likely but not confirmed"
        
        return self._generate_summary(step4.confidence, verdict)
    
    def _generate_summary(self, confidence: ConfidenceLevel, verdict: str) -> dict[str, Any]:
        """Generate test summary"""
        return {
            "verdict": verdict,
            "confidence": confidence.value,
            "template_engine": self.template_engine.value if self.template_engine else "unknown",
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
            "warning": "Safe testing only - never execute commands or access files"
        }
