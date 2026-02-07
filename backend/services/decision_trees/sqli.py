"""
SQLi Decision Tree Module
Implements hypothesis-driven testing methodology for SQL Injection vulnerabilities.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, Any
import time
import re


class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability detection"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class SQLiType(Enum):
    """Types of SQL injection"""
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
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


class SQLiDecisionTree:
    """
    SQL Injection vulnerability testing decision tree.
    Follows human security researcher reasoning patterns.
    Uses minimal, safe testing only - never dumps data.
    """
    
    def __init__(self, test_function: Callable[[str], tuple[str, int, float]]):
        """
        Initialize SQLi decision tree.
        
        Args:
            test_function: Function that takes payload and returns (response, status_code, response_time)
        """
        self.test_function = test_function
        self.results: list[TestResult] = []
        self.sqli_type: Optional[SQLiType] = None
        self.baseline_response: Optional[str] = None
        self.baseline_time: Optional[float] = None
        
    def step1_test_query_logic(self) -> TestResult:
        """
        Step 1: Test if input influences query logic.
        Uses boolean-based logic tests.
        
        Returns:
            TestResult with query logic test outcome
        """
        # Get baseline response
        baseline_payload = "1"
        baseline_resp, baseline_status, baseline_time = self.test_function(baseline_payload)
        self.baseline_response = baseline_resp
        self.baseline_time = baseline_time
        
        # Test true condition: ' OR '1'='1
        true_payload = "1' OR '1'='1"
        true_resp, true_status, true_time = self.test_function(true_payload)
        
        # Test false condition: ' OR '1'='2
        false_payload = "1' OR '1'='2"
        false_resp, false_status, false_time = self.test_function(false_payload)
        
        # Check if true and false conditions produce different results
        logic_influenced = (true_resp != false_resp) or (true_status != false_status)
        
        result = TestResult(
            step=1,
            description="Test if input influences query logic",
            payload=f"True: {true_payload}, False: {false_payload}",
            expected="Different responses for true vs false conditions",
            actual=f"Responses {'differ' if logic_influenced else 'identical'}",
            success=logic_influenced,
            confidence=ConfidenceLevel.MEDIUM if logic_influenced else ConfidenceLevel.NONE,
            next_action="Proceed to step 2: Check for error messages" if logic_influenced
                       else "Input likely not influencing query logic",
            evidence={
                "baseline_length": len(baseline_resp),
                "true_length": len(true_resp),
                "false_length": len(false_resp),
                "true_status": true_status,
                "false_status": false_status,
                "logic_influenced": logic_influenced
            }
        )
        
        self.results.append(result)
        return result
    
    def step2_check_error_messages(self) -> TestResult:
        """
        Step 2: Check for SQL error messages.
        
        Returns:
            TestResult with error message detection outcome
        """
        # Test payloads that commonly trigger SQL errors
        error_payloads = [
            "'",
            "1'",
            "1\"",
            "1`",
            "1' AND '1'='1",
        ]
        
        errors_found = []
        
        for payload in error_payloads:
            resp, status, _ = self.test_function(payload)
            
            # Check for common SQL error patterns
            error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"Driver.*SQL.*Server",
                r"OLE DB.*SQL Server",
                r"SQLServer JDBC Driver",
                r"Oracle error",
                r"Oracle.*Driver",
                r"warning.*oci_.*",
                r"sqlite3.OperationalError",
                r"SQLite/JDBCDriver",
                r"System.Data.SQLite.SQLiteException",
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, resp, re.IGNORECASE):
                    errors_found.append({
                        "payload": payload,
                        "pattern": pattern,
                        "snippet": self._extract_error_snippet(resp, pattern)
                    })
                    break
        
        has_errors = len(errors_found) > 0
        
        if has_errors:
            self.sqli_type = SQLiType.ERROR_BASED
        
        result = TestResult(
            step=2,
            description="Check for SQL error messages",
            payload=", ".join(error_payloads),
            expected="SQL error messages revealed",
            actual=f"{'Error messages found' if has_errors else 'No error messages'}",
            success=has_errors,
            confidence=ConfidenceLevel.HIGH if has_errors else ConfidenceLevel.LOW,
            next_action="Error-based SQLi confirmed - document findings" if has_errors
                       else "Proceed to step 3: Test boolean-based blind SQLi",
            evidence={
                "errors_found": errors_found,
                "error_count": len(errors_found)
            }
        )
        
        self.results.append(result)
        return result
    
    def _extract_error_snippet(self, response: str, pattern: str) -> str:
        """Extract error message snippet from response"""
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(response), match.end() + 50)
            return response[start:end]
        return ""
    
    def step3_test_boolean_blind(self) -> TestResult:
        """
        Step 3: Test boolean-based blind SQL injection.
        
        Returns:
            TestResult with boolean blind test outcome
        """
        # Test with safe boolean conditions
        tests = [
            {
                "true": "1' AND '1'='1",
                "false": "1' AND '1'='2"
            },
            {
                "true": "1' AND 1=1--",
                "false": "1' AND 1=2--"
            },
            {
                "true": "1) AND (1=1",
                "false": "1) AND (1=2"
            }
        ]
        
        boolean_vuln_found = False
        successful_test = None
        
        for test in tests:
            true_resp, true_status, _ = self.test_function(test["true"])
            false_resp, false_status, _ = self.test_function(test["false"])
            
            # Check if responses differ consistently
            response_differs = (len(true_resp) != len(false_resp)) or \
                             (true_status != false_status) or \
                             (true_resp != false_resp)
            
            if response_differs:
                boolean_vuln_found = True
                successful_test = test
                self.sqli_type = SQLiType.BOOLEAN_BASED
                break
        
        result = TestResult(
            step=3,
            description="Test boolean-based blind SQLi",
            payload=f"True/False pairs tested: {len(tests)}",
            expected="Consistent difference in responses for true vs false",
            actual=f"Boolean-based SQLi {'detected' if boolean_vuln_found else 'not detected'}",
            success=boolean_vuln_found,
            confidence=ConfidenceLevel.HIGH if boolean_vuln_found else ConfidenceLevel.LOW,
            next_action="Boolean-based blind SQLi confirmed" if boolean_vuln_found
                       else "Proceed to step 4: Test time-based blind SQLi",
            evidence={
                "tests_performed": len(tests),
                "successful_test": successful_test,
                "boolean_vuln_found": boolean_vuln_found
            }
        )
        
        self.results.append(result)
        return result
    
    def step4_test_time_based(self) -> TestResult:
        """
        Step 4: Test time-based blind SQL injection.
        Uses minimal delays (2-3 seconds) for safe testing.
        
        Returns:
            TestResult with time-based test outcome
        """
        # Get baseline timing (average of 3 requests)
        baseline_times = []
        for _ in range(3):
            _, _, resp_time = self.test_function("1")
            baseline_times.append(resp_time)
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test payloads with small delays (2 seconds)
        delay_payloads = [
            "1' AND SLEEP(2)--",  # MySQL
            "1' AND pg_sleep(2)--",  # PostgreSQL
            "1' WAITFOR DELAY '0:0:2'--",  # SQL Server
            "1' AND DBMS_LOCK.SLEEP(2)--",  # Oracle (would need privileges)
        ]
        
        time_based_vuln = False
        successful_payload = None
        measured_delay = 0
        
        for payload in delay_payloads:
            start_time = time.time()
            _, _, resp_time = self.test_function(payload)
            actual_delay = time.time() - start_time
            
            # Check if response took significantly longer (at least 1.5 seconds more)
            if actual_delay > (avg_baseline + 1.5):
                time_based_vuln = True
                successful_payload = payload
                measured_delay = actual_delay - avg_baseline
                self.sqli_type = SQLiType.TIME_BASED
                break
        
        result = TestResult(
            step=4,
            description="Test time-based blind SQLi",
            payload=f"Delay payloads tested: {len(delay_payloads)}",
            expected="Response delayed by ~2 seconds",
            actual=f"{'Delay detected' if time_based_vuln else 'No significant delay'} "
                   f"(+{measured_delay:.2f}s)" if time_based_vuln else "(normal timing)",
            success=time_based_vuln,
            confidence=ConfidenceLevel.CONFIRMED if time_based_vuln else ConfidenceLevel.NONE,
            next_action="Time-based blind SQLi confirmed" if time_based_vuln
                       else "No SQLi detected with current tests",
            evidence={
                "baseline_avg": avg_baseline,
                "baseline_times": baseline_times,
                "successful_payload": successful_payload,
                "measured_delay": measured_delay,
                "time_based_vuln": time_based_vuln
            }
        )
        
        self.results.append(result)
        return result
    
    def execute(self) -> dict[str, Any]:
        """
        Execute the full SQLi decision tree.
        
        Returns:
            Summary of all test results and final verdict
        """
        # Step 1: Test query logic
        step1 = self.step1_test_query_logic()
        
        # Step 2: Check for errors
        step2 = self.step2_check_error_messages()
        if step2.success:
            return self._generate_summary(ConfidenceLevel.HIGH,
                                         "Error-based SQLi confirmed")
        
        # Step 3: Boolean-based blind
        if step1.success:
            step3 = self.step3_test_boolean_blind()
            if step3.success:
                return self._generate_summary(ConfidenceLevel.HIGH,
                                             "Boolean-based blind SQLi confirmed")
        
        # Step 4: Time-based blind
        step4 = self.step4_test_time_based()
        if step4.success:
            return self._generate_summary(ConfidenceLevel.CONFIRMED,
                                         "Time-based blind SQLi confirmed")
        
        # No vulnerability found
        final_confidence = ConfidenceLevel.LOW if step1.success else ConfidenceLevel.NONE
        return self._generate_summary(final_confidence, "No SQLi detected")
    
    def _generate_summary(self, confidence: ConfidenceLevel, verdict: str) -> dict[str, Any]:
        """Generate test summary"""
        return {
            "verdict": verdict,
            "confidence": confidence.value,
            "sqli_type": self.sqli_type.value if self.sqli_type else "none",
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
            "warning": "This is a safe, minimal test. Never dump data or access unauthorized content."
        }
