# Decision Tree Modules for Vulnerability Testing

This directory contains decision tree modules that implement hypothesis-driven testing methodologies for common web vulnerabilities. Each module follows human security researcher reasoning patterns to systematically identify vulnerabilities through safe, minimal testing.

## Overview

The decision trees provide step-by-step guidance for vulnerability testing, returning structured results at each stage with:
- Test description
- Payload used
- Expected vs actual results
- Confidence level
- Next recommended action
- Evidence collected

## Modules

### 1. XSS Decision Tree (`xss.py`)

**Purpose**: Cross-Site Scripting vulnerability detection

**Testing Flow**:
1. **Step 1**: Check if input is reflected in response
2. **Step 2**: Identify reflection context (HTML, JavaScript, attribute, CSS, JSON, URL)
3. **Step 3**: Test context-appropriate encoding/filtering
4. **Step 4**: Test minimal payload to prove browser execution

**Usage**:
```python
from backend.services.decision_trees import XSSDecisionTree

def test_function(payload: str) -> str:
    # Your application testing logic
    return response

xss_tree = XSSDecisionTree(test_function)
summary = xss_tree.execute()

print(f"Verdict: {summary['verdict']}")
print(f"Confidence: {summary['confidence']}")
print(f"Context: {summary['context']}")
```

**Safe Payloads**: Uses minimal, safe test strings like `<test>`, `"><test>`, and `<img src=x>`

---

### 2. SQLi Decision Tree (`sqli.py`)

**Purpose**: SQL Injection vulnerability detection

**Testing Flow**:
1. **Step 1**: Test if input influences query logic (`' OR boolean`)
2. **Step 2**: Check for SQL error messages
3. **Step 3**: Test boolean-based blind SQLi
4. **Step 4**: Test time-based blind SQLi

**Usage**:
```python
from backend.services.decision_trees import SQLiDecisionTree

def test_function(payload: str) -> tuple[str, int, float]:
    # Returns (response, status_code, response_time)
    return response, status_code, response_time

sqli_tree = SQLiDecisionTree(test_function)
summary = sqli_tree.execute()

print(f"Verdict: {summary['verdict']}")
print(f"SQLi Type: {summary['sqli_type']}")
```

**Safe Testing**: 
- Uses only boolean logic tests (`'1'='1'` vs `'1'='2'`)
- Minimal time delays (2 seconds maximum)
- Never dumps data or accesses unauthorized content

---

### 3. SSRF Decision Tree (`ssrf.py`)

**Purpose**: Server-Side Request Forgery vulnerability detection

**Testing Flow**:
1. **Step 1**: Test if application fetches external resources
2. **Step 2**: Test if destination URL is controllable
3. **Step 3**: Test for blind interaction (Burp Collaborator style)
4. **Step 4**: Test for response content disclosure

**Usage**:
```python
from backend.services.decision_trees import SSRFDecisionTree

def test_function(url: str) -> tuple[str, int]:
    # Returns (response, status_code)
    return response, status_code

ssrf_tree = SSRFDecisionTree(test_function)
summary = ssrf_tree.execute()

print(f"Verdict: {summary['verdict']}")
print(f"SSRF Type: {summary['ssrf_type']}")
```

**Safe Testing**: Uses only controlled, safe domains (example.com) for testing

---

### 4. SSTI Decision Tree (`ssti.py`)

**Purpose**: Server-Side Template Injection vulnerability detection

**Testing Flow**:
1. **Step 1**: Confirm template engine via error messages
2. **Step 2**: Test engine-specific syntax (`{{7*7}}`, `${7*7}`, etc.)
3. **Step 3**: Observe behavioral changes with different inputs
4. **Step 4**: Confirm with safe mathematical expressions

**Usage**:
```python
from backend.services.decision_trees import SSTIDecisionTree

def test_function(payload: str) -> str:
    # Your application testing logic
    return response

ssti_tree = SSTIDecisionTree(test_function)
summary = ssti_tree.execute()

print(f"Verdict: {summary['verdict']}")
print(f"Template Engine: {summary['template_engine']}")
```

**Supported Template Engines**: Jinja2, Mako, Twig, Smarty, FreeMarker, Velocity, Thymeleaf, ERB, Handlebars, Pug, EJS

**Safe Testing**: Uses ONLY safe mathematical expressions - never executes commands or accesses files

---

## Common Features

### Structured Test Results

All decision trees return results in a consistent format:

```python
{
    "step": 1,
    "description": "Test description",
    "payload": "test_payload",
    "expected": "Expected outcome",
    "actual": "Actual outcome",
    "success": True/False,
    "confidence": "none|low|medium|high|confirmed",
    "next_action": "Recommended next step",
    "evidence": {
        # Step-specific evidence
    }
}
```

### Confidence Levels

- **NONE**: No indicators of vulnerability
- **LOW**: Weak indicators, needs more testing
- **MEDIUM**: Some indicators present, likely vulnerable
- **HIGH**: Strong indicators, very likely vulnerable
- **CONFIRMED**: Vulnerability confirmed with high certainty

### Execution Summary

The `execute()` method returns a comprehensive summary:

```python
{
    "verdict": "Vulnerability status",
    "confidence": "Overall confidence level",
    "total_steps": 4,
    "context": "Vulnerability context (varies by type)",
    "results": [
        # Array of all step results
    ]
}
```

---

## Step-by-Step Execution

For more control, you can execute individual steps:

```python
xss_tree = XSSDecisionTree(test_function)

# Execute individual steps
step1 = xss_tree.step1_check_reflection()
if step1.success:
    step2 = xss_tree.step2_identify_context()
    if step2.success:
        step3 = xss_tree.step3_test_encoding()
        step4 = xss_tree.step4_test_execution()

# Generate final summary
summary = xss_tree._generate_summary(
    step4.confidence if step4 else ConfidenceLevel.NONE,
    "Custom verdict"
)
```

---

## Example Usage

Run the example script to see all decision trees in action:

```bash
python3 backend/services/decision_trees/example_usage.py
```

This demonstrates:
- Complete execution of all four decision trees
- Step-by-step execution example
- Mock vulnerable applications
- Expected output formats

---

## Safety Guidelines

### ✅ DO:
- Use minimal, safe test payloads
- Test against authorized targets only
- Follow responsible disclosure practices
- Document all findings thoroughly
- Use controlled test domains

### ❌ DON'T:
- Execute arbitrary code or commands
- Dump sensitive data
- Access unauthorized resources
- Use destructive payloads
- Test production systems without permission

---

## Integration

These decision trees are designed to integrate with the bug hunting framework's:
- **Baseline Engine**: Compare test results against baseline behavior
- **Confidence Scorer**: Aggregate confidence scores across tests
- **Report Generator**: Include structured test results in reports
- **Correlation Engine**: Link related vulnerability indicators

---

## Type Hints

All modules use Python 3.10+ type hints for better IDE support and type checking:

```python
from typing import Callable, Any

def __init__(self, test_function: Callable[[str], str]) -> None:
    ...
```

---

## Dependencies

No external dependencies required - uses only Python standard library:
- `dataclasses` - For structured data
- `enum` - For enumeration types
- `typing` - For type hints
- `re` - For pattern matching
- `time` - For timing measurements (SQLi only)

---

## Contributing

When adding new decision tree modules:

1. Follow the existing structure (4 steps minimum)
2. Use safe, minimal payloads only
3. Provide clear evidence at each step
4. Return structured TestResult objects
5. Implement an `execute()` method
6. Include comprehensive docstrings
7. Add examples to `example_usage.py`

---

## License

Part of the Bug Hunting Framework - follow project license terms.
