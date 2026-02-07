# Quick Reference Guide - Decision Tree Modules

## Quick Start

```python
from backend.services.decision_trees import (
    XSSDecisionTree,
    SQLiDecisionTree, 
    SSRFDecisionTree,
    SSTIDecisionTree
)

# 1. Define your test function
def my_test_function(payload):
    # Send payload to target application
    response = send_request(payload)
    return response

# 2. Create decision tree instance
tree = XSSDecisionTree(my_test_function)

# 3. Execute full test
summary = tree.execute()

# 4. Check results
if summary['confidence'] in ['high', 'confirmed']:
    print(f"Vulnerability found: {summary['verdict']}")
```

## Module-Specific Signatures

### XSS Decision Tree
```python
def test_function(payload: str) -> str:
    """Returns: response body as string"""
    return response

tree = XSSDecisionTree(test_function)
summary = tree.execute()
# summary['context'] -> 'html_body', 'javascript', 'html_attribute', etc.
```

### SQLi Decision Tree
```python
def test_function(payload: str) -> tuple[str, int, float]:
    """Returns: (response, status_code, response_time)"""
    return response, status_code, response_time

tree = SQLiDecisionTree(test_function)
summary = tree.execute()
# summary['sqli_type'] -> 'error_based', 'boolean_based', 'time_based'
```

### SSRF Decision Tree
```python
def test_function(url: str) -> tuple[str, int]:
    """Returns: (response, status_code)"""
    return response, status_code

tree = SSRFDecisionTree(test_function)
summary = tree.execute()
# summary['ssrf_type'] -> 'full_response', 'blind', 'partial'
```

### SSTI Decision Tree
```python
def test_function(payload: str) -> str:
    """Returns: response body as string"""
    return response

tree = SSTIDecisionTree(test_function)
summary = tree.execute()
# summary['template_engine'] -> 'jinja2', 'twig', 'erb', etc.
```

## Step-by-Step Execution

```python
tree = XSSDecisionTree(test_function)

# Execute individual steps
step1 = tree.step1_check_reflection()
print(f"Step 1: {step1.description}")
print(f"Success: {step1.success}")
print(f"Evidence: {step1.evidence}")

if step1.success:
    step2 = tree.step2_identify_context()
    step3 = tree.step3_test_encoding()
    step4 = tree.step4_test_execution()

# Get all results
for result in tree.results:
    print(f"Step {result.step}: {result.description} - {result.confidence.value}")
```

## Common Patterns

### Pattern 1: Basic Vulnerability Check
```python
def check_xss(url, param):
    def test(payload):
        return requests.get(url, params={param: payload}).text
    
    tree = XSSDecisionTree(test)
    result = tree.execute()
    return result['confidence'] in ['high', 'confirmed']
```

### Pattern 2: Detailed Evidence Collection
```python
tree = SQLiDecisionTree(test_function)
summary = tree.execute()

for step in summary['results']:
    print(f"\n--- Step {step['step']} ---")
    print(f"Description: {step['description']}")
    print(f"Payload: {step['payload']}")
    print(f"Success: {step['success']}")
    print(f"Confidence: {step['confidence']}")
    print(f"Evidence: {json.dumps(step['evidence'], indent=2)}")
```

### Pattern 3: Conditional Testing
```python
xss_tree = XSSDecisionTree(test_function)

# Check reflection first
if xss_tree.step1_check_reflection().success:
    # Only proceed if input is reflected
    context_result = xss_tree.step2_identify_context()
    
    if context_result.evidence['context'] == 'javascript':
        # Handle JavaScript context specifically
        print("Testing JavaScript context...")
    
    summary = xss_tree.execute()
```

## Response Structure

### Summary Object
```python
{
    "verdict": str,              # Final verdict
    "confidence": str,           # Overall confidence level
    "total_steps": int,          # Number of steps executed
    "context": str,              # Vulnerability-specific context
    "results": [TestResult],     # Array of step results
}
```

### TestResult Object
```python
{
    "step": int,                 # Step number
    "description": str,          # What this step tests
    "payload": str,              # Payload used
    "expected": str,             # Expected outcome
    "actual": str,               # Actual outcome
    "success": bool,             # Whether test succeeded
    "confidence": str,           # Confidence level
    "next_action": str,          # Recommended next step
    "evidence": dict             # Step-specific evidence
}
```

## Confidence Levels

| Level | Meaning | Action |
|-------|---------|--------|
| `none` | No vulnerability indicators | Move to next test |
| `low` | Weak indicators present | Continue testing |
| `medium` | Some indicators found | Investigate further |
| `high` | Strong indicators present | Likely vulnerable |
| `confirmed` | Vulnerability confirmed | Document finding |

## Integration Example

```python
from backend.services.decision_trees import (
    XSSDecisionTree,
    SQLiDecisionTree,
    SSRFDecisionTree,
    SSTIDecisionTree
)

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {}
    
    def scan_all(self, param_name):
        # XSS
        def xss_test(payload):
            return requests.get(self.target_url, params={param_name: payload}).text
        
        xss = XSSDecisionTree(xss_test)
        self.results['xss'] = xss.execute()
        
        # SQLi
        def sqli_test(payload):
            resp = requests.get(self.target_url, params={param_name: payload})
            return resp.text, resp.status_code, resp.elapsed.total_seconds()
        
        sqli = SQLiDecisionTree(sqli_test)
        self.results['sqli'] = sqli.execute()
        
        # SSRF
        def ssrf_test(url):
            resp = requests.post(self.target_url, json={"url": url})
            return resp.text, resp.status_code
        
        ssrf = SSRFDecisionTree(ssrf_test)
        self.results['ssrf'] = ssrf.execute()
        
        # SSTI
        def ssti_test(payload):
            return requests.post(self.target_url, data={"template": payload}).text
        
        ssti = SSTIDecisionTree(ssti_test)
        self.results['ssti'] = ssti.execute()
        
        return self.results
    
    def get_confirmed_vulnerabilities(self):
        confirmed = []
        for vuln_type, result in self.results.items():
            if result['confidence'] in ['high', 'confirmed']:
                confirmed.append({
                    'type': vuln_type,
                    'verdict': result['verdict'],
                    'confidence': result['confidence']
                })
        return confirmed
```

## Best Practices

1. **Always use try-except blocks**
   ```python
   try:
       result = tree.execute()
   except Exception as e:
       print(f"Testing failed: {e}")
   ```

2. **Respect rate limits**
   ```python
   import time
   tree = SQLiDecisionTree(test_function)
   for step in [tree.step1_test_query_logic, tree.step2_check_error_messages]:
       result = step()
       time.sleep(1)  # Rate limiting
   ```

3. **Log all test activity**
   ```python
   import logging
   logger = logging.getLogger(__name__)
   
   tree = XSSDecisionTree(test_function)
   summary = tree.execute()
   logger.info(f"XSS test completed: {summary['verdict']}")
   ```

4. **Handle timeouts**
   ```python
   import signal
   
   def timeout_handler(signum, frame):
       raise TimeoutError("Test timeout")
   
   signal.signal(signal.SIGALRM, timeout_handler)
   signal.alarm(30)  # 30 second timeout
   
   try:
       result = tree.execute()
   finally:
       signal.alarm(0)  # Cancel alarm
   ```

## Troubleshooting

### Issue: "Input not reflected"
- XSS Step 1 fails
- **Solution**: Check if parameter is actually processed by application

### Issue: "No SQLi detected"
- All SQLi tests fail
- **Solution**: Try different parameters or injection points

### Issue: "Context could not be identified"
- XSS Step 2 fails
- **Solution**: Manually inspect response to understand context

### Issue: "Template syntax not confirmed"
- SSTI Step 2 fails
- **Solution**: Try manual template syntax detection first

## Examples in Repository

See `example_usage.py` for complete working examples of all decision trees.

Run: `python3 backend/services/decision_trees/example_usage.py`
