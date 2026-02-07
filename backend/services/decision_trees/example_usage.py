#!/usr/bin/env python3
"""
Example usage of decision tree modules for vulnerability testing.
This demonstrates how to use each decision tree with mock test functions.
"""

import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from backend.services.decision_trees import (
    XSSDecisionTree,
    SQLiDecisionTree,
    SSRFDecisionTree,
    SSTIDecisionTree
)


def demonstrate_xss():
    """Demonstrate XSS decision tree usage"""
    print("\n" + "="*60)
    print("XSS Decision Tree Demonstration")
    print("="*60)
    
    # Mock test function that simulates a vulnerable endpoint
    def test_xss_vulnerable(payload: str) -> str:
        # Simulates a vulnerable application that reflects input without encoding
        return f'<html><body><div>Hello {payload}!</div></body></html>'
    
    # Create and execute decision tree
    xss_tree = XSSDecisionTree(test_xss_vulnerable)
    summary = xss_tree.execute()
    
    print(json.dumps(summary, indent=2))
    print(f"\nVerdict: {summary['verdict']}")
    print(f"Confidence: {summary['confidence']}")
    print(f"Context: {summary['context']}")


def demonstrate_sqli():
    """Demonstrate SQLi decision tree usage"""
    print("\n" + "="*60)
    print("SQLi Decision Tree Demonstration")
    print("="*60)
    
    # Mock test function that simulates a vulnerable endpoint
    def test_sqli_vulnerable(payload: str) -> tuple[str, int, float]:
        # Simulates boolean-based SQLi vulnerability
        if "1' OR '1'='1" in payload:
            response = "User found: admin, user1, user2"
            status = 200
        elif "1' OR '1'='2" in payload:
            response = "No users found"
            status = 200
        else:
            response = f"Searching for: {payload}"
            status = 200
        
        return (response, status, 0.05)
    
    # Create and execute decision tree
    sqli_tree = SQLiDecisionTree(test_sqli_vulnerable)
    summary = sqli_tree.execute()
    
    print(json.dumps(summary, indent=2))
    print(f"\nVerdict: {summary['verdict']}")
    print(f"Confidence: {summary['confidence']}")
    print(f"SQLi Type: {summary['sqli_type']}")


def demonstrate_ssrf():
    """Demonstrate SSRF decision tree usage"""
    print("\n" + "="*60)
    print("SSRF Decision Tree Demonstration")
    print("="*60)
    
    # Mock test function that simulates a vulnerable endpoint
    def test_ssrf_vulnerable(url: str) -> tuple[str, int]:
        # Simulates SSRF with response disclosure
        if "example.com" in url:
            response = f"<!DOCTYPE html><html><body>Content from {url}</body></html>"
            status = 200
        else:
            response = "Invalid URL"
            status = 400
        
        return (response, status)
    
    # Create and execute decision tree
    ssrf_tree = SSRFDecisionTree(test_ssrf_vulnerable)
    summary = ssrf_tree.execute()
    
    print(json.dumps(summary, indent=2))
    print(f"\nVerdict: {summary['verdict']}")
    print(f"Confidence: {summary['confidence']}")
    print(f"SSRF Type: {summary['ssrf_type']}")


def demonstrate_ssti():
    """Demonstrate SSTI decision tree usage"""
    print("\n" + "="*60)
    print("SSTI Decision Tree Demonstration")
    print("="*60)
    
    # Mock test function that simulates a vulnerable endpoint
    def test_ssti_vulnerable(payload: str) -> str:
        # Simulates Jinja2 SSTI vulnerability
        import re
        
        # Simple evaluation of mathematical expressions for demo
        if "{{7*7}}" in payload:
            return payload.replace("{{7*7}}", "49")
        elif "{{8*8}}" in payload:
            return payload.replace("{{8*8}}", "64")
        elif "{{6+6}}" in payload:
            return payload.replace("{{6+6}}", "12")
        elif "{{10-3}}" in payload:
            return payload.replace("{{10-3}}", "7")
        elif "{{(7*7)+(8*8)}}" in payload:
            return payload.replace("{{(7*7)+(8*8)}}", "113")
        elif "{{" in payload:
            return f"Template: {payload}"
        
        return f"Welcome {payload}"
    
    # Create and execute decision tree
    ssti_tree = SSTIDecisionTree(test_ssti_vulnerable)
    summary = ssti_tree.execute()
    
    print(json.dumps(summary, indent=2))
    print(f"\nVerdict: {summary['verdict']}")
    print(f"Confidence: {summary['confidence']}")
    print(f"Template Engine: {summary['template_engine']}")


def demonstrate_step_by_step():
    """Demonstrate step-by-step execution of XSS decision tree"""
    print("\n" + "="*60)
    print("Step-by-Step XSS Decision Tree Execution")
    print("="*60)
    
    def test_function(payload: str) -> str:
        return f'<div class="output">{payload}</div>'
    
    xss_tree = XSSDecisionTree(test_function)
    
    # Step 1
    print("\n--- Step 1: Check Reflection ---")
    step1 = xss_tree.step1_check_reflection()
    print(f"Payload: {step1.payload}")
    print(f"Result: {step1.actual}")
    print(f"Success: {step1.success}")
    print(f"Next Action: {step1.next_action}")
    
    if step1.success:
        # Step 2
        print("\n--- Step 2: Identify Context ---")
        step2 = xss_tree.step2_identify_context()
        print(f"Payload: {step2.payload}")
        print(f"Result: {step2.actual}")
        print(f"Context: {step2.evidence['context']}")
        print(f"Next Action: {step2.next_action}")
        
        # Step 3
        print("\n--- Step 3: Test Encoding ---")
        step3 = xss_tree.step3_test_encoding()
        print(f"Payload: {step3.payload}")
        print(f"Result: {step3.actual}")
        print(f"Next Action: {step3.next_action}")
        
        # Step 4
        print("\n--- Step 4: Test Execution ---")
        step4 = xss_tree.step4_test_execution()
        print(f"Payload: {step4.payload}")
        print(f"Result: {step4.actual}")
        print(f"Confidence: {step4.confidence.value}")


if __name__ == "__main__":
    print("Decision Tree Vulnerability Testing Framework")
    print("Safe, hypothesis-driven testing demonstrations")
    
    # Run demonstrations
    demonstrate_xss()
    demonstrate_sqli()
    demonstrate_ssrf()
    demonstrate_ssti()
    demonstrate_step_by_step()
    
    print("\n" + "="*60)
    print("All demonstrations completed successfully!")
    print("="*60)
