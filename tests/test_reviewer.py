"""Unit tests for Security Reviewer"""

import pytest
from security_reviewer.reviewer import SecurityReviewer, Severity, SecurityFinding


class TestSecurityReviewer:
    def test_parse_findings_valid_json(self):
        reviewer = SecurityReviewer(openai_key="test", anthropic_key="test")
        response = '''[{"line": 10, "severity": "high", "category": "sql_injection", 
                     "description": "Unsafe query", "recommendation": "Use parameterized queries", "confidence": 0.95}]'''
        
        findings = reviewer._parse_findings(response, "test.py")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_generate_report_empty(self):
        reviewer = SecurityReviewer(openai_key="test", anthropic_key="test")
        report = reviewer.generate_report([])
        assert report["summary"]["total_findings"] == 0
