"""
AI-Powered Security Review Automation
"""

from dotenv import load_dotenv
load_dotenv()

import os
import json
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

import openai
from anthropic import Anthropic
from git import Repo


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityFinding:
    file_path: str
    line_number: int
    severity: Severity
    category: str
    description: str
    recommendation: str
    confidence: float


class SecurityReviewer:
    """Automated security review using multiple LLM providers"""
    
    def __init__(self, openai_key: Optional[str] = None, anthropic_key: Optional[str] = None):
        self.openai_client = openai.OpenAI(api_key=openai_key or os.getenv("OPENAI_API_KEY"))
        self.anthropic_client = Anthropic(api_key=anthropic_key or os.getenv("ANTHROPIC_API_KEY"))
        
    def analyze_diff(self, diff_content: str, file_path: str) -> List[SecurityFinding]:
        """Analyze a code diff for security issues"""
        prompt = self._build_analysis_prompt(diff_content, file_path)
        
        response = self.anthropic_client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=2000,
            temperature=0.1,
            system="You are a security expert. Analyze code for vulnerabilities. Respond in JSON format only.",
            messages=[{"role": "user", "content": prompt}]
        )
        
        return self._parse_findings(response.content[0].text, file_path)
    
    def _build_analysis_prompt(self, diff: str, path: str) -> str:
        return f"""Analyze this code diff for security vulnerabilities:

File: {path}
Diff:
{diff}

Check for: SQL injection, XSS, hardcoded secrets, insecure deserialization, path traversal, unsafe eval/exec, weak cryptography

Respond with JSON array: [{{"line": 42, "severity": "high", "category": "sql_injection", "description": "...", "recommendation": "...", "confidence": 0.95}}]

If no issues found, return empty array []."""
    
    def _parse_findings(self, response: str, file_path: str) -> List[SecurityFinding]:
        """Parse LLM response into structured findings"""
        try:
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            data = json.loads(response[json_start:json_end])
            
            findings = []
            for item in data:
                findings.append(SecurityFinding(
                    file_path=file_path,
                    line_number=item.get("line", 0),
                    severity=Severity(item.get("severity", "low")),
                    category=item.get("category", "unknown"),
                    description=item.get("description", ""),
                    recommendation=item.get("recommendation", ""),
                    confidence=item.get("confidence", 0.5)
                ))
            return findings
        except Exception as e:
            print(f"Parse error: {e}")
            return []
    
    def generate_report(self, findings: List[SecurityFinding]) -> Dict:
        """Generate structured security report"""
        return {
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
            },
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "severity": f.severity.value,
                    "category": f.category,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence
                }
                for f in findings
            ]
        }


class GitIntegration:
    """Integrate with Git repositories for automated reviews"""
    
    def __init__(self, repo_path: str = "."):
        self.repo = Repo(repo_path)
    
    def get_staged_diff(self) -> List[Dict[str, str]]:
        """Get diff of staged changes"""
        diffs = []
        for item in self.repo.index.diff("HEAD"):
            try:
                blob = item.a_blob or item.b_blob
                if blob and blob.path.endswith(('.py', '.js', '.ts', '.java', '.go')):
                    diff_text = item.diff.decode('utf-8', errors='ignore') if item.diff else ""
                    diffs.append({
                        "path": item.a_path or item.b_path,
                        "diff": diff_text
                    })
            except Exception:
                continue
        return diffs
