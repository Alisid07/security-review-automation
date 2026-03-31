#!/usr/bin/env python3
"""CLI for Security Review Automation"""

import argparse
import json
import os
import sys
from pathlib import Path
from .reviewer import SecurityReviewer, GitIntegration


def main():
    parser = argparse.ArgumentParser(description="AI Security Code Reviewer")
    parser.add_argument("--git", action="store_true", help="Review staged git changes")
    parser.add_argument("--file", type=str, help="Review specific file")
    parser.add_argument("--output", type=str, default="security_report.json", help="Output file")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], 
                       default="critical", help="Exit with error if issues found")
    
    args = parser.parse_args()
    reviewer = SecurityReviewer()
    findings = []
    
    if args.git:
        print("Analyzing staged changes...")
        git = GitIntegration()
        changes = git.get_staged_diff()
        
        for change in changes:
            if change["diff"]:
                file_findings = reviewer.analyze_diff(change["diff"], change["path"])
                findings.extend(file_findings)
                print(f"  {change['path']}: {len(file_findings)} issues")
    
    elif args.file:
        print(f"Analyzing {args.file}...")
        with open(args.file, 'r') as f:
            content = f.read()
        findings = reviewer.analyze_diff(content, args.file)
    
    else:
        parser.print_help()
        sys.exit(1)
    
    report = reviewer.generate_report(findings)
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nSecurity Review Complete")
    print(f"   Total findings: {report['summary']['total_findings']}")
    print(f"   Critical: {report['summary']['critical']}")
    print(f"   High: {report['summary']['high']}")
    print(f"   Medium: {report['summary']['medium']}")
    print(f"   Low: {report['summary']['low']}")
    print(f"\nReport saved to: {args.output}")
    
    severity_order = ["low", "medium", "high", "critical"]
    threshold_idx = severity_order.index(args.fail_on)
    
    for sev in severity_order[threshold_idx:]:
        if report['summary'][sev] > 0:
            print(f"\nFailed: {sev} severity issues found")
            sys.exit(1)
    
    print("\nAll checks passed")
    sys.exit(0)


if __name__ == "__main__":
    main()
