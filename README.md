
Security Review Automation

AI-powered automated security code review using Large Language Models (LLMs). Integrates with Git workflows to catch vulnerabilities before they reach production.

[![CI/CD](https://github.com/Alisid07/security-review-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/Alisid07/security-review-automation/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **Multi-Provider LLM Support**: OpenAI GPT-4 & Anthropic Claude for redundant analysis
- **Git Integration**: Automatically review staged changes pre-commit
- **CI/CD Ready**: GitHub Actions workflow for automated scanning
- **Structured Output**: JSON reports with severity classification
- **Policy Gates**: Configurable failure thresholds for pipelines

## 📋 Security Checks

| Category | Description |
|----------|-------------|
| SQL Injection | Detects unsafe query construction |
| XSS | Identifies cross-site scripting vectors |
| Secrets | Finds hardcoded credentials/tokens |
| Deserialization | Flags unsafe pickle/yaml loads |
| Path Traversal | Prevents directory escape attacks |
| Code Execution | Blocks unsafe eval/exec usage |
| Cryptography | Warns on weak algorithms |

## 🛠️ Installation

```bash
git clone https://github.com/Alisid07/security-review-automation.git
cd security-review-automation
pip install -e .
