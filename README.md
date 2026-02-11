# pii-guard

**Context-aware PII detection for LLM pipelines and data workflows**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A CLI tool that detects personally identifiable information (PII) in text, code, logs, and data files using context-aware pattern matching and statistical scoring. Unlike simple regex scanners, pii-guard analyzes surrounding context to reduce false positives, supports 18 PII types, and provides masked/redacted output formats.

## Why pii-guard?

- **Context-aware detection**: Analyzes surrounding text to reduce false positives compared to regex-only tools
- **Zero external dependencies**: Runs entirely locally with no API calls - fast and privacy-preserving
- **Built for developers**: Integrates into CI/CD pipelines, pre-commit hooks, and LLM preprocessing
- **Comprehensive coverage**: Detects 18 PII pattern types including SSNs, credit cards, API keys, emails, phone numbers, and more

## Installation

```bash
pip install pii-guard
```

## Quick Start

Scan a file for PII:

```bash
pii-guard scan input.txt
```

Output:
```
Scanning: input.txt

[Line 12] EMAIL (confidence: 95)
  john.doe@example.com
  Context: "Contact me at john.doe@example.com for"

[Line 23] SSN (confidence: 87)
  123-45-6789
  Context: "SSN: 123-45-6789 was"

Summary: 2 PII instances found in 1 file
```

Mask PII and save to a new file:

```bash
pii-guard scan --mask partial --output clean.txt input.txt
```

Process stdin for pipeline integration:

```bash
echo 'Email: alice@company.com, SSN: 123-45-6789' | pii-guard scan --stdin --mask full
```

Output:
```
Email: [EMAIL_REDACTED], SSN: [SSN_REDACTED]
```

Scan a directory with JSON output for CI/CD:

```bash
pii-guard scan --format json --threshold 80 ./logs/
```

List all supported PII patterns:

```bash
pii-guard patterns --list
```

## Features

- **18 PII pattern types**: SSNs, credit cards, emails, phone numbers, passports, API keys (AWS, OpenAI, Stripe, GitHub), IBANs, medical IDs, and more
- **Multiple masking strategies**: Full redaction, partial masking (`***-**-1234`), or hash replacement
- **Fast processing**: Uses compiled regex patterns for efficient scanning
- **Multiple output formats**: Human-readable text, JSON, or masked output files
- **Configurable thresholds**: Balance precision/recall with adjustable confidence scores (0-100)
- **CI/CD integration**: Returns non-zero exit codes when PII detected, enabling automated pipeline failures
- **Custom patterns**: Load organization-specific patterns from YAML config files

## Usage Examples

### Scan with custom threshold

```bash
pii-guard scan --threshold 90 sensitive_data.txt
```

### Batch processing

```bash
pii-guard scan --format json ./logs/ > pii_report.json
```

### Pre-commit hook integration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pii-guard
        name: PII Detection
        entry: pii-guard scan --format json --threshold 70
        language: system
        pass_filenames: true
```

### GitHub Actions

```yaml
- name: Scan for PII
  run: |
    pip install pii-guard
    pii-guard scan --format json --threshold 80 ./src/
```

## Supported PII Types

- **Identification**: SSN, Passport, Driver's License, National ID
- **Financial**: Credit Cards, IBAN, Routing Numbers, SWIFT/BIC
- **Contact**: Email, Phone Numbers, IP Addresses
- **Credentials**: API Keys, Password Hashes, JWTs
- **Medical**: Medical Record Numbers, NPI, DEA Numbers
- **Personal**: DOB, Addresses, ZIP Codes

## Configuration

Create a `pii-guard.yaml` file:

```yaml
threshold: 70
masking_strategy: partial
enabled_patterns:
  - EMAIL
  - SSN
  - CREDIT_CARD
  - API_KEY
custom_patterns:
  - name: EMPLOYEE_ID
    pattern: 'EMP-\d{6}'
    confidence: 85
```

## How It Works

pii-guard uses a multi-stage detection pipeline:

1. **Pattern tokenizer**: Splits input into semantic chunks
2. **Regex matcher**: Identifies 18 PII pattern types
3. **Context analyzer**: Examines surrounding text windows before/after matches
4. **Validators**: Applies Luhn algorithm, checksums, and format validation
5. **Statistical scorer**: Combines pattern + context + validation confidence
6. **Threshold filter**: Configurable cutoff to balance precision/recall
7. **Output formatter**: Applies masking strategies while preserving structure

## Comparison to Alternatives

| Tool | Setup | False Positives | Privacy |
|------|-------|-----------------|---------|
| **pii-guard** | `pip install` | Low (context-aware) | 100% local |
| Presidio | Complex (models + APIs) | Medium | Requires external calls |
| scrubadub | `pip install` | High (regex only) | 100% local |
| Enterprise DLP | Hours of config | Low | SaaS/cloud-based |

## License

MIT License - Copyright (c) 2026 Intellirim

## Contributing

Issues and pull requests welcome! This is an open-source project maintained by Intellirim.
