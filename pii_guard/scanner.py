"""Main scanner for PII detection."""

from typing import List
from pathlib import Path

from pii_guard.models import PIIMatch, ScanResult
from pii_guard.patterns import PATTERNS
from pii_guard.context import ContextAnalyzer
from pii_guard.validators import luhn_check, email_domain_check, ssn_format_validation, iban_checksum, api_key_entropy_check
from pii_guard.tokenizer import Tokenizer


class Scanner:
    """Scans text for PII using context-aware detection."""

    def __init__(self, threshold: int = 70):
        self.threshold = threshold
        self.context_analyzer = ContextAnalyzer()
        self.tokenizer = Tokenizer()

    def scan_text(self, text: str, filename: str = "<input>") -> ScanResult:
        """Scan text for PII."""
        matches = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            matches.extend(self._scan_line(line, line_num, text))

        summary = {}
        for match in matches:
            summary[match.type] = summary.get(match.type, 0) + 1

        return ScanResult(file=filename, matches=matches, summary=summary)

    def scan_file(self, filepath: str) -> ScanResult:
        """Scan a file for PII."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return self.scan_text(f.read(), filepath)
        except:
            return ScanResult(file=filepath, matches=[], summary={})

    def scan_directory(self, dirpath: str) -> List[ScanResult]:
        """Scan all files in a directory."""
        results = []
        for file in Path(dirpath).rglob('*'):
            if file.is_file() and not self._should_ignore(file):
                result = self.scan_file(str(file))
                if result.matches:
                    results.append(result)
        return results

    def _scan_line(self, line: str, line_num: int, full_text: str) -> List[PIIMatch]:
        """Scan a single line for PII patterns."""
        matches = []

        for pii_type, (pattern, base_confidence, _) in PATTERNS.items():
            for match in pattern.finditer(line):
                value = match.group(0)
                confidence = self._calculate_confidence(value, pii_type, base_confidence, full_text)

                if confidence >= self.threshold:
                    context = self.tokenizer.get_context_window(
                        full_text,
                        full_text.find(line) + match.start(),
                        full_text.find(line) + match.end()
                    )

                    matches.append(PIIMatch(
                        type=pii_type,
                        value=value,
                        confidence=confidence,
                        line=line_num,
                        column=match.start(),
                        context=context
                    ))

        return matches

    def _calculate_confidence(self, value: str, pii_type: str, base_confidence: int, full_text: str) -> int:
        """Calculate final confidence score."""
        confidence = base_confidence

        # Apply validators
        if pii_type == "CREDIT_CARD":
            confidence += 15 if luhn_check(value) else -20
        elif pii_type == "EMAIL":
            confidence += 10 if email_domain_check(value) else -15
        elif pii_type == "SSN":
            confidence += 10 if ssn_format_validation(value) else -20
        elif pii_type == "IBAN":
            confidence += 15 if iban_checksum(value) else -20
        elif "API_KEY" in pii_type:
            if api_key_entropy_check(value):
                confidence += 10

        # Apply context analysis
        match_start = full_text.find(value)
        if match_start != -1:
            confidence += self.context_analyzer.analyze_context(
                full_text, match_start, match_start + len(value), pii_type
            )

        return max(0, min(100, confidence))

    def _should_ignore(self, filepath: Path) -> bool:
        """Check if file should be ignored."""
        ignore = ['.git', '__pycache__', 'node_modules', '.pytest_cache', 'venv', 'dist', 'build']
        if any(p in str(filepath) for p in ignore):
            return True
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.read(512)
            return False
        except:
            return True
