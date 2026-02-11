"""Output formatters for scan results."""

import json
from typing import List
from pii_guard.models import ScanResult


class TextFormatter:
    """Format results as human-readable text."""

    def format(self, results: List[ScanResult]) -> str:
        """Format scan results as text."""
        output = []

        for result in results:
            if result.matches:
                output.append(f"Scanning: {result.file}\n")
                for match in result.matches:
                    output.append(f"[Line {match.line}] {match.type} (confidence: {match.confidence})")
                    output.append(f"  {match.value}")
                    output.append(f'  Context: "{match.context}"\n')

        total_matches = sum(len(r.matches) for r in results)
        total_files = len([r for r in results if r.matches])
        output.append(f"Summary: {total_matches} PII instances found in {total_files} file(s)")

        return '\n'.join(output)


class JSONFormatter:
    """Format results as JSON."""

    def format(self, results: List[ScanResult]) -> str:
        """Format scan results as JSON."""
        findings = []
        summary = {}

        for result in results:
            for match in result.matches:
                findings.append({
                    "file": result.file,
                    "line": match.line,
                    "column": match.column,
                    "type": match.type,
                    "value": match.value,
                    "confidence": match.confidence,
                    "context": match.context
                })
                summary[match.type] = summary.get(match.type, 0) + 1

        return json.dumps({
            "files_scanned": len(results),
            "total_findings": len(findings),
            "findings": findings,
            "summary": summary
        }, indent=2)


class CSVFormatter:
    """Format results as CSV."""

    def format(self, results: List[ScanResult]) -> str:
        """Format scan results as CSV."""
        output = ["file,line,column,type,confidence,value,context"]

        for result in results:
            for match in result.matches:
                value = match.value.replace('"', '""')
                context = match.context.replace('"', '""')
                output.append(
                    f'"{result.file}",{match.line},{match.column},'
                    f'{match.type},{match.confidence},"{value}","{context}"'
                )

        return '\n'.join(output)
