"""Data models for PII detection."""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict


class MaskingStrategy(Enum):
    """Masking strategies for PII redaction."""
    FULL = "full"
    PARTIAL = "partial"
    HASH = "hash"
    TOKEN = "token"


@dataclass
class PIIMatch:
    """Represents a detected PII instance."""
    type: str
    value: str
    confidence: int
    line: int
    column: int
    context: str

    def __repr__(self) -> str:
        return f"PIIMatch(type={self.type}, confidence={self.confidence}, line={self.line})"


@dataclass
class ScanResult:
    """Results from scanning a file or text."""
    file: str
    matches: List[PIIMatch]
    summary: Dict[str, int]

    def __repr__(self) -> str:
        total = sum(self.summary.values())
        return f"ScanResult(file={self.file}, total_matches={total})"
