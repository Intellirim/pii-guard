"""pii-guard: Context-aware PII detection for LLM pipelines and data workflows."""

__version__ = "1.0.0"

from pii_guard.scanner import Scanner
from pii_guard.models import PIIMatch, ScanResult, MaskingStrategy

__all__ = ["Scanner", "PIIMatch", "ScanResult", "MaskingStrategy", "__version__"]
