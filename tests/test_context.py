"""Minimal tests for context."""

from pii_guard.context import ContextAnalyzer


def test_context_analyzer():
    """Test context analysis."""
    analyzer = ContextAnalyzer()
    text = "SSN: 123-45-6789"
    adjustment = analyzer.analyze_context(text, 5, 16, "SSN")
    assert isinstance(adjustment, (int, float))
