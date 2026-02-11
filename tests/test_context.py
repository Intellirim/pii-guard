"""Minimal tests for context."""

from pii_guard.context import ContextAnalyzer


def test_context_analyzer():
    """Test context analysis."""
    analyzer = ContextAnalyzer()
    text = "SSN: 123-45-6789"
    adjustment = analyzer.analyze_context(text, 5, 16, "SSN")
    assert isinstance(adjustment, (int, float))
    assert adjustment >= -20 and adjustment <= 20


def test_context_analyzer_email():
    """Test context analysis for emails."""
    analyzer = ContextAnalyzer()
    text = "Contact email: john@example.com for support"
    adjustment = analyzer.analyze_context(text, 15, 32, "EMAIL")
    assert isinstance(adjustment, (int, float))
    assert adjustment >= -20


def test_context_analyzer_empty_text():
    """Test context analyzer with empty text."""
    analyzer = ContextAnalyzer()
    adjustment = analyzer.analyze_context("", 0, 0, "EMAIL")
    assert isinstance(adjustment, (int, float))
    assert adjustment >= -20 and adjustment <= 20


def test_context_analyzer_boundary():
    """Test context analyzer at text boundaries."""
    analyzer = ContextAnalyzer()
    text = "test@example.com"
    adjustment = analyzer.analyze_context(text, 0, len(text), "EMAIL")
    assert isinstance(adjustment, (int, float))
    assert adjustment >= -20 and adjustment <= 20


def test_context_analyzer_middle_of_text():
    """Test context analyzer in middle of long text."""
    analyzer = ContextAnalyzer()
    text = "a" * 100 + "test@example.com" + "b" * 100
    adjustment = analyzer.analyze_context(text, 100, 116, "EMAIL")
    assert isinstance(adjustment, (int, float))
    assert adjustment >= -20 and adjustment <= 20


def test_context_analyzer_multiple_types():
    """Test context analyzer with different PII types."""
    analyzer = ContextAnalyzer()
    text = "SSN: 123-45-6789, Email: test@example.com"
    ssn_adj = analyzer.analyze_context(text, 5, 16, "SSN")
    email_adj = analyzer.analyze_context(text, 26, 42, "EMAIL")
    assert isinstance(ssn_adj, (int, float))
    assert isinstance(email_adj, (int, float))
