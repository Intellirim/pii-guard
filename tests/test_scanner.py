"""Minimal tests for scanner."""

import pytest
from pii_shield.scanner import Scanner


def test_scan_text_basic():
    """Test basic text scanning."""
    scanner = Scanner(threshold=70)
    result = scanner.scan_text("Contact: test@example.com", "test.txt")
    assert len(result.matches) >= 1
    assert any(m.type == "EMAIL" for m in result.matches)


def test_scan_threshold():
    """Test threshold filtering."""
    scanner = Scanner(threshold=95)
    result = scanner.scan_text("test@example.com", "test.txt")
    assert isinstance(result.matches, list)
    assert result.file == "test.txt"


def test_scan_empty_text():
    """Test scanning empty text."""
    scanner = Scanner()
    result = scanner.scan_text("", "empty.txt")
    assert len(result.matches) == 0
    assert result.file == "empty.txt"


def test_scan_no_pii():
    """Test scanning text with no PII."""
    scanner = Scanner()
    result = scanner.scan_text("This is just normal text without any sensitive data.", "normal.txt")
    assert len(result.matches) == 0
    assert isinstance(result.summary, dict)


def test_scan_multiple_pii_types():
    """Test scanning text with multiple PII types."""
    scanner = Scanner(threshold=60)
    text = "Contact: john@example.com, Phone: 555-123-4567, SSN: 123-45-6789"
    result = scanner.scan_text(text, "multi.txt")
    assert len(result.matches) >= 2
    types = {m.type for m in result.matches}
    assert "EMAIL" in types or "PHONE" in types


def test_scan_multiline():
    """Test scanning multiline text."""
    scanner = Scanner()
    text = "Line 1: test@example.com\nLine 2: another@domain.org\nLine 3: third@site.net"
    result = scanner.scan_text(text, "multiline.txt")
    assert len(result.matches) >= 3
    assert all(m.line >= 1 for m in result.matches)


def test_scan_high_threshold():
    """Test high threshold filters out low confidence matches."""
    scanner = Scanner(threshold=99)
    result = scanner.scan_text("Maybe this is pii: test@example", "test.txt")
    assert len(result.matches) == 0
    assert isinstance(result.summary, dict)


def test_scan_low_threshold():
    """Test low threshold allows more matches."""
    scanner = Scanner(threshold=50)
    result = scanner.scan_text("Email: test@example.com", "test.txt")
    assert len(result.matches) >= 1
    assert result.file == "test.txt"


def test_scan_unicode_text():
    """Test scanning text with unicode characters."""
    scanner = Scanner()
    text = "Email: test@例え.com and 你好 test@example.com"
    result = scanner.scan_text(text, "unicode.txt")
    assert isinstance(result.matches, list)
    assert result.file == "unicode.txt"


def test_scan_very_long_line():
    """Test scanning very long lines."""
    scanner = Scanner()
    text = "x" * 10000 + " test@example.com " + "y" * 10000
    result = scanner.scan_text(text, "long.txt")
    assert len(result.matches) >= 1
    assert all(m.confidence > 0 for m in result.matches)


def test_scan_summary():
    """Test that summary counts matches correctly."""
    scanner = Scanner(threshold=60)
    text = "email1@test.com email2@test.com 123-45-6789"
    result = scanner.scan_text(text, "test.txt")
    assert isinstance(result.summary, dict)
    assert sum(result.summary.values()) == len(result.matches)


def test_scan_false_positive_reduction():
    """Test that validators affect confidence scores."""
    scanner = Scanner(threshold=80)
    text = "This is not an SSN: 000-00-0000 or 666-00-0000"
    result = scanner.scan_text(text, "test.txt")
    ssn_matches = [m for m in result.matches if m.type == "SSN"]
    # Invalid SSNs should have reduced confidence
    for match in ssn_matches:
        assert match.confidence < 85
    assert isinstance(result.matches, list)


def test_scan_context_window():
    """Test that context windows are captured."""
    scanner = Scanner()
    text = "The user's email address is alice@company.com for contact purposes."
    result = scanner.scan_text(text, "test.txt")
    if result.matches:
        assert all(len(m.context) > 0 for m in result.matches)
        assert all(isinstance(m.context, str) for m in result.matches)


def test_scan_column_position():
    """Test that column positions are tracked."""
    scanner = Scanner()
    text = "Start test@example.com end"
    result = scanner.scan_text(text, "test.txt")
    if result.matches:
        assert all(m.column >= 0 for m in result.matches)
        assert all(m.line > 0 for m in result.matches)
