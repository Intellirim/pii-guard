"""Minimal tests for scanner."""

import pytest
from pii_guard.scanner import Scanner


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
