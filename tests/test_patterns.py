"""Minimal tests for patterns."""

from pii_guard.patterns import PATTERNS


def test_email_pattern():
    """Test email pattern."""
    pattern, conf, desc = PATTERNS["EMAIL"]
    assert pattern.search("test@example.com") is not None


def test_ssn_pattern():
    """Test SSN pattern."""
    pattern, conf, desc = PATTERNS["SSN"]
    assert pattern.search("123-45-6789") is not None


def test_credit_card_pattern():
    """Test credit card pattern."""
    pattern, conf, desc = PATTERNS["CREDIT_CARD"]
    assert pattern.search("4532-1234-5678-9010") is not None
