"""Minimal tests for validators."""

from pii_guard.validators import luhn_check, email_domain_check, ssn_format_validation


def test_luhn_check():
    """Test Luhn algorithm."""
    assert luhn_check("4532015112830366") is True
    assert luhn_check("1234567890123456") is False


def test_email_domain_check():
    """Test email validation."""
    assert email_domain_check("test@example.com") is True
    assert email_domain_check("invalid") is False


def test_ssn_validation():
    """Test SSN validation."""
    assert ssn_format_validation("123-45-6789") is True
    assert ssn_format_validation("000-45-6789") is False
