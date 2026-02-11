"""Minimal tests for validators."""

from pii_shield.validators import (
    luhn_check, email_domain_check, ssn_format_validation,
    iban_checksum, api_key_entropy_check
)


def test_luhn_check():
    """Test Luhn algorithm."""
    assert luhn_check("4532015112830366") is True
    assert luhn_check("1234567890123456") is False


def test_luhn_check_with_spaces():
    """Test Luhn check handles spaces."""
    assert luhn_check("4532 0151 1283 0366") is True
    assert luhn_check("1234 5678 9012 3456") is False


def test_luhn_check_with_dashes():
    """Test Luhn check handles dashes."""
    assert luhn_check("4532-0151-1283-0366") is True
    assert luhn_check("1234-5678-9012-3456") is False


def test_luhn_check_invalid_length():
    """Test Luhn check rejects invalid lengths."""
    assert luhn_check("123") is False
    assert luhn_check("12345678901234567890") is False


def test_luhn_check_non_numeric():
    """Test Luhn check rejects non-numeric input."""
    assert luhn_check("abcd-efgh-ijkl-mnop") is False
    assert luhn_check("not a number") is False


def test_email_domain_check():
    """Test email validation."""
    assert email_domain_check("test@example.com") is True
    assert email_domain_check("invalid") is False


def test_email_domain_check_subdomain():
    """Test email validation with subdomains."""
    assert email_domain_check("user@mail.example.com") is True
    assert email_domain_check("test@subdomain.company.org") is True


def test_email_domain_check_no_at():
    """Test email validation rejects missing @."""
    assert email_domain_check("user.example.com") is False
    assert email_domain_check("nodomain") is False


def test_email_domain_check_no_dot():
    """Test email validation rejects missing dot in domain."""
    assert email_domain_check("user@nodot") is False
    assert email_domain_check("test@domain") is False


def test_email_domain_check_invalid_tld():
    """Test email validation checks TLD."""
    assert email_domain_check("user@example.123") is False
    assert email_domain_check("test@domain.x") is False


def test_email_domain_check_empty_parts():
    """Test email validation rejects empty parts."""
    assert email_domain_check("@example.com") is False
    assert email_domain_check("user@") is False


def test_ssn_validation():
    """Test SSN validation."""
    assert ssn_format_validation("123-45-6789") is True
    assert ssn_format_validation("000-45-6789") is False


def test_ssn_validation_666_area():
    """Test SSN validation rejects 666 area code."""
    assert ssn_format_validation("666-45-6789") is False
    assert ssn_format_validation("667-45-6789") is True


def test_ssn_validation_9xx_area():
    """Test SSN validation rejects 9xx area codes."""
    assert ssn_format_validation("900-45-6789") is False
    assert ssn_format_validation("999-45-6789") is False


def test_ssn_validation_zero_group():
    """Test SSN validation rejects 00 group."""
    assert ssn_format_validation("123-00-6789") is False
    assert ssn_format_validation("123-01-6789") is True


def test_ssn_validation_zero_serial():
    """Test SSN validation rejects 0000 serial."""
    assert ssn_format_validation("123-45-0000") is False
    assert ssn_format_validation("123-45-0001") is True


def test_ssn_validation_wrong_format():
    """Test SSN validation requires correct format."""
    assert ssn_format_validation("123456789") is False
    assert ssn_format_validation("12-345-6789") is False


def test_iban_checksum_valid():
    """Test IBAN checksum validation."""
    assert iban_checksum("GB82WEST12345698765432") is True
    assert iban_checksum("DE89370400440532013000") is True


def test_iban_checksum_invalid():
    """Test IBAN checksum rejects invalid IBANs."""
    assert iban_checksum("GB00WEST12345698765432") is False
    assert iban_checksum("INVALID") is False


def test_iban_checksum_length():
    """Test IBAN checksum validates length."""
    assert iban_checksum("AB12") is False
    assert iban_checksum("AB" + "1" * 50) is False


def test_iban_checksum_format():
    """Test IBAN checksum validates format."""
    assert iban_checksum("1234567890123456") is False
    assert iban_checksum("ABCD1234567890") is False


def test_api_key_entropy_check_high():
    """Test API key entropy check for high entropy."""
    assert api_key_entropy_check("abcdefghijklmnop") is True
    assert api_key_entropy_check("A1B2C3D4E5F6G7H8") is True


def test_api_key_entropy_check_low():
    """Test API key entropy check for low entropy."""
    assert api_key_entropy_check("aaaaaaaaaaaaaaaa") is False
    assert api_key_entropy_check("1111111111111111") is False


def test_api_key_entropy_check_short():
    """Test API key entropy check rejects short strings."""
    assert api_key_entropy_check("short") is False
    assert api_key_entropy_check("abc") is False
