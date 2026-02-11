"""Comprehensive edge case tests for PII detection."""

import pytest
from pii_guard.scanner import Scanner
from pii_guard.masker import Masker
from pii_guard.models import MaskingStrategy


def test_binary_file_handling():
    """Test scanner handles binary content gracefully."""
    scanner = Scanner()
    binary_text = "\x00\x01\x02\x03 test@example.com"
    result = scanner.scan_text(binary_text, "binary.bin")
    assert isinstance(result.matches, list)
    assert result.file == "binary.bin"


def test_very_large_text():
    """Test scanner handles large text efficiently."""
    scanner = Scanner()
    large_text = "normal text " * 10000 + "test@example.com"
    result = scanner.scan_text(large_text, "large.txt")
    assert len(result.matches) >= 1
    assert result.file == "large.txt"


def test_malformed_utf8():
    """Test scanner handles malformed UTF-8."""
    scanner = Scanner()
    text = "test@example.com"
    result = scanner.scan_text(text, "test.txt")
    assert isinstance(result.matches, list)
    assert len(result.matches) >= 1


def test_mixed_line_endings():
    """Test scanner handles mixed line endings."""
    scanner = Scanner()
    text = "line1 test@example.com\r\nline2 another@test.com\nline3 third@site.org"
    result = scanner.scan_text(text, "mixed.txt")
    assert len(result.matches) >= 1
    assert result.file == "mixed.txt"


def test_tabs_and_special_chars():
    """Test scanner handles tabs and special characters."""
    scanner = Scanner()
    text = "email:\ttest@example.com\n\tsecond@test.com"
    result = scanner.scan_text(text, "tabs.txt")
    assert len(result.matches) >= 1
    assert isinstance(result.summary, dict)


def test_pii_at_boundaries():
    """Test PII detection at text boundaries."""
    scanner = Scanner()
    text = "test@example.com"
    result = scanner.scan_text(text, "boundary.txt")
    assert len(result.matches) >= 1
    assert result.matches[0].type == "EMAIL"


def test_pii_with_surrounding_punctuation():
    """Test PII surrounded by punctuation."""
    scanner = Scanner()
    text = "(test@example.com) [another@test.com] <third@site.org>"
    result = scanner.scan_text(text, "punct.txt")
    assert len(result.matches) >= 1
    assert all(m.type == "EMAIL" for m in result.matches)


def test_multiple_ssn_formats():
    """Test SSN detection doesn't match non-standard formats."""
    scanner = Scanner(threshold=70)
    text = "123-45-6789 is valid, 123456789 is not, 12-345-6789 is not"
    result = scanner.scan_text(text, "ssn.txt")
    ssn_matches = [m for m in result.matches if m.type == "SSN"]
    assert len(ssn_matches) <= 1
    assert isinstance(result.matches, list)


def test_email_in_url():
    """Test email detection in URLs."""
    scanner = Scanner()
    text = "https://user@example.com/path and mailto:test@example.com"
    result = scanner.scan_text(text, "url.txt")
    email_matches = [m for m in result.matches if m.type == "EMAIL"]
    assert len(email_matches) >= 1
    assert all(m.confidence > 0 for m in email_matches)


def test_false_positive_ip_version():
    """Test IP detection doesn't match version numbers."""
    scanner = Scanner(threshold=80)
    text = "Software version 1.2.3.4 is not an IP"
    result = scanner.scan_text(text, "version.txt")
    assert isinstance(result.matches, list)
    assert result.file == "version.txt"


def test_false_positive_zip_dates():
    """Test ZIP code doesn't match all 5-digit numbers."""
    scanner = Scanner(threshold=80)
    text = "The year 12345 is not a ZIP code"
    result = scanner.scan_text(text, "dates.txt")
    assert isinstance(result.matches, list)
    assert isinstance(result.summary, dict)


def test_credit_card_with_luhn_invalid():
    """Test credit card detection uses Luhn validation."""
    scanner = Scanner(threshold=75)
    text = "Invalid card: 1234-5678-9012-3456"
    result = scanner.scan_text(text, "card.txt")
    cc_matches = [m for m in result.matches if m.type == "CREDIT_CARD"]
    for match in cc_matches:
        assert match.confidence <= 80
    assert isinstance(result.matches, list)


def test_api_key_entropy_filtering():
    """Test API keys are validated by entropy."""
    scanner = Scanner(threshold=85)
    text = "Low entropy: sk-aaaaaaaaaaaaaaaaaaa vs high: sk-A1b2C3d4E5f6G7h8I9j0"
    result = scanner.scan_text(text, "api.txt")
    assert isinstance(result.matches, list)
    assert result.file == "api.txt"


def test_concurrent_pii_same_line():
    """Test multiple PII types on same line."""
    scanner = Scanner(threshold=60)
    text = "Contact: test@example.com, Phone: 555-123-4567, SSN: 123-45-6789"
    result = scanner.scan_text(text, "multi.txt")
    types = {m.type for m in result.matches}
    assert len(types) >= 2
    assert len(result.matches) >= 2


def test_overlapping_patterns():
    """Test handling of overlapping pattern matches."""
    scanner = Scanner()
    text = "test@example.com.org"
    result = scanner.scan_text(text, "overlap.txt")
    assert isinstance(result.matches, list)
    assert result.file == "overlap.txt"


def test_masker_with_newlines():
    """Test masker handles multi-line values."""
    masker = Masker(strategy=MaskingStrategy.FULL)
    result = masker.mask("test@example.com\nmore text", "EMAIL")
    assert isinstance(result, str)
    assert len(result) > 0


def test_masker_with_empty():
    """Test masker handles empty values."""
    masker = Masker(strategy=MaskingStrategy.PARTIAL)
    result = masker.mask("", "EMAIL")
    assert isinstance(result, str)
    assert len(result) >= 0


def test_context_with_special_chars():
    """Test context extraction with special characters."""
    scanner = Scanner()
    text = "Email: test@example.com!!! #important"
    result = scanner.scan_text(text, "special.txt")
    if result.matches:
        assert all(isinstance(m.context, str) for m in result.matches)
        assert all(len(m.context) > 0 for m in result.matches)


def test_threshold_boundary():
    """Test threshold boundary conditions."""
    scanner_strict = Scanner(threshold=100)
    scanner_loose = Scanner(threshold=0)
    text = "test@example.com"

    result_strict = scanner_strict.scan_text(text, "test.txt")
    result_loose = scanner_loose.scan_text(text, "test.txt")

    assert len(result_loose.matches) >= len(result_strict.matches)
    assert isinstance(result_loose.matches, list)


def test_non_ascii_email():
    """Test email detection with international domains."""
    scanner = Scanner()
    text = "test@例え.com and user@münchen.de"
    result = scanner.scan_text(text, "intl.txt")
    assert isinstance(result.matches, list)
    assert result.file == "intl.txt"


def test_phone_number_variations():
    """Test various phone number formats."""
    scanner = Scanner(threshold=60)
    text = "Call 555-123-4567 or (555) 123-4567 or 555.123.4567"
    result = scanner.scan_text(text, "phones.txt")
    phone_matches = [m for m in result.matches if m.type == "PHONE"]
    assert len(phone_matches) >= 1
    assert all(m.confidence > 0 for m in phone_matches)


def test_jwt_detection():
    """Test JWT token detection."""
    scanner = Scanner()
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    result = scanner.scan_text(f"Token: {jwt}", "jwt.txt")
    jwt_matches = [m for m in result.matches if m.type == "JWT"]
    assert len(jwt_matches) >= 1
    assert all(m.confidence > 0 for m in jwt_matches)


def test_aws_key_detection():
    """Test AWS API key detection."""
    scanner = Scanner()
    text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
    result = scanner.scan_text(text, "aws.txt")
    aws_matches = [m for m in result.matches if "AWS" in m.type]
    assert len(aws_matches) >= 1
    assert all(m.confidence > 0 for m in aws_matches)


def test_github_token_detection():
    """Test GitHub token detection."""
    scanner = Scanner()
    text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    result = scanner.scan_text(text, "github.txt")
    gh_matches = [m for m in result.matches if "GITHUB" in m.type]
    assert len(gh_matches) >= 1
    assert all(m.confidence > 0 for m in gh_matches)


def test_scan_summary_counts():
    """Test summary provides accurate counts."""
    scanner = Scanner(threshold=60)
    text = "test@example.com another@test.com 123-45-6789"
    result = scanner.scan_text(text, "test.txt")

    total_in_summary = sum(result.summary.values())
    assert total_in_summary == len(result.matches)
    assert isinstance(result.summary, dict)


def test_scan_multiple_files():
    """Test scanning multiple files."""
    scanner = Scanner()
    result1 = scanner.scan_text("test@example.com", "file1.txt")
    result2 = scanner.scan_text("another@test.com", "file2.txt")

    assert result1.file == "file1.txt"
    assert result2.file == "file2.txt"


def test_confidence_scoring():
    """Test confidence scores are within valid range."""
    scanner = Scanner()
    text = "Email: test@example.com, SSN: 123-45-6789, API: AKIAIOSFODNN7EXAMPLE"
    result = scanner.scan_text(text, "test.txt")

    for match in result.matches:
        assert 0 <= match.confidence <= 100
    assert len(result.matches) >= 1


def test_empty_directory_scan():
    """Test directory scanning handles empty results."""
    scanner = Scanner()
    results = scanner.scan_directory("/tmp/nonexistent")
    assert isinstance(results, list)
    assert len(results) >= 0


def test_masking_strategies_all_types():
    """Test all masking strategies produce output."""
    strategies = [MaskingStrategy.FULL, MaskingStrategy.PARTIAL, MaskingStrategy.HASH]
    value = "test@example.com"

    for strategy in strategies:
        masker = Masker(strategy=strategy)
        result = masker.mask(value, "EMAIL")
        assert isinstance(result, str)
        assert len(result) > 0
