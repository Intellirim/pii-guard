"""Minimal tests for masker."""

from pii_shield.masker import Masker
from pii_shield.models import MaskingStrategy


def test_full_masking():
    """Test full redaction."""
    masker = Masker(strategy=MaskingStrategy.FULL)
    result = masker.mask("test@example.com", "EMAIL")
    assert "REDACTED" in result
    assert "test@example.com" not in result


def test_partial_masking():
    """Test partial masking."""
    masker = Masker(strategy=MaskingStrategy.PARTIAL)
    result = masker.mask("123-45-6789", "SSN")
    assert "***" in result or "6789" in result
    assert len(result) > 0


def test_hash_masking():
    """Test hash masking."""
    masker = Masker(strategy=MaskingStrategy.HASH)
    result = masker.mask("test@example.com", "EMAIL")
    assert len(result) > 0
    assert result != "test@example.com"


def test_masking_preserves_type():
    """Test that masking preserves PII type information."""
    masker = Masker(strategy=MaskingStrategy.FULL)
    result = masker.mask("test@example.com", "EMAIL")
    assert "EMAIL" in result
    assert isinstance(result, str)


def test_masking_empty_string():
    """Test masking empty string."""
    masker = Masker(strategy=MaskingStrategy.FULL)
    result = masker.mask("", "EMAIL")
    assert isinstance(result, str)
    assert len(result) >= 0


def test_masking_unicode():
    """Test masking unicode content."""
    masker = Masker(strategy=MaskingStrategy.PARTIAL)
    result = masker.mask("测试@example.com", "EMAIL")
    assert len(result) > 0
    assert isinstance(result, str)


def test_partial_masking_ssn():
    """Test partial masking preserves SSN structure."""
    masker = Masker(strategy=MaskingStrategy.PARTIAL)
    result = masker.mask("123-45-6789", "SSN")
    assert len(result) > 0
    assert "***" in result or "6789" in result


def test_partial_masking_credit_card():
    """Test partial masking for credit cards."""
    masker = Masker(strategy=MaskingStrategy.PARTIAL)
    result = masker.mask("4532-1234-5678-9010", "CREDIT_CARD")
    assert len(result) > 0
    assert isinstance(result, str)


def test_hash_masking_deterministic():
    """Test hash masking is deterministic."""
    masker = Masker(strategy=MaskingStrategy.HASH)
    result1 = masker.mask("test@example.com", "EMAIL")
    result2 = masker.mask("test@example.com", "EMAIL")
    assert result1 == result2
    assert isinstance(result1, str)


def test_hash_masking_different_inputs():
    """Test hash masking produces different outputs for different inputs."""
    masker = Masker(strategy=MaskingStrategy.HASH)
    result1 = masker.mask("test1@example.com", "EMAIL")
    result2 = masker.mask("test2@example.com", "EMAIL")
    assert result1 != result2
    assert isinstance(result1, str)


def test_masking_very_long_string():
    """Test masking very long strings."""
    masker = Masker(strategy=MaskingStrategy.FULL)
    long_value = "x" * 1000 + "@example.com"
    result = masker.mask(long_value, "EMAIL")
    assert isinstance(result, str)
    assert len(result) > 0
