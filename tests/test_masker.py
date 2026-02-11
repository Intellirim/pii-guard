"""Minimal tests for masker."""

from pii_guard.masker import Masker
from pii_guard.models import MaskingStrategy


def test_full_masking():
    """Test full redaction."""
    masker = Masker(strategy=MaskingStrategy.FULL)
    result = masker.mask("test@example.com", "EMAIL")
    assert "REDACTED" in result


def test_partial_masking():
    """Test partial masking."""
    masker = Masker(strategy=MaskingStrategy.PARTIAL)
    result = masker.mask("123-45-6789", "SSN")
    assert "***" in result or "6789" in result


def test_hash_masking():
    """Test hash masking."""
    masker = Masker(strategy=MaskingStrategy.HASH)
    result = masker.mask("test@example.com", "EMAIL")
    assert len(result) > 0
    assert result != "test@example.com"
