"""Pytest fixtures."""

import pytest
from pii_guard.scanner import Scanner


@pytest.fixture
def scanner():
    """Create a Scanner instance."""
    return Scanner(threshold=70)
