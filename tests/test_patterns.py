"""Minimal tests for patterns."""

from pii_shield.patterns import PATTERNS


def test_email_pattern():
    """Test email pattern."""
    pattern, conf, desc = PATTERNS["EMAIL"]
    assert pattern.search("test@example.com") is not None
    assert pattern.search("no-email-here") is None


def test_ssn_pattern():
    """Test SSN pattern."""
    pattern, conf, desc = PATTERNS["SSN"]
    assert pattern.search("123-45-6789") is not None
    assert pattern.search("12345678") is None


def test_credit_card_pattern():
    """Test credit card pattern."""
    pattern, conf, desc = PATTERNS["CREDIT_CARD"]
    assert pattern.search("4532-1234-5678-9010") is not None
    assert pattern.search("123") is None


def test_phone_pattern():
    """Test phone number pattern."""
    pattern, conf, desc = PATTERNS["PHONE"]
    assert pattern.search("555-123-4567") is not None
    assert pattern.search("12") is None


def test_phone_pattern_variations():
    """Test phone pattern with various formats."""
    pattern, conf, desc = PATTERNS["PHONE"]
    assert pattern.search("(555) 123-4567") is not None
    assert pattern.search("555.123.4567") is not None


def test_ip_address_pattern():
    """Test IP address pattern."""
    pattern, conf, desc = PATTERNS["IP_ADDRESS"]
    assert pattern.search("192.168.1.1") is not None
    assert pattern.search("not.an.ip") is None


def test_aws_api_key_pattern():
    """Test AWS API key pattern."""
    pattern, conf, desc = PATTERNS["API_KEY_AWS"]
    assert pattern.search("AKIAIOSFODNN7EXAMPLE") is not None
    assert pattern.search("NOTAKEY123") is None


def test_openai_api_key_pattern():
    """Test OpenAI API key pattern."""
    pattern, conf, desc = PATTERNS["API_KEY_OPENAI"]
    assert pattern.search("sk-1234567890abcdefghij") is not None
    assert pattern.search("not-a-key") is None


def test_github_token_pattern():
    """Test GitHub token pattern."""
    pattern, conf, desc = PATTERNS["API_KEY_GITHUB"]
    assert pattern.search("ghp_1234567890abcdefghijklmnopqrstuvwxyz") is not None
    assert pattern.search("github_token") is None


def test_jwt_pattern():
    """Test JWT pattern."""
    pattern, conf, desc = PATTERNS["JWT"]
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert pattern.search(jwt) is not None
    assert pattern.search("not.a.jwt") is None


def test_passport_pattern():
    """Test passport pattern."""
    pattern, conf, desc = PATTERNS["PASSPORT"]
    assert pattern.search("A12345678") is not None
    assert pattern.search("PASS") is None


def test_iban_pattern():
    """Test IBAN pattern."""
    pattern, conf, desc = PATTERNS["IBAN"]
    assert pattern.search("GB82WEST12345698765432") is not None
    assert pattern.search("NOTIBAN") is None


def test_dob_pattern():
    """Test date of birth pattern."""
    pattern, conf, desc = PATTERNS["DOB"]
    assert pattern.search("01/15/1990") is not None
    assert pattern.search("13/32/2020") is None


def test_zip_code_pattern():
    """Test ZIP code pattern."""
    pattern, conf, desc = PATTERNS["ZIP_CODE"]
    assert pattern.search("12345") is not None
    assert pattern.search("12345-6789") is not None


def test_mrn_pattern():
    """Test medical record number pattern."""
    pattern, conf, desc = PATTERNS["MRN"]
    assert pattern.search("MRN: 1234567") is not None
    assert pattern.search("random text") is None


def test_patterns_have_confidence():
    """Test all patterns have confidence scores."""
    for name, (pattern, conf, desc) in PATTERNS.items():
        assert isinstance(conf, int)
        assert 0 <= conf <= 100


def test_patterns_have_descriptions():
    """Test all patterns have descriptions."""
    for name, (pattern, conf, desc) in PATTERNS.items():
        assert isinstance(desc, str)
        assert len(desc) > 0


def test_email_false_positive():
    """Test email pattern doesn't match invalid formats."""
    pattern, conf, desc = PATTERNS["EMAIL"]
    assert pattern.search("not@email") is None
    assert pattern.search("@example.com") is None


def test_ssn_false_positive():
    """Test SSN pattern is strict about format."""
    pattern, conf, desc = PATTERNS["SSN"]
    assert pattern.search("12345678") is None
    assert pattern.search("123-456-789") is None


def test_credit_card_formats():
    """Test credit card pattern handles different spacing."""
    pattern, conf, desc = PATTERNS["CREDIT_CARD"]
    assert pattern.search("4532 1234 5678 9010") is not None
    assert pattern.search("4532123456789010") is not None
