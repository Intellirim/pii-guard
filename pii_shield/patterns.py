"""PII pattern definitions and metadata."""

import re
from typing import Dict, List, Tuple

# Pattern definitions: (regex, base_confidence, description)
PATTERNS: Dict[str, Tuple[re.Pattern, int, str]] = {
    # Identification
    "SSN": (
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        80,
        "US Social Security Numbers"
    ),
    "PASSPORT": (
        re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
        70,
        "Passport numbers"
    ),
    "DRIVERS_LICENSE": (
        re.compile(r'\b[A-Z]\d{7,8}\b'),
        65,
        "US driver's license numbers"
    ),

    # Financial
    "CREDIT_CARD": (
        re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        75,
        "Credit/debit card numbers"
    ),
    "IBAN": (
        re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
        70,
        "International Bank Account Numbers"
    ),
    "ROUTING_NUMBER": (
        re.compile(r'\b\d{9}\b'),
        60,
        "US bank routing numbers"
    ),

    # Contact
    "EMAIL": (
        re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
        90,
        "Email addresses"
    ),
    "PHONE": (
        re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        75,
        "Phone numbers"
    ),
    "IP_ADDRESS": (
        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        70,
        "IPv4 addresses"
    ),

    # Credentials
    "API_KEY_AWS": (
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        95,
        "AWS API keys"
    ),
    "API_KEY_OPENAI": (
        re.compile(r'\bsk-[a-zA-Z0-9]{20,}\b'),
        95,
        "OpenAI API keys"
    ),
    "API_KEY_STRIPE": (
        re.compile(r'\b(sk_live_[a-zA-Z0-9]{24,})\b'),
        95,
        "Stripe API keys"
    ),
    "API_KEY_GITHUB": (
        re.compile(r'\bghp_[a-zA-Z0-9]{30,}\b'),
        95,
        "GitHub personal access tokens"
    ),
    "JWT": (
        re.compile(r'\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b'),
        85,
        "JSON Web Tokens"
    ),

    # Medical
    "MRN": (
        re.compile(r'\bMRN:?\s*\d{6,10}\b', re.IGNORECASE),
        75,
        "Medical Record Numbers"
    ),
    "NPI": (
        re.compile(r'\b\d{10}\b'),
        60,
        "National Provider Identifier"
    ),

    # Personal
    "DOB": (
        re.compile(r'\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b'),
        70,
        "Dates of birth"
    ),
    "ZIP_CODE": (
        re.compile(r'\b\d{5}(?:-\d{4})?\b'),
        55,
        "US ZIP codes"
    ),
}


def get_pattern_categories() -> Dict[str, List[str]]:
    """Return patterns organized by category."""
    return {
        "IDENTIFICATION": ["SSN", "PASSPORT", "DRIVERS_LICENSE"],
        "FINANCIAL": ["CREDIT_CARD", "IBAN", "ROUTING_NUMBER"],
        "CONTACT": ["EMAIL", "PHONE", "IP_ADDRESS"],
        "CREDENTIALS": ["API_KEY_AWS", "API_KEY_OPENAI", "API_KEY_STRIPE", "API_KEY_GITHUB", "JWT"],
        "MEDICAL": ["MRN", "NPI"],
        "PERSONAL": ["DOB", "ZIP_CODE"],
    }


def get_pattern_info(pattern_type: str) -> str:
    """Get description for a pattern type."""
    if pattern_type in PATTERNS:
        return PATTERNS[pattern_type][2]
    return "Unknown pattern type"
