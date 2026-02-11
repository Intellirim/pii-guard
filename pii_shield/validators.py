"""Validation functions for PII patterns."""

import re


def luhn_check(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = re.sub(r'[-\s]', '', card_number)
    if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    for i, digit in enumerate(digits[::-1]):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def email_domain_check(email: str) -> bool:
    """Validate email domain format."""
    if '@' not in email:
        return False
    parts = email.split('@')
    if len(parts) != 2:
        return False
    local, domain = parts
    if not local or '.' not in domain:
        return False
    domain_parts = domain.split('.')
    if len(domain_parts) < 2 or not all(domain_parts):
        return False
    tld = domain_parts[-1]
    return len(tld) >= 2 and tld.isalpha()


def ssn_format_validation(ssn: str) -> bool:
    """Validate SSN format and known invalid patterns."""
    if not re.match(r'^\d{3}-\d{2}-\d{4}$', ssn):
        return False
    parts = ssn.split('-')
    area, group, serial = parts[0], parts[1], parts[2]
    if area == '000' or area == '666' or area.startswith('9'):
        return False
    if group == '00' or serial == '0000':
        return False
    return True


def iban_checksum(iban: str) -> bool:
    """Validate IBAN checksum."""
    if len(iban) < 15 or len(iban) > 34:
        return False
    if not iban[:2].isalpha() or not iban[2:4].isdigit():
        return False

    rearranged = iban[4:] + iban[:4]
    numeric = ''
    for char in rearranged:
        if char.isalpha():
            numeric += str(ord(char.upper()) - ord('A') + 10)
        else:
            numeric += char

    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def api_key_entropy_check(key: str) -> bool:
    """Check if string has sufficient entropy to be an API key."""
    if len(key) < 16:
        return False
    unique_chars = len(set(key))
    return unique_chars >= len(key) * 0.5
