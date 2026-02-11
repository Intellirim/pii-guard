"""Masking strategies for PII redaction."""

import hashlib
from pii_guard.models import MaskingStrategy


class Masker:
    """Applies masking strategies to PII values."""

    def __init__(self, strategy: MaskingStrategy = MaskingStrategy.FULL):
        self.strategy = strategy
        self.token_counter = 0

    def mask(self, value: str, pii_type: str) -> str:
        """
        Mask a PII value according to the configured strategy.

        Args:
            value: The PII value to mask
            pii_type: Type of PII (for context-aware masking)

        Returns:
            Masked value
        """
        if self.strategy == MaskingStrategy.FULL:
            return self.full_redact(pii_type)
        elif self.strategy == MaskingStrategy.PARTIAL:
            return self.partial_mask(value, pii_type)
        elif self.strategy == MaskingStrategy.HASH:
            return self.hash_replace(value)
        elif self.strategy == MaskingStrategy.TOKEN:
            return self.token_replace()
        else:
            return self.full_redact(pii_type)

    def full_redact(self, pii_type: str) -> str:
        """Replace with [TYPE_REDACTED]."""
        return f"[{pii_type}_REDACTED]"

    def partial_mask(self, value: str, pii_type: str) -> str:
        """
        Partially mask value, showing last few characters.

        Args:
            value: Value to mask
            pii_type: Type of PII

        Returns:
            Partially masked value
        """
        # Handle different formats
        if pii_type == "SSN":
            # Show last 4: ***-**-1234
            parts = value.split('-')
            if len(parts) == 3:
                return f"***-**-{parts[2]}"
            return "***-**-****"

        elif pii_type == "CREDIT_CARD":
            # Show last 4: ****-****-****-1234
            digits = value.replace('-', '').replace(' ', '')
            if len(digits) >= 4:
                return f"****-****-****-{digits[-4:]}"
            return "****-****-****-****"

        elif pii_type == "EMAIL":
            # Show first char and domain: j***@example.com
            if '@' in value:
                local, domain = value.split('@', 1)
                if len(local) > 0:
                    return f"{local[0]}***@{domain}"
            return "***@***.***"

        elif pii_type == "PHONE":
            # Show last 4: ***-***-1234
            digits = ''.join(c for c in value if c.isdigit())
            if len(digits) >= 4:
                return f"***-***-{digits[-4:]}"
            return "***-***-****"

        else:
            # Generic: show last 4 chars
            if len(value) > 4:
                return "*" * (len(value) - 4) + value[-4:]
            return "*" * len(value)

    def hash_replace(self, value: str) -> str:
        """Replace with SHA256 hash (first 16 chars)."""
        hash_obj = hashlib.sha256(value.encode())
        return hash_obj.hexdigest()[:16]

    def token_replace(self) -> str:
        """Replace with unique token identifier."""
        self.token_counter += 1
        return f"PLACEHOLDER_{self.token_counter}"
