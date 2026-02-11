"""Context analysis for PII detection."""

import re


class ContextAnalyzer:
    """Analyzes context around PII matches to adjust confidence scores."""

    CONTEXT_KEYWORDS = {
        "SSN": ["ssn", "social", "security"],
        "EMAIL": ["email", "contact", "mailto"],
        "PHONE": ["phone", "tel", "call"],
        "CREDIT_CARD": ["card", "credit", "payment"],
        "API_KEY": ["key", "token", "secret", "api"],
    }

    def analyze_context(self, text: str, match_start: int, match_end: int, pii_type: str) -> int:
        """Analyze context and return confidence adjustment (-20 to +20)."""
        window_size = 50
        context_start = max(0, match_start - window_size)
        context_end = min(len(text), match_end + window_size)
        context = text[context_start:context_end].lower()

        adjustment = 0

        # Check for relevant keywords
        base_type = pii_type.split('_')[0]
        for key_type in [pii_type, base_type]:
            if key_type in self.CONTEXT_KEYWORDS:
                for keyword in self.CONTEXT_KEYWORDS[key_type]:
                    if keyword in context:
                        adjustment += 10
                        break

        # Check for labeling patterns (e.g., "SSN: 123-45-6789")
        before_context = text[context_start:match_start]
        if re.search(r'[:=]\s*$', before_context):
            adjustment += 15

        # Penalize if in code-like context
        if re.search(r'[_\-\.]', before_context[-5:]):
            adjustment -= 10

        return max(-20, min(20, adjustment))
