# -*- coding: utf-8 -*-
"""
==============================================================================
SENSITIVE DATA & PII SCRUBBER (modules/pii_masker.py)
==============================================================================
Scans log streams, command arguments, and network payloads in real-time to mask
Credit Cards, National IDs (TCKN), Passwords, API Keys, and JWT tokens before
indexing or alerting, ensuring compliance with KVKK, GDPR, and PCI-DSS.
"""

import re

class PIIMasker:
    def __init__(self):
        # 1. Credit Card Patterns (Visa, Mastercard, Amex, Discover: 13-19 digits with optional hyphens/spaces)
        self.cc_regex = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
        
        # 2. Turkish Republic ID (T.C. Kimlik No: 11 Digits, cannot start with 0)
        self.tckn_regex = re.compile(r"\b[1-9]\d{10}\b")
        
        # 3. Password / Secret in parameters (e.g. password=secret123, pwd='123', --token=xyz)
        self.pwd_param_regex = re.compile(
            r"((?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|bearer)[\s:=]+)(['\"]?)([^\s'\";&]+)\2",
            re.IGNORECASE
        )
        
        # 4. AWS Access Key ID (AKIA...)
        self.aws_key_regex = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
        
        # 5. JWT Token pattern (eyJ... . eyJ... . ...)
        self.jwt_regex = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")

    @staticmethod
    def _is_valid_luhn(cc_str: str) -> bool:
        """Fast Luhn algorithm validation for credit card numbers."""
        digits = [int(c) for c in re.sub(r"\D", "", cc_str)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = d * 2
                total += doubled - 9 if doubled > 9 else doubled
            else:
                total += d
        return total % 10 == 0

    @staticmethod
    def _is_valid_tckn(tckn_str: str) -> bool:
        """Validates 11-digit Turkish Republic ID algorithm."""
        digits = [int(c) for c in tckn_str]
        if len(digits) != 11 or digits[0] == 0:
            return False
        d10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
        d11 = sum(digits[:10]) % 10
        return digits[9] == d10 and digits[10] == d11

    def mask(self, text: str) -> str:
        """Masks all sensitive PII and credential tokens in the given text."""
        if not text or not isinstance(text, str):
            return text

        masked = text

        # 1. Mask JWT Tokens
        masked = self.jwt_regex.sub("[MASKED_JWT_TOKEN]", masked)

        # 2. Mask AWS Keys
        masked = self.aws_key_regex.sub("[MASKED_AWS_KEY]", masked)

        # 3. Mask Password/Token Arguments
        masked = self.pwd_param_regex.sub(r"\1\2[MASKED_SECRET]\2", masked)

        # 4. Mask Credit Cards (4x4 chunked groups or Luhn valid numbers)
        def _cc_sub(m):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if len(digits) in [15, 16] or self._is_valid_luhn(raw):
                return "[MASKED_CREDIT_CARD]"
            return raw
        masked = self.cc_regex.sub(_cc_sub, masked)

        # 5. Mask Valid TCKN Numbers
        def _tckn_sub(m):
            raw = m.group(0)
            if self._is_valid_tckn(raw):
                return "[MASKED_TCKN]"
            return raw
        masked = self.tckn_regex.sub(_tckn_sub, masked)

        return masked

# Singleton instance
pii_masker = PIIMasker()
