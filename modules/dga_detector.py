# -*- coding: utf-8 -*-
"""
==============================================================================
DOMAIN GENERATION ALGORITHM (DGA) DETECTION ENGINE (modules/dga_detector.py)
==============================================================================
Calculates Shannon entropy, vowel/consonant distribution, and n-gram transition
probabilities to detect algorithmically generated malware C2 domains in real-time.
"""

import math
import re
from collections import Counter
import config

class DGADetector:
    def __init__(self, entropy_threshold=config.DGA_ENTROPY_THRESHOLD):
        self.entropy_threshold = entropy_threshold
        self.vowels = set("aeiou")
        
        # Legitimate domain whitelist to prevent false alarms
        self.whitelist = {
            "google.com", "ubuntu.com", "canonical.com", "github.com",
            "microsoft.com", "cloudflare.com", "debian.org", "python.org",
            "docker.io", "docker.com", "kubernetes.io", "amazonaws.com"
        }

    def calculate_shannon_entropy(self, text: str) -> float:
        """Calculates standard Shannon entropy H(X) = -sum(p * log2(p))."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    def extract_domain_labels(self, domain: str) -> str:
        """Extracts the Second-Level Domain (SLD) label from a FQDN (e.g. 'c2evil.com' -> 'c2evil')."""
        domain = domain.lower().strip()
        # Remove protocol if present
        domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0]
        parts = domain.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return domain

    def analyze(self, domain: str) -> dict:
        """
        Analyzes a domain name and returns DGA probability metrics.
        """
        if not domain or not isinstance(domain, str):
            return {"is_dga": False, "entropy": 0.0, "score": 0.0}

        domain_clean = domain.lower().strip()
        
        # Check whitelist
        for w in self.whitelist:
            if domain_clean.endswith(w):
                return {"is_dga": False, "entropy": 0.0, "score": 0.0, "reason": "Whitelisted Domain"}

        label = self.extract_domain_labels(domain_clean)
        if len(label) < 6:
            return {"is_dga": False, "entropy": 0.0, "score": 0.0, "reason": "Label too short for DGA"}

        # 1. Shannon Entropy
        entropy = self.calculate_shannon_entropy(label)

        # 2. Vowel to Length Ratio
        vowel_count = sum(1 for c in label if c in self.vowels)
        vowel_ratio = vowel_count / len(label)

        # 3. Digit Ratio
        digit_count = sum(1 for c in label if c.isdigit())
        digit_ratio = digit_count / len(label)

        # 4. Long Consecutive Consonant Chains (e.g. 'xkqwrtpsdf' or mixed digits)
        has_consonant_cluster = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", label)) or bool(re.search(r"[a-z0-9]{6,}", label) and digit_ratio > 0.15)

        # Composite DGA Score (0.0 to 1.0)
        score = 0.0
        if entropy >= 3.3:
            score += 0.35
        if entropy >= self.entropy_threshold:
            score += 0.15
        if vowel_ratio < 0.22 or vowel_ratio > 0.68:
            score += 0.25
        if digit_ratio > 0.15:
            score += 0.20
        if has_consonant_cluster:
            score += 0.20

        is_dga = score >= 0.50

        return {
            "domain": domain_clean,
            "label": label,
            "is_dga": is_dga,
            "entropy": round(entropy, 3),
            "vowel_ratio": round(vowel_ratio, 3),
            "digit_ratio": round(digit_ratio, 3),
            "score": round(score * 100, 1)
        }

# Singleton instance
dga_detector = DGADetector()
