"""API key, secret, and auth token detector.

Two-tiered approach:
  1. Known provider key formats (AWS, GitHub, Stripe, Slack, generic JWT,
     etc.) -- these have recognizable prefixes/structure, so confidence
     is high.
  2. Generic "assignment + high-entropy string" pattern (e.g.
     `api_key = "x8Hf92..."`) to catch secrets that don't match a known
     vendor format. Entropy is used to avoid flagging ordinary words or
     low-entropy config values.
"""

from __future__ import annotations

import math
import re

from piiwatch.detectors.base import Finding, PIIType

_KNOWN_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), 0.97),
    ("aws_secret_access_key_hint", re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'), 0.9),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0.97),
    ("slack_token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"), 0.95),
    ("stripe_key", re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}\b"), 0.95),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0.95),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 0.9),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.99),
]

# Generic "key = value" assignment, used as a fallback when nothing above
# matches. Looks for common secret-ish variable names plus a quoted or
# bare token value.
_GENERIC_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(api[_-]?key|secret|token|access[_-]?key|auth[_-]?token|password|passwd|client[_-]?secret)
    \s*[=:]\s*
    ["']?([A-Za-z0-9_\-/+.]{16,})["']?
    """
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class APIKeyDetector:
    name = "api_key_detector"
    # Below this entropy, a generic-assignment match is treated as a
    # likely placeholder/config value (e.g. "changeme", "your_key_here")
    # rather than a real secret.
    _MIN_ENTROPY = 3.0

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        matched_spans: list[tuple[int, int]] = []

        for label, pattern, confidence in _KNOWN_PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                matched_spans.append((start, end))
                pii_type = PIIType.API_KEY if "key" in label or label == "private_key_block" else PIIType.AUTH_TOKEN
                findings.append(
                    Finding(
                        pii_type=pii_type,
                        raw_value=match.group(),
                        start=start,
                        end=end,
                        confidence=confidence,
                        validated=True,
                        source=self.name,
                        context=text[max(0, start - 20) : end + 20],
                        metadata={"provider": label},
                    )
                )

        for match in _GENERIC_ASSIGNMENT_RE.finditer(text):
            start, end = match.span()
            # Skip if this span overlaps a known-pattern match already found.
            if any(s <= start < e or s < end <= e for s, e in matched_spans):
                continue

            value = match.group(2)
            entropy = _shannon_entropy(value)
            if entropy < self._MIN_ENTROPY:
                continue

            confidence = min(0.55 + (entropy - self._MIN_ENTROPY) * 0.1, 0.85)

            findings.append(
                Finding(
                    pii_type=PIIType.GENERIC_SECRET,
                    raw_value=match.group(),
                    start=start,
                    end=end,
                    confidence=round(confidence, 2),
                    validated=None,
                    source=self.name,
                    context=text[max(0, start - 20) : end + 20],
                    metadata={"entropy": round(entropy, 2), "field_name": match.group(1).lower()},
                )
            )
        return findings
