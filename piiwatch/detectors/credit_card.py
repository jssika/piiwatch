"""Credit card number detector.

Matches candidate card numbers via regex, then validates them with the
Luhn checksum algorithm. A regex match that fails Luhn is still reported
(it might still be sensitive-looking data worth a human's attention) but
with reduced confidence and `validated=False`, rather than being dropped
silently -- false negatives are worse than a slightly noisier report.
"""

from __future__ import annotations

import re

from piiwatch.detectors.base import Finding, PIIType

# Candidate numbers: 13-19 digits, optionally separated by spaces or
# hyphens in common groupings. We deliberately over-match here and let
# Luhn + brand prefix checks narrow things down.
_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

_BRAND_PREFIXES = {
    "visa": re.compile(r"^4\d{12}(\d{3})?(\d{3})?$"),
    "mastercard": re.compile(r"^(5[1-5]\d{14}|2(2[2-9]\d{2}|[3-6]\d{3}|7[0-1]\d{2}|720\d)\d{10})$"),
    "amex": re.compile(r"^3[47]\d{13}$"),
    "discover": re.compile(r"^6(?:011\d{12}|5\d{14}|4[4-9]\d{13})$"),
    "diners_club": re.compile(r"^3(?:0[0-5]\d{11}|[68]\d{12})$"),
    "jcb": re.compile(r"^35\d{14}$"),
}


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum: double every second digit from the right,
    subtract 9 if the result exceeds 9, sum everything, valid if divisible
    by 10.
    """
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _detect_brand(digits: str) -> str | None:
    for brand, pattern in _BRAND_PREFIXES.items():
        if pattern.match(digits):
            return brand
    return None


class CreditCardDetector:
    name = "credit_card_detector"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _CANDIDATE_RE.finditer(text):
            raw = match.group()
            digits = re.sub(r"[ -]", "", raw)

            # Guard against matching things like long sequential IDs that
            # happen to be 13-19 digits but obviously aren't card numbers
            # (e.g. all the same digit, or strictly sequential).
            if len(set(digits)) == 1:
                continue

            valid = _luhn_valid(digits)
            brand = _detect_brand(digits)

            # Confidence model:
            #  - Luhn pass + known brand prefix -> high confidence
            #  - Luhn pass, no recognized brand -> medium-high (could be a
            #    valid but less common/test scheme)
            #  - Luhn fail -> low confidence, but still surfaced
            if valid and brand:
                confidence = 0.97
            elif valid:
                confidence = 0.75
            else:
                confidence = 0.25

            start, end = match.span()
            findings.append(
                Finding(
                    pii_type=PIIType.CREDIT_CARD,
                    raw_value=raw,
                    start=start,
                    end=end,
                    confidence=confidence,
                    validated=valid,
                    source=self.name,
                    context=text[max(0, start - 20) : end + 20],
                    metadata={"brand": brand or "unknown", "digit_count": len(digits)},
                )
            )
        return findings
