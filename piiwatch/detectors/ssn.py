"""US Social Security Number detector.

SSNs have a well-defined format (AAA-GG-SSSS) and a set of values the
Social Security Administration has stated it will never issue (e.g. area
000, 666, or 900-999; group 00; serial 0000). Matching the format *and*
excluding known-invalid ranges meaningfully cuts false positives compared
to a naive `\\d{3}-\\d{2}-\\d{4}` regex.
"""

from __future__ import annotations

import re

from piiwatch.detectors.base import Finding, PIIType

# Accept both hyphenated (123-45-6789) and plain 9-digit forms, the
# latter gated by word boundaries to avoid matching inside longer numbers.
_SSN_RE = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    r"|\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b"
)


def _is_structurally_valid(digits: str) -> bool:
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


class SSNDetector:
    name = "ssn_detector"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _SSN_RE.finditer(text):
            raw = match.group()
            digits = re.sub(r"-", "", raw)
            start, end = match.span()

            hyphenated = "-" in raw
            # Hyphenated matches are far more likely to be genuine SSNs
            # (the format is distinctive); plain 9-digit matches are
            # ambiguous with lots of other numeric data, so confidence is
            # lower and an AI/contextual layer is more valuable there.
            confidence = 0.9 if hyphenated else 0.4

            findings.append(
                Finding(
                    pii_type=PIIType.SSN,
                    raw_value=raw,
                    start=start,
                    end=end,
                    confidence=confidence,
                    validated=_is_structurally_valid(digits),
                    source=self.name,
                    context=text[max(0, start - 20) : end + 20],
                    metadata={"format": "hyphenated" if hyphenated else "plain"},
                )
            )
        return findings
