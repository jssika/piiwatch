"""Phone number detector (US/NANP-focused, with loose international support).

Phone numbers are notoriously ambiguous to detect via regex alone (they
overlap heavily with other numeric IDs), so this detector leans on
structural cues -- parentheses, hyphens, optional country code -- to keep
confidence calibrated rather than pretending plain 10-digit runs are
reliably phone numbers.
"""

from __future__ import annotations

import re

from piiwatch.detectors.base import Finding, PIIType

# Matches formats like:
#   (312) 555-0148, 312-555-0148, 312.555.0148, +1 312 555 0148
_PHONE_RE = re.compile(
    r"\b(?:\+?1[\s.-]?)?"
    r"\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"
)

_NANP_AREA_INVALID_START = ("0", "1")


def _has_explicit_formatting(raw: str) -> bool:
    return any(ch in raw for ch in "()-. ") or raw.strip().startswith("+")


class PhoneDetector:
    name = "phone_detector"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _PHONE_RE.finditer(text):
            raw = match.group()
            digits = re.sub(r"\D", "", raw)
            # Normalize away a leading country code "1" for area-code checks.
            core = digits[-10:]
            area_code = core[:3]
            start, end = match.span()

            structurally_plausible = area_code[0] not in _NANP_AREA_INVALID_START

            if not structurally_plausible:
                continue

            # Unformatted 10-digit runs are heavily ambiguous with order
            # numbers, IDs, etc. -- only keep them if other signals exist;
            # otherwise this detector would be extremely noisy.
            if not _has_explicit_formatting(raw):
                confidence = 0.45
            else:
                confidence = 0.9

            findings.append(
                Finding(
                    pii_type=PIIType.PHONE,
                    raw_value=raw,
                    start=start,
                    end=end,
                    confidence=confidence,
                    validated=structurally_plausible,
                    source=self.name,
                    context=text[max(0, start - 20) : end + 20],
                    metadata={"area_code": area_code},
                )
            )
        return findings
