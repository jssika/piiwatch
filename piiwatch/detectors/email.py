"""Email address detector."""

from __future__ import annotations

import re

from piiwatch.detectors.base import Finding, PIIType

# Pragmatic RFC-5322-ish pattern: strict enough to avoid most garbage
# matches, permissive enough to handle real-world addresses (plus signs,
# subdomains, etc.) without trying to be a full RFC implementation.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+\-]*[A-Za-z0-9])?"
    r"@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+\b"
)

# Common placeholder/example domains that show up constantly in test
# fixtures, docs, and sample configs -- treat as lower confidence rather
# than excluding entirely, since they *can* still appear in real leaks.
_LOW_SIGNAL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "localhost.com", "domain.com",
}


class EmailDetector:
    name = "email_detector"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _EMAIL_RE.finditer(text):
            raw = match.group()
            domain = raw.rsplit("@", 1)[-1].lower()
            start, end = match.span()

            confidence = 0.6 if domain in _LOW_SIGNAL_DOMAINS else 0.95

            findings.append(
                Finding(
                    pii_type=PIIType.EMAIL,
                    raw_value=raw,
                    start=start,
                    end=end,
                    confidence=confidence,
                    validated=True,
                    source=self.name,
                    context=text[max(0, start - 20) : end + 20],
                    metadata={"domain": domain},
                )
            )
        return findings
