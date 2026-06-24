"""Core data model and detector interface shared by all PII detectors.

Every concrete detector (SSN, credit card, email, etc.) implements the
`Detector` protocol below. This keeps the engine, AI classifier, and
reporting layers decoupled from the specifics of any single detector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class PIIType(str, Enum):
    """Canonical set of PII categories PIIWatch can detect."""

    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    API_KEY = "api_key"
    AUTH_TOKEN = "auth_token"
    GENERIC_SECRET = "generic_secret"


class Severity(str, Enum):
    """Severity ranking, low to critical. Assigned by the scoring layer,
    not by individual detectors -- detectors only report confidence.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def redact(value: str, keep_start: int = 0, keep_end: int = 4) -> str:
    """Redact a sensitive value for safe display/reporting.

    Keeps a few trailing characters (common convention, e.g. credit cards
    shown as ``************1234``) so a human can still recognize *which*
    finding is which without the report itself becoming a PII leak.
    """
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return ("*" * (len(value) - keep_start - keep_end)) + value[-keep_end:] if keep_end else "*" * len(value)


@dataclass
class Finding:
    """A single PII detection result.

    Attributes:
        pii_type: Category of PII detected.
        raw_value: The actual matched string. Callers should generally
            use `redacted_value` for display/reporting and reserve
            `raw_value` for cases that genuinely need it (e.g. piping into
            a secrets-rotation workflow), since it is the live sensitive data.
        start: Character offset where the match begins in the source text.
        end: Character offset where the match ends in the source text.
        confidence: Detector's confidence in [0.0, 1.0]. Pattern-only
            matches that fail secondary validation (e.g. Luhn) should
            report a lower confidence rather than being silently dropped.
        validated: Whether the value passed format-specific validation
            (Luhn checksum, known API key prefix, etc.). None means "not
            applicable" for this PII type.
        source: Name of the detector that produced this finding, e.g.
            "credit_card_detector". Useful for debugging and metrics.
        context: A short snippet of surrounding text, used by the AI
            classifier and by human reviewers to judge whether a match is
            a true positive (e.g. "test card 4111111111111111" vs a real
            transaction log).
        metadata: Free-form extra detail specific to the detector (e.g.
            card brand, key provider name).
    """

    pii_type: PIIType
    raw_value: str
    start: int
    end: int
    confidence: float
    validated: bool | None = None
    source: str = ""
    context: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def redacted_value(self) -> str:
        return redact(self.raw_value)

    def to_dict(self, *, include_raw: bool = False) -> dict:
        """Serialize for reporting. Raw value is opt-in and off by default
        so reports don't become PII leaks themselves.
        """
        d = {
            "pii_type": self.pii_type.value,
            "value": self.raw_value if include_raw else self.redacted_value,
            "start": self.start,
            "end": self.end,
            "confidence": round(self.confidence, 3),
            "validated": self.validated,
            "source": self.source,
            "context": self.context,
            "metadata": self.metadata,
        }
        return d


@runtime_checkable
class Detector(Protocol):
    """Interface every PII detector must implement.

    Keeping this minimal (one method, plain string in, list of Finding
    out) means the engine can run detectors uniformly, new PII types can
    be added without touching the engine, and the AI classifier can later
    consume the same Finding objects regardless of which detector produced
    them.
    """

    name: str

    def detect(self, text: str) -> list[Finding]:
        """Scan `text` and return all findings. Must not raise on input
        that simply contains no matches -- return an empty list instead.
        """
        ...
