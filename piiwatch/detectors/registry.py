"""Central registry of all available detectors.

Adding a new PII detector means: write the detector class, import it
here, add it to `DEFAULT_DETECTORS`. Nothing else in the codebase needs
to change.
"""

from __future__ import annotations

from piiwatch.detectors.api_key import APIKeyDetector
from piiwatch.detectors.base import Detector
from piiwatch.detectors.credit_card import CreditCardDetector
from piiwatch.detectors.email import EmailDetector
from piiwatch.detectors.phone import PhoneDetector
from piiwatch.detectors.ssn import SSNDetector

DEFAULT_DETECTORS: list[Detector] = [
    SSNDetector(),
    CreditCardDetector(),
    EmailDetector(),
    PhoneDetector(),
    APIKeyDetector(),
]
