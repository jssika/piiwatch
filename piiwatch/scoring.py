"""Risk scoring and severity assessment.

Deliberately separate from detection: detectors only know "is this PII
and how confident am I", scoring decides "how bad is it if this leaked."
That separation means severity policy (e.g. "treat SSNs as always
critical") can be tuned/configured without touching detector internals.
"""

from __future__ import annotations

from piiwatch.detectors.base import Finding, PIIType, Severity

# Baseline severity by PII type, reflecting typical regulatory/business
# impact if exposed (SSNs and full card numbers are the most consistently
# regulated categories; emails are common but lower-impact on their own).
_BASE_SEVERITY: dict[PIIType, Severity] = {
    PIIType.SSN: Severity.CRITICAL,
    PIIType.CREDIT_CARD: Severity.CRITICAL,
    PIIType.API_KEY: Severity.HIGH,
    PIIType.AUTH_TOKEN: Severity.HIGH,
    PIIType.GENERIC_SECRET: Severity.MEDIUM,
    PIIType.PHONE: Severity.LOW,
    PIIType.EMAIL: Severity.LOW,
}

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _downgrade(severity: Severity, steps: int = 1) -> Severity:
    idx = max(_SEVERITY_ORDER.index(severity) - steps, 0)
    return _SEVERITY_ORDER[idx]


def score_finding(finding: Finding) -> tuple[Severity, float]:
    """Return (severity, risk_score) for a single finding.

    risk_score is a 0-100 scale combining base severity weight and
    detector confidence, so two findings of the same type can still be
    ranked against each other (e.g. a Luhn-valid card vs. a Luhn-failing
    one) instead of clumping everything of one type at identical risk.
    """
    base = _BASE_SEVERITY.get(finding.pii_type, Severity.MEDIUM)

    # Low-confidence or explicitly failed validation softens severity --
    # a credit-card-shaped string that fails Luhn is still worth a look,
    # but shouldn't trigger the same alarm as a confirmed valid number.
    if finding.validated is False:
        base = _downgrade(base, steps=1)
    if finding.confidence < 0.5:
        base = _downgrade(base, steps=1)

    severity_weight = {
        Severity.INFO: 10,
        Severity.LOW: 30,
        Severity.MEDIUM: 55,
        Severity.HIGH: 75,
        Severity.CRITICAL: 95,
    }[base]

    risk_score = round(severity_weight * finding.confidence, 1)
    return base, risk_score


def score_findings(findings: list[Finding]) -> list[dict]:
    """Score a batch of findings, returning enriched dicts ready for
    reporting (each original finding's dict plus severity + risk_score).
    """
    results = []
    for f in findings:
        severity, risk_score = score_finding(f)
        d = f.to_dict()
        d["severity"] = severity.value
        d["risk_score"] = risk_score
        results.append(d)
    # Highest risk first -- the report should lead with what matters most.
    results.sort(key=lambda d: d["risk_score"], reverse=True)
    return results


def summarize(scored: list[dict]) -> dict:
    """Produce an aggregate summary: counts by type and severity, plus an
    overall risk indicator for the scanned input.
    """
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for d in scored:
        by_type[d["pii_type"]] = by_type.get(d["pii_type"], 0) + 1
        by_severity[d["severity"]] = by_severity.get(d["severity"], 0) + 1

    overall_risk = max((d["risk_score"] for d in scored), default=0.0)

    return {
        "total_findings": len(scored),
        "by_type": by_type,
        "by_severity": by_severity,
        "overall_risk_score": overall_risk,
    }
