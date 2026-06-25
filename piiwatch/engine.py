"""Detection engine: orchestrates all registered detectors over input
text and returns scored, deduplicated findings.

This is the main entry point the CLI, AI layer, and reporting modules
will all call into -- they should never need to talk to individual
detectors directly.
"""

from __future__ import annotations

from piiwatch.detectors.base import Detector, Finding
from piiwatch.detectors.registry import DEFAULT_DETECTORS
from piiwatch.scoring import score_findings, summarize


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.start < b.end and b.start < a.end


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """When multiple detectors match overlapping spans (e.g. a generic
    secret pattern and a known-provider pattern both firing on the same
    text), keep only the highest-confidence finding per overlapping
    cluster rather than reporting duplicates.
    """
    if not findings:
        return []

    ordered = sorted(findings, key=lambda f: f.confidence, reverse=True)
    kept: list[Finding] = []
    for f in ordered:
        if not any(_overlaps(f, k) for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


class PIIWatchEngine:
    """Runs the full detection pipeline over a piece of text.

    Usage:
        engine = PIIWatchEngine()
        result = engine.scan(text)

        # With AI-assisted review of ambiguous findings:
        from piiwatch.ai import AIClassifier, build_provider
        classifier = AIClassifier(provider=build_provider("anthropic"))
        engine = PIIWatchEngine(classifier=classifier)
        result = engine.scan(text)
    """

    def __init__(self, detectors: list[Detector] | None = None, classifier=None):
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS
        # classifier is an AIClassifier instance or None. Kept untyped
        # here (rather than imported) so importing piiwatch.engine never
        # requires the AI module's optional dependencies.
        self.classifier = classifier

    def scan(self, text: str, *, min_confidence: float = 0.0, use_ai: bool = True, force_ai_all: bool = False) -> dict:
        """Run all detectors over `text`, dedupe overlapping matches,
        optionally run AI review on ambiguous findings, score the
        survivors, and return a report-ready dict.

        min_confidence filters out low-confidence noise -- applied AFTER
        AI review, since review can change a finding's confidence (e.g.
        confirming a previously-ambiguous match, or rejecting a false
        positive down to near-zero).

        use_ai disables AI review for this call even if a classifier is
        configured (useful for cost control on bulk scans). force_ai_all
        sends every finding to the AI, not just ambiguous ones.
        """
        all_findings: list[Finding] = []
        for detector in self.detectors:
            all_findings.extend(detector.detect(text))

        deduped = _dedupe(all_findings)

        if self.classifier is not None and use_ai and deduped:
            deduped = self.classifier.review(deduped, text, force_all=force_ai_all)

        filtered = [f for f in deduped if f.confidence >= min_confidence]

        scored = score_findings(filtered)
        summary = summarize(scored)

        return {"summary": summary, "findings": scored}

    def scan_lines(self, lines: list[str], *, min_confidence: float = 0.0, use_ai: bool = True) -> dict:
        """Scan multiple lines (e.g. a log file read line by line),
        tagging each finding with its originating line number. Useful
        once we move beyond single-blob scanning to real log files.
        """
        per_line_results = []
        for i, line in enumerate(lines, start=1):
            result = self.scan(line, min_confidence=min_confidence, use_ai=use_ai)
            for finding in result["findings"]:
                finding["line"] = i
            if result["findings"]:
                per_line_results.extend(result["findings"])

        per_line_results.sort(key=lambda d: d["risk_score"], reverse=True)
        summary = summarize(per_line_results)
        return {"summary": summary, "findings": per_line_results}
