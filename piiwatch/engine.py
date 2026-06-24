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
    """

    def __init__(self, detectors: list[Detector] | None = None):
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS

    def scan(self, text: str, *, min_confidence: float = 0.0) -> dict:
        """Run all detectors over `text`, dedupe overlapping matches,
        score the survivors, and return a report-ready dict.

        min_confidence filters out low-confidence noise before scoring --
        defaults to 0 (return everything) since callers may want to see
        the full picture, including weak/speculative matches.
        """
        all_findings: list[Finding] = []
        for detector in self.detectors:
            all_findings.extend(detector.detect(text))

        deduped = _dedupe(all_findings)
        filtered = [f for f in deduped if f.confidence >= min_confidence]

        scored = score_findings(filtered)
        summary = summarize(scored)

        return {"summary": summary, "findings": scored}

    def scan_lines(self, lines: list[str], *, min_confidence: float = 0.0) -> dict:
        """Scan multiple lines (e.g. a log file read line by line),
        tagging each finding with its originating line number. Useful
        once we move beyond single-blob scanning to real log files.
        """
        per_line_results = []
        for i, line in enumerate(lines, start=1):
            result = self.scan(line, min_confidence=min_confidence)
            for finding in result["findings"]:
                finding["line"] = i
            if result["findings"]:
                per_line_results.extend(result["findings"])

        per_line_results.sort(key=lambda d: d["risk_score"], reverse=True)
        summary = summarize(per_line_results)
        return {"summary": summary, "findings": per_line_results}
