from piiwatch.ai.classifier import AIClassifier
from piiwatch.engine import PIIWatchEngine
from tests.fakes import FakeProvider


def test_engine_without_classifier_behaves_as_before():
    engine = PIIWatchEngine()
    result = engine.scan("email a@b.com")
    assert result["summary"]["total_findings"] == 1
    assert "ai_review" not in result["findings"][0]


def test_engine_with_classifier_reviews_ambiguous_findings():
    provider = FakeProvider(
        responses=[{"verdict": "rejected", "confidence": 0.9, "corrected_type": "none", "reasoning": "tracking id, not a phone"}]
    )
    classifier = AIClassifier(provider=provider)
    engine = PIIWatchEngine(classifier=classifier)

    text = "tracking id 3125550148 attached"  # unformatted phone, low confidence -> ambiguous
    result = engine.scan(text)

    findings = result["findings"]
    assert len(findings) == 1
    assert findings[0]["ai_review"]["verdict"] == "rejected"


def test_engine_use_ai_false_skips_classifier_even_if_configured():
    provider = FakeProvider(responses=[{"verdict": "rejected", "confidence": 0.9, "corrected_type": "none", "reasoning": "x"}])
    classifier = AIClassifier(provider=provider)
    engine = PIIWatchEngine(classifier=classifier)

    result = engine.scan("tracking id 3125550148 attached", use_ai=False)

    assert len(provider.calls) == 0
    assert "ai_review" not in result["findings"][0]


def test_min_confidence_applied_after_ai_review():
    # AI rejects the finding, driving confidence down -- min_confidence
    # filtering should see the POST-review confidence, not the original.
    provider = FakeProvider(
        responses=[{"verdict": "rejected", "confidence": 0.95, "corrected_type": "none", "reasoning": "false positive"}]
    )
    classifier = AIClassifier(provider=provider)
    engine = PIIWatchEngine(classifier=classifier)

    result = engine.scan("tracking id 3125550148 attached", min_confidence=0.5)

    assert result["summary"]["total_findings"] == 0


def test_ai_failure_does_not_break_scan():
    provider = FakeProvider(raise_error="simulated outage")
    classifier = AIClassifier(provider=provider)
    engine = PIIWatchEngine(classifier=classifier)

    result = engine.scan("tracking id 3125550148 attached, SSN 123-45-6789")

    # Scan should still complete and return both findings, just without
    # AI enrichment on the one that would have been reviewed.
    assert result["summary"]["total_findings"] == 2
