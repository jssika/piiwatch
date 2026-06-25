from piiwatch.ai.classifier import AIClassifier
from piiwatch.detectors.base import Finding, PIIType
from tests.fakes import FakeProvider, MalformedProvider


def _make_finding(pii_type=PIIType.PHONE, confidence=0.45, start=10, end=20):
    return Finding(
        pii_type=pii_type,
        raw_value="3125550148",
        start=start,
        end=end,
        confidence=confidence,
        validated=True,
        source="phone_detector",
        context="tracking id 3125550148 attached",
        metadata={"area_code": "312"},
    )


def test_ambiguous_finding_gets_reviewed():
    provider = FakeProvider(
        responses=[{"verdict": "rejected", "confidence": 0.9, "corrected_type": "none", "reasoning": "looks like a tracking ID"}]
    )
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.45)  # within default ambiguity band

    reviewed = classifier.review([finding], "tracking id 3125550148 attached")

    assert len(provider.calls) == 1
    assert reviewed[0].ai_reviewed is True
    assert reviewed[0].ai_verdict == "rejected"
    assert reviewed[0].confidence < finding.confidence


def test_confident_finding_skipped_by_default():
    provider = FakeProvider(responses=[])
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.97)  # above ambiguity band

    reviewed = classifier.review([finding], "card 4111111111111111")

    assert len(provider.calls) == 0
    assert reviewed[0].ai_reviewed is False
    assert reviewed[0] is finding


def test_force_all_reviews_even_confident_findings():
    provider = FakeProvider(
        responses=[{"verdict": "confirmed", "confidence": 0.95, "corrected_type": "phone", "reasoning": "real number"}]
    )
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.97)

    reviewed = classifier.review([finding], "call 3125550148 now", force_all=True)

    assert len(provider.calls) == 1
    assert reviewed[0].ai_verdict == "confirmed"


def test_confirmed_verdict_updates_confidence():
    provider = FakeProvider(
        responses=[{"verdict": "confirmed", "confidence": 0.85, "corrected_type": "phone", "reasoning": "valid number in context"}]
    )
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.45)

    reviewed = classifier.review([finding], "call 3125550148 now")

    assert reviewed[0].ai_verdict == "confirmed"
    assert reviewed[0].confidence == 0.85
    assert reviewed[0].pii_type == PIIType.PHONE
    assert reviewed[0].corrected_type is None


def test_retyped_verdict_changes_pii_type():
    provider = FakeProvider(
        responses=[
            {
                "verdict": "confirmed",
                "confidence": 0.8,
                "corrected_type": "generic_secret",
                "reasoning": "this is actually an internal ID, not a phone number, but looks secret-like",
            }
        ]
    )
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(pii_type=PIIType.PHONE, confidence=0.5)

    reviewed = classifier.review([finding], "internal ref 3125550148 used")

    assert reviewed[0].ai_verdict == "retyped"
    assert reviewed[0].pii_type == PIIType.GENERIC_SECRET
    assert reviewed[0].corrected_type == PIIType.GENERIC_SECRET


def test_provider_failure_falls_back_to_original_finding():
    provider = FakeProvider(raise_error="simulated network failure")
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.5)

    reviewed = classifier.review([finding], "tracking id 3125550148 attached")

    assert reviewed[0] is finding
    assert reviewed[0].ai_reviewed is False


def test_malformed_response_falls_back_to_original_finding():
    classifier = AIClassifier(provider=MalformedProvider())
    finding = _make_finding(confidence=0.5)

    reviewed = classifier.review([finding], "tracking id 3125550148 attached")

    assert reviewed[0] is finding
    assert reviewed[0].ai_reviewed is False


def test_invalid_verdict_value_falls_back():
    provider = FakeProvider(responses=[{"verdict": "maybe", "confidence": 0.5, "corrected_type": "none", "reasoning": "unsure"}])
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.5)

    reviewed = classifier.review([finding], "some context here")

    assert reviewed[0].ai_reviewed is False


def test_out_of_range_confidence_falls_back():
    provider = FakeProvider(responses=[{"verdict": "confirmed", "confidence": 1.5, "corrected_type": "phone", "reasoning": "bad value"}])
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.5)

    reviewed = classifier.review([finding], "some context here")

    assert reviewed[0].ai_reviewed is False


def test_context_window_is_bounded():
    provider = FakeProvider(responses=[{"verdict": "confirmed", "confidence": 0.7, "corrected_type": "phone", "reasoning": "ok"}])
    classifier = AIClassifier(provider=provider, context_chars=5)
    long_text = "x" * 100 + "3125550148" + "y" * 100
    finding = _make_finding(confidence=0.5, start=100, end=110)

    classifier.review([finding], long_text)

    sent_prompt = provider.calls[0].user_prompt
    # Only ~5 chars of padding on each side should appear, not the full 100
    assert "x" * 100 not in sent_prompt
    assert "y" * 100 not in sent_prompt


def test_reasoning_is_preserved_for_audit_trail():
    provider = FakeProvider(
        responses=[{"verdict": "rejected", "confidence": 0.9, "corrected_type": "none", "reasoning": "this is a tracking number, not PII"}]
    )
    classifier = AIClassifier(provider=provider)
    finding = _make_finding(confidence=0.5)

    reviewed = classifier.review([finding], "tracking id 3125550148 attached")

    assert reviewed[0].ai_reasoning == "this is a tracking number, not PII"


def test_multiple_findings_only_ambiguous_ones_call_provider():
    provider = FakeProvider(
        responses=[{"verdict": "confirmed", "confidence": 0.6, "corrected_type": "phone", "reasoning": "ok"}]
    )
    classifier = AIClassifier(provider=provider)
    ambiguous = _make_finding(confidence=0.5, start=0, end=10)
    confident = _make_finding(confidence=0.95, start=20, end=30)

    classifier.review([ambiguous, confident], "x" * 40)

    assert len(provider.calls) == 1


def test_raw_value_redacted_in_prompt_by_default():
    provider = FakeProvider(responses=[{"verdict": "confirmed", "confidence": 0.6, "corrected_type": "phone", "reasoning": "ok"}])
    classifier = AIClassifier(provider=provider)  # send_raw_values=False by default
    finding = _make_finding(confidence=0.5, start=12, end=22)
    text = "call me at 3125550148 today"

    classifier.review([finding], text)

    prompt = provider.calls[0].user_prompt
    assert "3125550148" not in prompt
    assert "*" in prompt


def test_raw_value_sent_when_explicitly_enabled():
    provider = FakeProvider(responses=[{"verdict": "confirmed", "confidence": 0.6, "corrected_type": "phone", "reasoning": "ok"}])
    classifier = AIClassifier(provider=provider, send_raw_values=True)
    finding = _make_finding(confidence=0.5, start=11, end=21)
    text = "call me at 3125550148 today"

    classifier.review([finding], text)

    prompt = provider.calls[0].user_prompt
    assert "3125550148" in prompt


def test_span_markers_disambiguate_nearby_findings():
    # Two phone-shaped matches close enough together that their context
    # windows overlap -- the >>> <<< markers must make it unambiguous
    # which one is actually being judged in each separate call.
    provider = FakeProvider(
        responses=[
            {"verdict": "confirmed", "confidence": 0.6, "corrected_type": "phone", "reasoning": "first"},
            {"verdict": "confirmed", "confidence": 0.6, "corrected_type": "phone", "reasoning": "second"},
        ]
    )
    classifier = AIClassifier(provider=provider, send_raw_values=True, context_chars=80)
    text = "Order tracking reference 3125550148 created for shipment. Customer callback number on file: 7735551234, please contact ASAP."

    from piiwatch.detectors.phone import PhoneDetector

    findings = PhoneDetector().detect(text)
    assert len(findings) == 2

    classifier.review(findings, text)

    first_prompt = provider.calls[0].user_prompt
    second_prompt = provider.calls[1].user_prompt
    # Each prompt's marker must wrap that call's own value, not the other one
    assert ">>>3125550148<<<" in first_prompt
    assert ">>>7735551234<<<" in second_prompt
