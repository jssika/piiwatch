from piiwatch.detectors.phone import PhoneDetector

detector = PhoneDetector()


def test_formatted_phone_high_confidence():
    findings = detector.detect("Call us at (312) 555-0148")
    assert len(findings) == 1
    assert findings[0].confidence >= 0.8


def test_dashed_phone_with_country_code():
    findings = detector.detect("+1 312-555-0148")
    assert len(findings) == 1


def test_unformatted_run_low_confidence():
    findings = detector.detect("Tracking number 3125550148 attached")
    assert len(findings) == 1
    assert findings[0].confidence < 0.5


def test_invalid_area_code_rejected():
    # Area codes can't start with 0 or 1
    findings = detector.detect("Code: (012) 555-0148")
    assert findings == []


def test_no_match_in_plain_text():
    findings = detector.detect("Just some words with no numbers at all here.")
    assert findings == []
