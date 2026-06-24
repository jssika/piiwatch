from piiwatch.detectors.ssn import SSNDetector

detector = SSNDetector()


def test_hyphenated_ssn_detected_high_confidence():
    findings = detector.detect("Employee SSN: 123-45-6789")
    assert len(findings) == 1
    assert findings[0].validated is True
    assert findings[0].confidence >= 0.8


def test_invalid_area_code_rejected():
    findings = detector.detect("Bad SSN: 000-12-3456")
    assert findings == []


def test_invalid_900_area_rejected():
    findings = detector.detect("Bad SSN: 912-34-5678")
    assert findings == []


def test_invalid_group_rejected_but_format_matches():
    # 666 area is invalid per SSA rules
    findings = detector.detect("SSN: 666-12-3456")
    assert findings == []


def test_plain_digit_ssn_lower_confidence():
    findings = detector.detect("ID 123456789 on file")
    assert len(findings) == 1
    assert findings[0].confidence < 0.5


def test_no_false_positive_on_normal_text():
    findings = detector.detect("Order total: $123.45, quantity 6789")
    assert findings == []
