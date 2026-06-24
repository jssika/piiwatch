from piiwatch.detectors.credit_card import CreditCardDetector

detector = CreditCardDetector()


def test_valid_visa_detected_with_high_confidence():
    findings = detector.detect("Card on file: 4111 1111 1111 1111")
    assert len(findings) == 1
    f = findings[0]
    assert f.validated is True
    assert f.metadata["brand"] == "visa"
    assert f.confidence >= 0.9


def test_valid_amex_detected():
    findings = detector.detect("Amex: 378282246310005")
    assert len(findings) == 1
    assert findings[0].metadata["brand"] == "amex"
    assert findings[0].validated is True


def test_luhn_invalid_number_still_reported_low_confidence():
    # 4111 1111 1111 1112 fails Luhn (last digit changed)
    findings = detector.detect("Card: 4111111111111112")
    assert len(findings) == 1
    assert findings[0].validated is False
    assert findings[0].confidence < 0.5


def test_repeated_digit_sequence_ignored():
    findings = detector.detect("Reference number: 1111111111111111")
    assert findings == []


def test_no_match_in_unrelated_text():
    findings = detector.detect("The quick brown fox jumps over the lazy dog.")
    assert findings == []


def test_hyphenated_card_number():
    findings = detector.detect("4111-1111-1111-1111")
    assert len(findings) == 1
    assert findings[0].validated is True
