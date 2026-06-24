from piiwatch.detectors.email import EmailDetector

detector = EmailDetector()


def test_simple_email_detected():
    findings = detector.detect("Contact: jane.doe@acmecorp.com for details")
    assert len(findings) == 1
    assert findings[0].raw_value == "jane.doe@acmecorp.com"
    assert findings[0].confidence >= 0.9


def test_email_with_plus_and_subdomain():
    findings = detector.detect("user+test@mail.subdomain.example.org")
    assert len(findings) == 1
    assert findings[0].metadata["domain"] == "mail.subdomain.example.org"


def test_example_domain_lower_confidence():
    findings = detector.detect("test@example.com")
    assert len(findings) == 1
    assert findings[0].confidence < 0.9


def test_multiple_emails_in_text():
    findings = detector.detect("From: a@b.com To: c@d.org")
    assert len(findings) == 2


def test_no_match_without_at_symbol():
    findings = detector.detect("This is just text without an email here.")
    assert findings == []
