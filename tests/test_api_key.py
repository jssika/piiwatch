from piiwatch.detectors.api_key import APIKeyDetector

detector = APIKeyDetector()


def test_aws_access_key_detected():
    findings = detector.detect("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert len(findings) == 1
    assert findings[0].metadata["provider"] == "aws_access_key_id"
    assert findings[0].confidence >= 0.9


def test_github_token_detected():
    findings = detector.detect("token: ghp_16C7e42F292c6912E7710c838347Ae178B4a")
    providers = [f.metadata.get("provider") for f in findings]
    assert "github_token" in providers


def test_slack_token_detected():
    findings = detector.detect("xoxb-12345678901-ABCDEFGHIJKLMNOPQRSTUVWX")
    assert any(f.metadata.get("provider") == "slack_token" for f in findings)


def test_stripe_key_detected():
    findings = detector.detect("sk_live_4eC39HqLyjWDarjtT1zdp7dc")
    assert any(f.metadata.get("provider") == "stripe_key" for f in findings)


def test_generic_high_entropy_secret_detected():
    findings = detector.detect('api_key = "x8Hf92QpL0zR7vMnT4eYcW1sKdJ6aN3b"')
    assert len(findings) == 1
    assert findings[0].metadata["field_name"] == "api_key"


def test_low_entropy_placeholder_not_flagged():
    findings = detector.detect('password = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"')
    assert findings == []


def test_no_duplicate_when_known_pattern_also_matches_generic():
    text = "api_key=AKIAIOSFODNN7EXAMPLE"
    findings = detector.detect(text)
    # Should only get the high-confidence AWS match, not also a generic one
    providers = [f.metadata.get("provider") for f in findings]
    assert providers.count("aws_access_key_id") == 1


def test_no_match_in_plain_sentence():
    findings = detector.detect("The weather today is sunny and warm.")
    assert findings == []
