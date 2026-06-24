from piiwatch.engine import PIIWatchEngine

engine = PIIWatchEngine()


def test_scan_detects_multiple_pii_types():
    text = (
        "User jane.doe@acmecorp.com (SSN 123-45-6789) paid with card "
        "4111 1111 1111 1111. AWS key AKIAIOSFODNN7EXAMPLE was logged."
    )
    result = engine.scan(text)
    types_found = {f["pii_type"] for f in result["findings"]}
    assert {"email", "ssn", "credit_card", "api_key"} <= types_found
    assert result["summary"]["total_findings"] == len(result["findings"])


def test_scan_empty_text_returns_no_findings():
    result = engine.scan("")
    assert result["findings"] == []
    assert result["summary"]["total_findings"] == 0


def test_scan_orders_findings_by_risk_score_descending():
    text = "Email a@b.com and SSN 123-45-6789 both appear here."
    result = engine.scan(text)
    scores = [f["risk_score"] for f in result["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_min_confidence_filters_weak_matches():
    text = "Tracking ID 3125550148"  # unformatted phone-like number, low confidence
    full = engine.scan(text, min_confidence=0.0)
    filtered = engine.scan(text, min_confidence=0.8)
    assert len(full["findings"]) >= len(filtered["findings"])


def test_summary_counts_by_severity():
    text = "SSN 123-45-6789 and card 4111111111111111"
    result = engine.scan(text)
    assert result["summary"]["by_severity"].get("critical", 0) >= 1


def test_scan_lines_tags_line_numbers():
    lines = [
        "normal log line, nothing here",
        "user email is test@company.com",
        "card 4111111111111111 charged",
    ]
    result = engine.scan_lines(lines)
    line_numbers = {f["line"] for f in result["findings"]}
    assert 2 in line_numbers
    assert 3 in line_numbers
    assert 1 not in line_numbers


def test_redaction_never_exposes_full_raw_value_by_default():
    text = "card 4111111111111111"
    result = engine.scan(text)
    finding = result["findings"][0]
    assert finding["value"] != "4111111111111111"
    assert finding["value"].endswith("1111")
