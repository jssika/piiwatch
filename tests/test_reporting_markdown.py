from piiwatch.reporting.markdown_reporter import render_markdown


def _result(findings=None):
    findings = findings or []
    by_sev = {}
    by_type = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_type[f["pii_type"]] = by_type.get(f["pii_type"], 0) + 1
    return {
        "summary": {
            "total_findings": len(findings),
            "by_type": by_type,
            "by_severity": by_sev,
            "overall_risk_score": findings[0]["risk_score"] if findings else 0,
        },
        "findings": findings,
    }


def _finding(**overrides):
    base = {
        "pii_type": "credit_card",
        "value": "************1111",
        "confidence": 0.97,
        "validated": True,
        "source": "credit_card_detector",
        "context": "Card: 4111111111111111",
        "metadata": {},
        "severity": "critical",
        "risk_score": 92.1,
        "file": "payments.log",
    }
    base.update(overrides)
    return base


def test_markdown_has_h1_title():
    output = render_markdown(_result())
    assert output.startswith("# PIIWatch Scan Report")


def test_markdown_has_summary_section():
    output = render_markdown(_result([_finding()]))
    assert "## Summary" in output
    assert "Total findings" in output
    assert "Overall risk score" in output


def test_markdown_has_findings_table():
    output = render_markdown(_result([_finding()]))
    assert "## Findings" in output
    assert "| Severity |" in output
    assert "|----------|" in output


def test_markdown_finding_appears_in_table():
    output = render_markdown(_result([_finding()]))
    assert "credit_card" in output
    assert "************1111" in output
    assert "CRITICAL" in output


def test_markdown_empty_findings_shows_no_findings():
    output = render_markdown(_result())
    assert "No findings" in output
    assert "## Findings" not in output


def test_markdown_value_wrapped_in_backticks():
    output = render_markdown(_result([_finding()]))
    assert "`************1111`" in output


def test_markdown_severity_is_uppercased():
    output = render_markdown(_result([_finding(severity="high")]))
    assert "HIGH" in output


def test_markdown_file_location_in_table():
    output = render_markdown(_result([_finding(file="logs/app.log")]))
    assert "logs/app.log" in output


def test_markdown_line_number_appended_when_present():
    finding = _finding(file="app.log", line=7)
    output = render_markdown(_result([finding]))
    assert "app.log:7" in output


def test_markdown_ai_review_section_appears_when_present():
    finding = _finding()
    finding["ai_review"] = {
        "verdict": "confirmed",
        "reasoning": "Real card in production log",
        "corrected_type": None,
    }
    output = render_markdown(_result([finding]))
    assert "## AI Review Notes" in output
    assert "confirmed" in output
    assert "Real card in production log" in output


def test_markdown_no_ai_section_when_no_reviews():
    output = render_markdown(_result([_finding()]))
    assert "## AI Review Notes" not in output


def test_markdown_multiple_findings_all_in_table():
    findings = [
        _finding(pii_type="credit_card", value="************1111"),
        _finding(pii_type="ssn", value="*******6789", severity="critical", risk_score=85.5),
        _finding(pii_type="email", value="*****@b.com", severity="low", risk_score=28.5),
    ]
    output = render_markdown(_result(findings))
    assert "credit_card" in output
    assert "ssn" in output
    assert "email" in output


def test_markdown_summary_includes_severity_counts():
    findings = [_finding(severity="critical"), _finding(pii_type="email", severity="low", risk_score=28.5)]
    output = render_markdown(_result(findings))
    assert "CRITICAL" in output
    assert "LOW" in output


def test_markdown_ends_with_newline():
    output = render_markdown(_result())
    assert output.endswith("\n")
