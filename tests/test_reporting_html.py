import json

from piiwatch.reporting.html_reporter import render_html


def _result(findings=None):
    findings = findings or []
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "summary": {
            "total_findings": len(findings),
            "by_type": {},
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
        "context": "Card: 4111 1111 1111 1111",
        "metadata": {},
        "severity": "critical",
        "risk_score": 92.1,
        "file": "payments.log",
    }
    base.update(overrides)
    return base


def test_html_starts_with_doctype():
    output = render_html(_result())
    assert output.strip().startswith("<!DOCTYPE html>")


def test_html_has_html_head_body_structure():
    output = render_html(_result())
    assert "<html" in output
    assert "<head>" in output
    assert "<body>" in output
    assert "</html>" in output


def test_html_has_title_tag():
    output = render_html(_result())
    assert "<title>PIIWatch Report</title>" in output


def test_html_finding_value_appears_in_output():
    output = render_html(_result([_finding()]))
    assert "************1111" in output


def test_html_pii_type_appears():
    output = render_html(_result([_finding(pii_type="ssn", value="*******6789")]))
    assert "ssn" in output


def test_html_severity_badge_rendered():
    output = render_html(_result([_finding(severity="critical")]))
    assert "CRITICAL" in output


def test_html_file_location_present():
    output = render_html(_result([_finding(file="logs/app.log")]))
    assert "logs/app.log" in output


def test_html_embeds_raw_json_data():
    result = _result([_finding()])
    output = render_html(result)
    assert "PIIWATCH_DATA" in output
    # Extract and validate the embedded JSON
    start = output.index("PIIWATCH_DATA = ") + len("PIIWATCH_DATA = ")
    end = output.index(";", start)
    embedded = json.loads(output[start:end])
    assert embedded["summary"]["total_findings"] == 1


def test_html_escapes_special_characters_in_table_cells():
    # The context value should be HTML-escaped in the table cell so it
    # doesn't render as actual HTML. The embedded JSON data block is in a
    # <script> tag and doesn't need escaping there.
    finding = _finding(context='<b>bold</b> and <i>italic</i>')
    output = render_html(_result([finding]))
    # The table cell must escape the tags
    assert "&lt;b&gt;" in output
    # The raw tags must not appear outside the script data block
    script_start = output.index("<script>")
    html_body = output[:script_start]
    assert "<b>bold</b>" not in html_body


def test_html_empty_findings_shows_no_findings_cell():
    output = render_html(_result())
    assert "No findings" in output


def test_html_ai_review_verdict_shown():
    finding = _finding()
    finding["ai_review"] = {
        "verdict": "confirmed",
        "reasoning": "Real transaction log",
        "corrected_type": None,
    }
    output = render_html(_result([finding]))
    assert "confirmed" in output
    assert "Real transaction log" in output


def test_html_severity_pill_shown_in_summary():
    output = render_html(_result([_finding(severity="critical")]))
    assert "CRITICAL" in output


def test_html_total_findings_count_shown():
    findings = [_finding(), _finding(pii_type="ssn")]
    output = render_html(_result(findings))
    assert "2" in output


def test_html_risk_score_shown():
    output = render_html(_result([_finding(risk_score=92.1)]))
    assert "92.1" in output


def test_html_multiple_findings_all_rendered():
    findings = [
        _finding(pii_type="credit_card", value="************1111"),
        _finding(pii_type="ssn", value="*******6789"),
        _finding(pii_type="email", value="*****@acme.com"),
    ]
    output = render_html(_result(findings))
    assert "credit_card" in output
    assert "ssn" in output
    assert "email" in output
