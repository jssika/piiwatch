import csv
import io

from piiwatch.reporting.csv_reporter import render_csv


def _result(findings=None):
    findings = findings or []
    return {
        "summary": {
            "total_findings": len(findings),
            "by_type": {},
            "by_severity": {},
            "overall_risk_score": findings[0]["risk_score"] if findings else 0,
        },
        "findings": findings,
    }


def _finding(**overrides):
    base = {
        "pii_type": "credit_card",
        "value": "************1111",
        "start": 0,
        "end": 16,
        "confidence": 0.97,
        "validated": True,
        "source": "credit_card_detector",
        "context": "Card: 4111111111111111",
        "metadata": {"brand": "visa"},
        "severity": "critical",
        "risk_score": 92.1,
        "file": "payments.log",
    }
    base.update(overrides)
    return base


def _parse_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_has_header_row():
    output = render_csv(_result())
    headers = output.splitlines()[0].split(",")
    assert "severity" in headers
    assert "pii_type" in headers
    assert "value" in headers
    assert "risk_score" in headers


def test_csv_finding_appears_as_row():
    result = _result([_finding()])
    rows = _parse_csv(render_csv(result))
    assert len(rows) == 1
    assert rows[0]["pii_type"] == "credit_card"
    assert rows[0]["value"] == "************1111"
    assert rows[0]["severity"] == "critical"
    assert rows[0]["risk_score"] == "92.1"


def test_csv_empty_findings_produces_header_only():
    output = render_csv(_result())
    rows = _parse_csv(output)
    assert rows == []
    assert "severity" in output.splitlines()[0]


def test_csv_multiple_findings_produce_multiple_rows():
    findings = [_finding(pii_type="credit_card"), _finding(pii_type="ssn", value="*******6789")]
    rows = _parse_csv(render_csv(_result(findings)))
    assert len(rows) == 2
    types = {r["pii_type"] for r in rows}
    assert types == {"credit_card", "ssn"}


def test_csv_ai_review_fields_populated_when_present():
    finding = _finding()
    finding["ai_review"] = {
        "verdict": "confirmed",
        "reasoning": "Looks real",
        "corrected_type": None,
    }
    rows = _parse_csv(render_csv(_result([finding])))
    assert rows[0]["ai_verdict"] == "confirmed"
    assert rows[0]["ai_reasoning"] == "Looks real"


def test_csv_ai_fields_empty_when_no_review():
    rows = _parse_csv(render_csv(_result([_finding()])))
    assert rows[0]["ai_verdict"] == ""
    assert rows[0]["ai_reasoning"] == ""


def test_csv_includes_file_and_line_fields():
    finding = _finding(file="app.log", line=42)
    rows = _parse_csv(render_csv(_result([finding])))
    assert rows[0]["file"] == "app.log"
    assert rows[0]["line"] == "42"


def test_csv_is_parseable_roundtrip():
    findings = [_finding(pii_type=t) for t in ["credit_card", "ssn", "email"]]
    output = render_csv(_result(findings))
    rows = _parse_csv(output)
    assert len(rows) == 3


def test_csv_values_with_commas_are_quoted():
    finding = _finding(context="John, card 4111111111111111, exp 04/27")
    output = render_csv(_result([finding]))
    rows = _parse_csv(output)
    assert "John" in rows[0]["context"]
