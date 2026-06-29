import json

from piiwatch.reporting.sarif_reporter import render_sarif


def _result(findings=None):
    findings = findings or []
    return {
        "summary": {
            "total_findings": len(findings),
            "by_type": {},
            "by_severity": {},
            "overall_risk_score": 0,
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


def _parse(result):
    return json.loads(render_sarif(result))


def test_sarif_output_is_valid_json():
    output = render_sarif(_result())
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_sarif_has_correct_schema():
    sarif = _parse(_result())
    assert "sarif-schema-2.1.0" in sarif["$schema"]
    assert sarif["version"] == "2.1.0"


def test_sarif_has_runs_array():
    sarif = _parse(_result())
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_tool_driver_has_name():
    sarif = _parse(_result())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PIIWatch"
    assert "version" in driver


def test_sarif_empty_findings_produces_empty_results():
    sarif = _parse(_result())
    assert sarif["runs"][0]["results"] == []


def test_sarif_finding_produces_result():
    sarif = _parse(_result([_finding()]))
    results = sarif["runs"][0]["results"]
    assert len(results) == 1


def test_sarif_result_has_rule_id_matching_pii_type():
    sarif = _parse(_result([_finding(pii_type="ssn")]))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "ssn"


def test_sarif_critical_maps_to_error_level():
    sarif = _parse(_result([_finding(severity="critical")]))
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_sarif_high_maps_to_error_level():
    sarif = _parse(_result([_finding(severity="high")]))
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_sarif_medium_maps_to_warning_level():
    sarif = _parse(_result([_finding(severity="medium")]))
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_low_maps_to_note_level():
    sarif = _parse(_result([_finding(severity="low")]))
    assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_sarif_result_has_location_with_file():
    sarif = _parse(_result([_finding(file="logs/app.log")]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
    assert "logs/app.log" in uri


def test_sarif_result_includes_line_number_when_present():
    finding = _finding(file="app.log", line=42)
    sarif = _parse(_result([finding]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["region"]["startLine"] == 42


def test_sarif_result_omits_region_when_no_line():
    sarif = _parse(_result([_finding()]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert "region" not in loc["physicalLocation"]


def test_sarif_rule_generated_per_pii_type():
    findings = [
        _finding(pii_type="credit_card"),
        _finding(pii_type="ssn"),
        _finding(pii_type="email"),
    ]
    sarif = _parse(_result(findings))
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"credit_card", "ssn", "email"}


def test_sarif_duplicate_pii_types_produce_one_rule():
    findings = [_finding(pii_type="email"), _finding(pii_type="email")]
    sarif = _parse(_result(findings))
    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids.count("email") == 1


def test_sarif_message_contains_pii_type_and_risk():
    sarif = _parse(_result([_finding(pii_type="credit_card", risk_score=92.1)]))
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "credit card" in msg.lower()
    assert "92.1" in msg


def test_sarif_result_properties_include_confidence():
    sarif = _parse(_result([_finding(confidence=0.97)]))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["confidence"] == 0.97


def test_sarif_ai_review_fields_in_properties_when_present():
    finding = _finding()
    finding["ai_review"] = {
        "verdict": "confirmed",
        "reasoning": "Real card",
        "corrected_type": None,
    }
    sarif = _parse(_result([finding]))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["ai_verdict"] == "confirmed"
    assert props["ai_reasoning"] == "Real card"


def test_sarif_no_ai_fields_when_no_review():
    sarif = _parse(_result([_finding()]))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "ai_verdict" not in props
