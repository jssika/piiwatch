"""SARIF 2.1.0 report renderer.

SARIF (Static Analysis Results Interchange Format) is the GitHub standard
for security findings -- uploading a SARIF file to GitHub shows findings
inline on PRs and in the Security tab.

Upload in CI with:
    piiwatch scan . --recursive --format sarif --output results.sarif
    # then in your GitHub Actions workflow:
    # - uses: github/codeql-action/upload-sarif@v3
    #   with: { sarif_file: results.sarif }
"""

from __future__ import annotations

import json

_TOOL_VERSION = "0.1.0"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}


def render_sarif(result: dict) -> str:
    rules_seen: dict[str, dict] = {}
    sarif_results = []

    for f in result["findings"]:
        rule_id = f["pii_type"]
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("_", " ").title(),
                "shortDescription": {"text": f"Detected {rule_id.replace('_', ' ')} in source"},
                "properties": {"tags": ["security", "pii"]},
            }

        location_uri = f.get("file", "<stdin>").lstrip("./")
        level = _SEVERITY_TO_LEVEL.get(f.get("severity", "info"), "note")

        sarif_result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": (
                    f"Possible {rule_id.replace('_', ' ')} detected "
                    f"(risk score: {f['risk_score']}, confidence: {f['confidence']}). "
                    f"Value: {f['value']}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location_uri, "uriBaseId": "%SRCROOT%"},
                        **({"region": {"startLine": f["line"]}} if "line" in f else {}),
                    }
                }
            ],
            "properties": {
                "confidence": f.get("confidence"),
                "validated": f.get("validated"),
                "pii_type": f.get("pii_type"),
            },
        }

        ai = f.get("ai_review")
        if ai:
            sarif_result["properties"]["ai_verdict"] = ai.get("verdict")
            sarif_result["properties"]["ai_reasoning"] = ai.get("reasoning")

        sarif_results.append(sarif_result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PIIWatch",
                        "version": _TOOL_VERSION,
                        "informationUri": "https://github.com/jssika/piiwatch",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif, indent=2)
