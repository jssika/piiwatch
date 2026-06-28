"""CSV report renderer."""

from __future__ import annotations

import csv
import io


def render_csv(result: dict) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "pii_type", "value", "risk_score", "confidence", "validated", "file", "line", "context", "ai_verdict", "ai_reasoning"])
    for f in result["findings"]:
        ai = f.get("ai_review") or {}
        writer.writerow([
            f.get("severity", ""),
            f.get("pii_type", ""),
            f.get("value", ""),
            f.get("risk_score", ""),
            f.get("confidence", ""),
            f.get("validated", ""),
            f.get("file", ""),
            f.get("line", ""),
            f.get("context", ""),
            ai.get("verdict", ""),
            ai.get("reasoning", ""),
        ])
    return output.getvalue()
