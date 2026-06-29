"""Markdown report renderer."""

from __future__ import annotations


def render_markdown(result: dict) -> str:
    summary = result["summary"]
    findings = result["findings"]
    lines = []

    lines.append("# PIIWatch Scan Report\n")
    lines.append("## Summary\n")
    lines.append(f"- **Total findings:** {summary['total_findings']}")
    lines.append(f"- **Overall risk score:** {summary['overall_risk_score']}")

    if summary["by_severity"]:
        severity_parts = ", ".join(f"**{k.upper()}**: {v}" for k, v in summary["by_severity"].items())
        lines.append(f"- **By severity:** {severity_parts}")

    if summary["by_type"]:
        type_parts = ", ".join(f"{k}: {v}" for k, v in summary["by_type"].items())
        lines.append(f"- **By type:** {type_parts}")

    lines.append("")

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.append("## Findings\n")
    lines.append("| Severity | Type | Value | Risk | File | AI Verdict |")
    lines.append("|----------|------|-------|------|------|------------|")

    for f in findings:
        location = f.get("file", "")
        if "line" in f:
            location += f":{f['line']}"
        ai = f.get("ai_review") or {}
        verdict = ai.get("verdict", "")
        lines.append(
            f"| {f['severity'].upper()} "
            f"| {f['pii_type']} "
            f"| `{f['value']}` "
            f"| {f['risk_score']} "
            f"| {location} "
            f"| {verdict} |"
        )

    has_ai = any(f.get("ai_review") for f in findings)
    if has_ai:
        lines.append("\n## AI Review Notes\n")
        for f in findings:
            ai = f.get("ai_review")
            if ai and ai.get("reasoning"):
                lines.append(f"- **[{f['pii_type']}]** `{f['value']}` — {ai['verdict']}: {ai['reasoning']}")

    return "\n".join(lines) + "\n"
