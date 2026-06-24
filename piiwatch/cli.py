"""PIIWatch CLI.

Entry point: `piiwatch scan <path>`

Supports three input modes:
  - A single file:        piiwatch scan app.log
  - A directory (recurse): piiwatch scan ./logs --recursive
  - Stdin:                 cat app.log | piiwatch scan -

Output is a pretty colored summary + table by default; pass --json for
machine-readable output suitable for piping into other tools or CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from piiwatch.engine import PIIWatchEngine
from piiwatch.file_discovery import DEFAULT_EXTENSIONS, discover_files
from piiwatch.reporting.terminal import bold, dim, render_table, severity_label

engine = PIIWatchEngine()


def _scan_text(text: str, *, min_confidence: float, label: str) -> dict:
    result = engine.scan(text, min_confidence=min_confidence)
    for finding in result["findings"]:
        finding["file"] = label
    return result


def _scan_path(path: Path, *, min_confidence: float) -> dict:
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        click.echo(f"warning: could not read {path}: {exc}", err=True)
        return {"summary": {"total_findings": 0, "by_type": {}, "by_severity": {}, "overall_risk_score": 0}, "findings": []}
    return _scan_text(text, min_confidence=min_confidence, label=str(path))


def _merge_results(results: list[dict]) -> dict:
    all_findings = []
    for r in results:
        all_findings.extend(r["findings"])
    all_findings.sort(key=lambda f: f["risk_score"], reverse=True)

    from piiwatch.scoring import summarize

    return {"summary": summarize(all_findings), "findings": all_findings}


def _print_human(result: dict, *, verbose: bool) -> None:
    summary = result["summary"]
    findings = result["findings"]

    if not findings:
        click.echo(bold("PIIWatch scan complete") + " -- no findings.")
        return

    click.echo(bold("PIIWatch scan summary"))
    click.echo(
        f"  {summary['total_findings']} finding(s)  |  "
        f"overall risk score: {bold(str(summary['overall_risk_score']))}"
    )
    severity_counts = ", ".join(
        f"{sev.upper()}={count}" for sev, count in summary["by_severity"].items()
    )
    click.echo(f"  by severity: {severity_counts}")
    click.echo("")

    headers = ["SEVERITY", "TYPE", "VALUE", "RISK", "LOCATION"]
    rows = []
    for f in findings:
        location = f.get("file", "")
        if "line" in f:
            location += f":{f['line']}"
        rows.append(
            [
                severity_label(f["severity"]),
                f["pii_type"],
                f["value"],
                str(f["risk_score"]),
                dim(location) if location else "",
            ]
        )
    click.echo(render_table(rows, headers))

    if verbose:
        click.echo("")
        click.echo(bold("Context:"))
        for f in findings:
            click.echo(f"  [{f['pii_type']}] ...{f['context']}...")


@click.group()
@click.version_option(package_name="piiwatch")
def cli():
    """PIIWatch: detect and prevent sensitive data leakage in enterprise systems."""


@cli.command()
@click.argument("path", type=str)
@click.option("--recursive", "-r", is_flag=True, help="Recurse into subdirectories when PATH is a directory.")
@click.option(
    "--all-files",
    is_flag=True,
    help="When scanning a directory, scan every file regardless of extension (default: common log/text formats only).",
)
@click.option("--min-confidence", default=0.0, show_default=True, type=float, help="Drop findings below this confidence (0.0-1.0).")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON instead of a formatted summary.")
@click.option("--verbose", "-v", is_flag=True, help="Include surrounding context for each finding.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info", "none"]), default="none", help="Exit with a non-zero status if any finding meets or exceeds this severity. Useful in CI.")
def scan(path: str, recursive: bool, all_files: bool, min_confidence: float, as_json: bool, verbose: bool, fail_on: str):
    """Scan PATH for PII and secrets.

    PATH may be a file, a directory, or "-" to read from stdin.
    """
    results: list[dict] = []

    if path == "-":
        text = sys.stdin.read()
        results.append(_scan_text(text, min_confidence=min_confidence, label="<stdin>"))
    else:
        target = Path(path)
        if not target.exists():
            raise click.ClickException(f"path not found: {path}")

        if target.is_file():
            results.append(_scan_path(target, min_confidence=min_confidence))
        elif target.is_dir():
            if not recursive:
                raise click.ClickException(
                    f"{path} is a directory; pass --recursive to scan it (or scan a specific file)."
                )
            extensions = None if all_files else DEFAULT_EXTENSIONS
            files = discover_files(target, extensions=extensions)
            if not files:
                click.echo(f"no scannable files found under {path}", err=True)
            for f in files:
                results.append(_scan_path(f, min_confidence=min_confidence))
        else:
            raise click.ClickException(f"unsupported path type: {path}")

    merged = _merge_results(results)

    if as_json:
        click.echo(json.dumps(merged, indent=2))
    else:
        _print_human(merged, verbose=verbose)

    if fail_on != "none":
        severity_rank = ["info", "low", "medium", "high", "critical"]
        threshold = severity_rank.index(fail_on)
        triggered = any(severity_rank.index(f["severity"]) >= threshold for f in merged["findings"])
        if triggered:
            sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
