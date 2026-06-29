import json
import os

from click.testing import CliRunner

from piiwatch.cli import cli

os.environ["NO_COLOR"] = "1"  # keep test output deterministic, no ANSI codes


def test_scan_single_file_human_output(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("user email is jane.doe@acmecorp.com")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file)])

    assert result.exit_code == 0
    assert "PIIWatch scan summary" in result.output
    assert "email" in result.output


def test_scan_single_file_json_output(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789 found in record")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["pii_type"] == "ssn"


def test_scan_directory_requires_recursive_flag(tmp_path):
    (tmp_path / "a.log").write_text("nothing sensitive here")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code != 0
    assert "--recursive" in result.output


def test_scan_directory_recursive_finds_nested_files(tmp_path):
    nested = tmp_path / "sub"
    nested.mkdir()
    (tmp_path / "a.log").write_text("card 4111111111111111")
    (nested / "b.log").write_text("email a@b.com")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--recursive", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["total_findings"] == 2
    files_seen = {f["file"] for f in data["findings"]}
    assert any("a.log" in f for f in files_seen)
    assert any("b.log" in f for f in files_seen)


def test_scan_nonexistent_path_errors():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "/no/such/path.log"])

    assert result.exit_code != 0
    assert "not found" in result.output


def test_scan_stdin():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "-", "--json"], input="contact a@b.com please")

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["file"] == "<stdin>"


def test_fail_on_threshold_triggers_nonzero_exit(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")  # critical severity

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--fail-on", "critical", "--json"])

    assert result.exit_code == 1


def test_fail_on_threshold_not_triggered_when_below(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("contact a@b.com")  # low severity only

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--fail-on", "critical", "--json"])

    assert result.exit_code == 0


def test_min_confidence_filters_results(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("tracking id 3125550148")  # unformatted phone, low confidence

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--min-confidence", "0.8", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["total_findings"] == 0


def test_no_findings_message(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("nothing sensitive in this line at all")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file)])

    assert result.exit_code == 0
    assert "no findings" in result.output


def test_ai_provider_missing_sdk_fails_gracefully(tmp_path):
    # Simulate the SDK not being installed by patching the import inside
    # the provider module -- the CLI must report a clear error and exit
    # non-zero rather than crashing with an ImportError traceback.
    import unittest.mock

    log_file = tmp_path / "app.log"
    log_file.write_text("email a@b.com")

    runner = CliRunner()
    with unittest.mock.patch.dict("sys.modules", {"anthropic": None}):
        result = runner.invoke(cli, ["scan", str(log_file), "--ai-provider", "anthropic"])

    assert result.exit_code != 0
    assert "anthropic" in result.output.lower()


def test_ai_provider_invalid_choice_rejected_by_click(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("email a@b.com")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--ai-provider", "not-a-real-provider"])

    assert result.exit_code != 0
    assert "Invalid value" in result.output or "invalid choice" in result.output.lower()


def test_scan_without_ai_provider_unaffected(tmp_path):
    # Sanity check: omitting --ai-provider entirely must still work
    # exactly as before, with zero AI involvement.
    log_file = tmp_path / "app.log"
    log_file.write_text("email a@b.com")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "ai_review" not in data["findings"][0]


# ---------------------------------------------------------------------------
# --format flag
# ---------------------------------------------------------------------------

def test_format_json_equivalent_to_json_flag(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    r1 = runner.invoke(cli, ["scan", str(log_file), "--json"])
    r2 = runner.invoke(cli, ["scan", str(log_file), "--format", "json"])

    assert r1.exit_code == r2.exit_code == 0
    assert json.loads(r1.output) == json.loads(r2.output)


def test_format_csv_outputs_csv_with_header(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "csv"])

    assert result.exit_code == 0
    first_line = result.output.splitlines()[0]
    assert "severity" in first_line
    assert "pii_type" in first_line
    assert "value" in first_line


def test_format_csv_finding_row_present(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("card 4111111111111111")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "csv"])

    assert result.exit_code == 0
    assert "credit_card" in result.output


def test_format_markdown_outputs_markdown(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "markdown"])

    assert result.exit_code == 0
    assert "# PIIWatch Scan Report" in result.output
    assert "## Summary" in result.output


def test_format_markdown_finding_in_table(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "markdown"])

    assert result.exit_code == 0
    assert "ssn" in result.output
    assert "| Severity |" in result.output


def test_format_html_outputs_html(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "html"])

    assert result.exit_code == 0
    assert "<!DOCTYPE html>" in result.output
    assert "<title>PIIWatch Report</title>" in result.output


def test_format_html_contains_finding(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("card 4111111111111111")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "html"])

    assert result.exit_code == 0
    assert "credit_card" in result.output
    assert "CRITICAL" in result.output


def test_format_sarif_outputs_valid_json(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "sarif"])

    assert result.exit_code == 0
    sarif = json.loads(result.output)
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif


def test_format_sarif_finding_has_correct_rule(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "sarif"])

    sarif = json.loads(result.output)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "ssn" in rule_ids


def test_format_terminal_is_default(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file)])

    assert result.exit_code == 0
    assert "PIIWatch scan summary" in result.output


def test_format_invalid_choice_rejected(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "pdf"])

    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# --output flag
# ---------------------------------------------------------------------------

def test_output_flag_writes_to_file(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")
    out_file = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "json", "--output", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["summary"]["total_findings"] == 1


def test_output_flag_writes_csv_to_file(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("card 4111111111111111")
    out_file = tmp_path / "report.csv"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "csv", "--output", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text()
    assert "severity" in content
    assert "credit_card" in content


def test_output_flag_writes_html_to_file(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")
    out_file = tmp_path / "report.html"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "html", "--output", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    assert "<!DOCTYPE html>" in out_file.read_text()


def test_output_flag_confirmation_message_shown(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")
    out_file = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "json", "--output", str(out_file)])

    assert result.exit_code == 0
    # The CLI echoes a "Report written to ..." confirmation
    assert str(out_file) in result.output


def test_output_flag_markdown_file_written(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("SSN 123-45-6789")
    out_file = tmp_path / "report.md"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(log_file), "--format", "markdown", "--output", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    assert "# PIIWatch" in out_file.read_text()
