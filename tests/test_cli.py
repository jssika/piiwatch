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
    # In this environment neither the anthropic nor openai SDK is
    # installed, so this exercises the real "SDK not available" path --
    # the CLI must report a clear error and exit non-zero, not crash.
    log_file = tmp_path / "app.log"
    log_file.write_text("email a@b.com")

    runner = CliRunner()
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
