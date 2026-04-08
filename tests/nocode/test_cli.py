"""End-to-end CLI tests for `drako nocode`."""

from pathlib import Path

from click.testing import CliRunner

from drako.nocode.cli import nocode

FIX = Path(__file__).parent / "fixtures"


def test_scan_n8n_clean_workflow_exit_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(
        nocode, ["scan", str(FIX / "n8n/clean.json"), "--platform", "n8n"]
    )
    assert result.exit_code == 0
    assert "Governance Score" in result.output


def test_scan_n8n_many_violations_exit_one_with_critical() -> None:
    runner = CliRunner()
    result = runner.invoke(
        nocode, ["scan", str(FIX / "n8n/many_violations.json"), "--platform", "n8n"]
    )
    # CRITICAL findings cause exit 1
    assert result.exit_code == 1
    assert "CRITICAL" in result.output
    assert "NC-" in result.output


def test_scan_json_format() -> None:
    runner = CliRunner()
    result = runner.invoke(
        nocode,
        ["scan", str(FIX / "n8n/one_violation.json"), "--platform", "n8n", "--format", "json"],
    )
    assert '"workflow"' in result.output
    assert '"score"' in result.output


def test_bom_command_renders_graph() -> None:
    runner = CliRunner()
    result = runner.invoke(
        nocode, ["bom", str(FIX / "n8n/clean.json"), "--platform", "n8n"]
    )
    assert result.exit_code == 0
    assert "Bill of Materials" in result.output
    assert "Webhook" in result.output


def test_flowise_violations_detected() -> None:
    runner = CliRunner()
    result = runner.invoke(
        nocode, ["scan", str(FIX / "flowise/violations.json"), "--platform", "flowise"]
    )
    assert "NC-" in result.output


def test_unknown_platform_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(
        nocode, ["scan", str(FIX / "n8n/clean.json"), "--platform", "wrong"]
    )
    assert result.exit_code != 0
