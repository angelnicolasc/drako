"""--simple must error cleanly when combined with --format sarif or --details."""

from click.testing import CliRunner

from drako.cli.scan_command import scan


def test_simple_with_sarif_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(scan, [".", "--simple", "--format", "sarif"])
    assert result.exit_code != 0
    assert "--simple cannot be combined with --format sarif" in result.output


def test_simple_with_details_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(scan, [".", "--simple", "--details"])
    assert result.exit_code != 0
    assert "--simple cannot be combined with --details" in result.output
