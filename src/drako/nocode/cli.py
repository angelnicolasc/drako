"""`drako nocode` Click command group."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from drako.nocode.formatters import BOM_FORMATTERS, FORMATTERS
from drako.nocode.parsers import PARSERS
from drako.nocode.parsers.base import ParserError
from drako.nocode.reachability import propagate_user_input
from drako.nocode.rules import evaluate_all


_PLATFORM_CHOICE = click.Choice(sorted(PARSERS.keys()), case_sensitive=False)
_FORMAT_CHOICE = click.Choice(["text", "json", "markdown"], case_sensitive=False)


def _load(file_path: str) -> dict:
    try:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise click.UsageError(f"File not found: {file_path}")
    except json.JSONDecodeError as exc:
        raise click.UsageError(f"Invalid JSON in {file_path}: {exc.msg}")


@click.group()
def nocode() -> None:
    """Scan exported n8n / Flowise workflows for governance violations."""


@nocode.command("scan")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--platform",
    type=_PLATFORM_CHOICE,
    required=True,
    help="Source platform that produced the workflow export.",
)
@click.option(
    "--format",
    "output_format",
    type=_FORMAT_CHOICE,
    default="text",
    show_default=True,
    help="Output format.",
)
def scan_cmd(file: str, platform: str, output_format: str) -> None:
    """Scan a workflow export for governance issues."""
    payload = _load(file)
    try:
        parser = PARSERS[platform.lower()]()
        workflow = parser.parse(payload)
    except ParserError as exc:
        raise click.UsageError(str(exc))

    propagate_user_input(workflow)
    findings = evaluate_all(workflow)
    formatter = FORMATTERS[output_format.lower()]
    click.echo(formatter(workflow, findings))

    # Exit non-zero if any CRITICAL is present so CI can gate.
    if any(f.severity == "CRITICAL" for f in findings):
        sys.exit(1)


@nocode.command("bom")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--platform",
    type=_PLATFORM_CHOICE,
    required=True,
    help="Source platform that produced the workflow export.",
)
@click.option(
    "--format",
    "output_format",
    type=_FORMAT_CHOICE,
    default="text",
    show_default=True,
    help="Output format.",
)
def bom_cmd(file: str, platform: str, output_format: str) -> None:
    """Print the normalised graph (nodes + edges) without running rules."""
    payload = _load(file)
    try:
        parser = PARSERS[platform.lower()]()
        workflow = parser.parse(payload)
    except ParserError as exc:
        raise click.UsageError(str(exc))

    formatter = BOM_FORMATTERS[output_format.lower()]
    click.echo(formatter(workflow))
