"""`drako baseline` — Manage scan baseline.

Commands to view and reset the scan baseline that filters
previously-acknowledged findings.
"""

from __future__ import annotations

import click


@click.group()
def baseline() -> None:
    """Manage the scan baseline for incremental adoption."""


@baseline.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
def show(directory: str) -> None:
    """Display the current baseline summary."""
    from drako.cli.baseline import Baseline

    bl = Baseline(directory)
    info = bl.summary()

    if info is None:
        click.echo("No baseline found. Run `drako scan . --baseline` to create one.")
        return

    click.echo(f"Baseline v{info['version']} — created {info['created_at']}")
    click.echo(f"Drako version: {info['drako_version']}")
    click.echo(f"Total baselined findings: {info['total_findings']}")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = info["severity_counts"].get(sev, 0)
        if count > 0:
            click.echo(f"  {sev}: {count}")


@baseline.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
def reset(directory: str) -> None:
    """Delete the baseline file."""
    from drako.cli.baseline import Baseline

    bl = Baseline(directory)
    if bl.reset():
        click.echo("Baseline deleted.")
    else:
        click.echo("No baseline file found.")
