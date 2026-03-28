"""CLI command: drako rollback — revert to a previous policy version."""

from __future__ import annotations

import click

from drako.cli._helpers import load_client_safe, parse_version


@click.command()
@click.argument("version", type=str)
@click.option("--config", "-c", "config_path", default=None, help="Path to .drako.yaml")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def rollback(version: str, config_path: str | None, yes: bool) -> None:
    """Rollback to a previous policy version (requires Pro)."""
    version = parse_version(version)
    client = load_client_safe(config_path)

    if not yes:
        click.echo(f"Rolling back to v{version}...")
        if not click.confirm("This will create a new version with old content. Continue?"):
            click.echo("Aborted.")
            return

    try:
        resp = client._request_sync(
            "POST",
            "/api/v1/policies/snapshots/rollback",
            json={"version": version},
        )
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        return

    new_version = resp.get("version", "?")
    click.echo()
    click.secho(f"[OK] Rolled back to v{version}. New version: v{new_version}", fg="green")
    click.secho("[OK] Config pushed to platform", fg="green")
