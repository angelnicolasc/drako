"""`agentmesh status` — Show project & connection status."""

from __future__ import annotations

from pathlib import Path

import click

from agentmesh.config import AgentMeshConfig
from agentmesh.exceptions import AgentMeshError, ConfigError


@click.command()
@click.option("--config", "config_path", default=".agentmesh.yaml", help="Path to config file")
def status(config_path: str) -> None:
    """Show the status of your AgentMesh integration."""

    click.echo()
    click.secho("  AgentMesh Status", fg="cyan", bold=True)
    click.echo()

    # ---- Config file ----
    if not Path(config_path).exists():
        click.echo(click.style("  [config] ", fg="red") + f"{config_path} not found. Run 'agentmesh init' first.")
        raise SystemExit(1)

    try:
        config = AgentMeshConfig.load(config_path)
    except ConfigError as exc:
        click.echo(click.style("  [config] ", fg="red") + str(exc))
        raise SystemExit(1)

    click.echo(click.style("  [config] ", fg="green") + f"Config loaded from {config_path}")
    click.echo(f"           Tenant:    {config.tenant_id}")
    click.echo(f"           Framework: {config.framework}")
    click.echo(f"           Endpoint:  {config.endpoint}")

    # ---- API key ----
    try:
        api_key = config.resolve_api_key()
        masked = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "****"
        click.echo(click.style("  [auth]   ", fg="green") + f"API key: {masked}")
    except ConfigError as exc:
        click.echo(click.style("  [auth]   ", fg="red") + str(exc))
        raise SystemExit(1)

    # ---- Connectivity ----
    click.echo(click.style("  [conn]   ", fg="green") + "Testing connection...")
    try:
        from agentmesh.client import AgentMeshClient

        client = AgentMeshClient(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id)
        result = client.validate_key_sync()
        click.echo(click.style("  [conn]   ", fg="green") + "Connected to AgentMesh backend")

        # Show stats if available
        if isinstance(result, dict):
            for key in ("total_agents", "active_tasks", "avg_trust_score"):
                if key in result:
                    label = key.replace("_", " ").title()
                    click.echo(f"           {label}: {result[key]}")
    except AgentMeshError as exc:
        click.echo(click.style("  [conn]   ", fg="red") + f"Connection failed: {exc}")
        raise SystemExit(1)
    except Exception as exc:
        click.echo(click.style("  [conn]   ", fg="red") + f"Connection failed: {exc}")
        raise SystemExit(1)

    # ---- Quota ----
    try:
        quota = client.check_quota_sync()
        if isinstance(quota, dict):
            used = quota.get("used", "?")
            limit = quota.get("limit", "?")
            plan = quota.get("plan", "?")
            click.echo(click.style("  [quota]  ", fg="green") + f"Plan: {plan} | Usage: {used}/{limit}")
    except AgentMeshError:
        click.echo(click.style("  [quota]  ", fg="yellow") + "Could not fetch quota info")

    click.echo()
    click.secho("  All checks passed.", fg="green", bold=True)
    click.echo()
