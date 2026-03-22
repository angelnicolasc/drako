# mypy: strict
"""MCP Governance Directory Scanner — CLI entry point.

Scans popular MCP servers for governance characteristics and
generates a graded directory in JSON and HTML formats.

Usage:
    python scan_directory.py                    # fetch + analyze all 20 servers
    python scan_directory.py --offline          # use cached data only
    python scan_directory.py --servers github,slack,filesystem
    python scan_directory.py --format json      # JSON only
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import httpx

from governance_analyzer import ServerAnalysis, analyze_server
from manifest_cache import fetch_server_content
from mcp_configs import MCP_SERVERS, MCPServerConfig, get_servers_by_name
from report_generator import generate_html_report, generate_json_report


@click.command()
@click.option(
    "--output", "output_dir",
    type=click.Path(),
    default="output",
    help="Output directory for reports (default: output/)",
)
@click.option(
    "--offline",
    is_flag=True,
    help="Use cached manifests only — no network calls",
)
@click.option(
    "--servers",
    default="",
    help="Comma-separated server names to analyze (default: all)",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["json", "html", "both"]),
    default="both",
    help="Output format (default: both)",
)
def main(
    output_dir: str,
    offline: bool,
    servers: str,
    output_format: str,
) -> None:
    """Scan MCP servers for governance characteristics."""
    # Parse server filter
    server_names = [s.strip() for s in servers.split(",") if s.strip()] if servers else []
    configs = get_servers_by_name(server_names)

    if not configs:
        click.secho("No servers matched the filter.", fg="red")
        sys.exit(1)

    click.echo(f"Analyzing {len(configs)} MCP servers...")
    if offline:
        click.echo("  (offline mode — using cached data only)")

    # Fetch and analyze
    analyses: list[ServerAnalysis] = []
    client: httpx.Client | None = None if offline else httpx.Client()

    try:
        for config in configs:
            click.echo(f"  [{config.category:10s}] {config.name}...", nl=False)

            content = fetch_server_content(config, client=client, offline=offline)
            if content is None:
                click.secho(" SKIP (no data)", fg="yellow")
                continue

            analysis = analyze_server(
                config=config,
                manifest_content=content.manifest,
                source_content=content.source,
            )
            analyses.append(analysis)

            grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "red", "F": "red"}
            color = grade_colors.get(analysis.grade, "white")
            click.echo(" ", nl=False)
            click.secho(f"{analysis.score}/100 [{analysis.grade}]", fg=color)
    finally:
        if client is not None:
            client.close()

    if not analyses:
        click.secho("No servers could be analyzed.", fg="red")
        sys.exit(1)

    # Generate reports
    out = Path(output_dir)
    click.echo()

    if output_format in ("json", "both"):
        json_path = generate_json_report(analyses, out)
        click.echo(f"  JSON report: {json_path}")

    if output_format in ("html", "both"):
        html_path = generate_html_report(analyses, out)
        click.echo(f"  HTML report: {html_path}")

    # Summary
    avg = round(sum(a.score for a in analyses) / len(analyses))
    click.echo()
    click.echo(f"  {len(analyses)} servers analyzed — average score: {avg}/100")


if __name__ == "__main__":
    main()
