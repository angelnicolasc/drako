"""`agentmesh init` — Initialize AgentMesh in an existing project.

Generates a rich `.agentmesh.yaml` pre-populated with real agents, tools,
and models discovered by the scanner. No `.py` files are generated.
"""

from __future__ import annotations

import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml

from agentmesh.utils.detection import detect_framework

_CONFIG_FILENAME = ".agentmesh.yaml"


# ------------------------------------------------------------------
# YAML template builder
# ------------------------------------------------------------------

def _infer_tool_type(tool: dict) -> str:
    """Infer a tool type label from scan BOM permissions."""
    if tool.get("has_code_execution"):
        return "execute"
    if tool.get("has_network_access"):
        return "network"
    if tool.get("has_filesystem_access"):
        return "write"
    return "read"


def _build_agents_section(agents: list[dict]) -> str:
    """Build the agents: YAML section from scan data."""
    if not agents:
        return (
            "agents: {}  # no agents detected — run agentmesh scan . first\n"
        )
    lines = ["agents:"]
    for a in agents:
        name = a["name"]
        source = a.get("file_path", "")
        lines.append(f"  {name}:")
        lines.append(f"    source: {source}")
        lines.append(f'    description: ""  # add a description for compliance docs')
        lines.append(f"    # trust_threshold: 50       # requires Pro — minimum trust score to operate")
        lines.append(f"    # human_escalation: true    # requires Pro — pause on low-confidence decisions")
        lines.append("")
    return "\n".join(lines) + "\n"


def _build_tools_section(tools: list[dict]) -> str:
    """Build the tools: YAML section from scan data."""
    if not tools:
        return (
            "tools: {}  # no tools detected — run agentmesh scan . first\n"
        )
    lines = [
        "# Types: read, write, execute, network, payment",
        "tools:",
    ]
    for t in tools:
        name = t["name"]
        source = t.get("file_path", "")
        tool_type = _infer_tool_type(t)
        critical_note = ""
        if tool_type == "execute":
            critical_note = "              # ⚠ flagged as CRITICAL by scan"
        lines.append(f"  {name}:")
        lines.append(f"    source: {source}")
        lines.append(f"    type: {tool_type}{critical_note}")
        lines.append(f"    # rate_limit: 30/minute     # requires Pro")
        lines.append("")
    return "\n".join(lines) + "\n"


def _build_odd_section(agents: list[dict], tools: list[dict]) -> str:
    """Build the ODD section with real tool names."""
    tool_names = [t["name"] for t in tools]
    lines = [
        "# ──────────────────────────────────────────────",
        "# OPERATIONAL BOUNDARIES (ODD)              [requires Pro]",
        "# Define what each agent CAN do. Everything",
        "# else is denied. Allowlist, not denylist.",
        "# ──────────────────────────────────────────────",
    ]
    if agents and tool_names:
        for a in agents:
            lines.append(f"# odd:")
            lines.append(f"#   {a['name']}:")
            lines.append(f"#     permitted_tools:")
            for tn in tool_names[:2]:
                lines.append(f"#       - {tn}")
            if len(tool_names) > 2:
                lines.append(f"#     forbidden_tools:")
                for tn in tool_names[2:]:
                    lines.append(f"#       - {tn}")
            lines.append(f"#     max_actions_per_minute: 30")
            lines.append(f"#     max_cost_per_session_usd: 5.00")
            break  # Only show first agent as example
        if len(agents) > 1:
            lines.append(f"#")
            lines.append(f"#   {agents[1]['name']}:")
            lines.append(f"#     permitted_tools:")
            lines.append(f"#       - {tool_names[0]}" if tool_names else "#       - ...")
            lines.append(f"#     forbidden_tools:")
            for tn in tool_names[1:]:
                lines.append(f"#       - {tn}")
    else:
        lines.append("# odd:")
        lines.append("#   agent_name:")
        lines.append("#     permitted_tools:")
        lines.append("#       - tool_name")
        lines.append("#     max_actions_per_minute: 30")
    return "\n".join(lines) + "\n"


def _generate_yaml(
    tenant_id: str,
    endpoint: str,
    framework: str | None,
    framework_version: str | None,
    scan_data: dict | None,
) -> str:
    """Generate the full .agentmesh.yaml content with comments."""
    agents = scan_data.get("agents", []) if scan_data else []
    tools = scan_data.get("tools", []) if scan_data else []
    project_name = scan_data.get("project_name", "my-project") if scan_data else "my-project"

    fw_label = framework or "unknown"
    if framework_version:
        fw_label = f"{framework} {framework_version}"

    header = textwrap.dedent(f"""\
        # AgentMesh Configuration
        # Generated from scan of: {project_name} ({fw_label})
        # Docs: https://docs.useagentmesh.com/config

        version: "1.0"
        api_key_env: AGENTMESH_API_KEY  # or set api_key directly (not recommended)
        tenant_id: {tenant_id}
        endpoint: {endpoint}
        framework: {framework or 'generic'}

    """)

    agents_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # AGENTS — discovered by scan
        # ──────────────────────────────────────────────
    """) + _build_agents_section(agents)

    tools_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # TOOLS — discovered by scan
        # Classify each tool to enable governance rules.
        # ──────────────────────────────────────────────
    """) + _build_tools_section(tools)

    odd_section = _build_odd_section(agents, tools)

    magnitude_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # MAGNITUDE LIMITS                          [requires Pro]
        # Pre-action validation. Blocks before execution.
        # ──────────────────────────────────────────────
        # magnitude:
        #   max_spend_per_action_usd: 10.00
        #   max_spend_per_session_usd: 50.00
        #   max_tokens_per_call: 4000
        #   max_records_per_action: 100
        #   max_records_per_hour: 1000
    """)

    dlp_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # DLP (Data Loss Prevention)
        # Scans tool call payloads for PII/PCI.
        # ──────────────────────────────────────────────
        dlp:
          mode: audit        # audit = log only │ enforce = block (Pro) │ off
    """)

    cb_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # CIRCUIT BREAKER
        # Auto-suspends agents or tools on failure.
        # ──────────────────────────────────────────────
        circuit_breaker:
          agent_level:
            failure_threshold: 10
            time_window_seconds: 300
            recovery_timeout_seconds: 60
          # per_tool:                                    [requires Pro]
          #   tool_name:
          #     failure_threshold: 3
          #     time_window_seconds: 60
          #     recovery_timeout_seconds: 30
          #     fallback: skip          # skip │ escalate │ use_alternative
    """)

    injection_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # PROMPT INJECTION DETECTION                [requires Pro]
        # Scans inputs reaching the agent for
        # injection attempts in external data.
        # ──────────────────────────────────────────────
        # injection_detection:
        #   mode: enforce      # audit │ enforce │ off
        #   sensitivity: medium
    """)

    audit_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # AUDIT TRAIL
        # ──────────────────────────────────────────────
        audit:
          enabled: true
          # cryptographic: true     # SHA-256 hash chain   [requires Pro]
          # retention_days: 90      # default: 7 (free)    [requires Pro: 90, Enterprise: 365]
    """)

    ci_section = textwrap.dedent("""\
        # ──────────────────────────────────────────────
        # CI/CD                                     [requires Starter]
        # ──────────────────────────────────────────────
        # ci:
        #   threshold: 70            # fail PR if score < 70
        #   fail_on:
        #     - critical
        #     - high
        #   ignore_rules:
        #     - BP-003
    """)

    return (
        header
        + agents_section + "\n"
        + tools_section + "\n"
        + odd_section + "\n"
        + magnitude_section + "\n"
        + dlp_section + "\n"
        + cb_section + "\n"
        + injection_section + "\n"
        + audit_section + "\n"
        + ci_section
    )


# ------------------------------------------------------------------
# CLI Command
# ------------------------------------------------------------------

@click.command()
@click.option("--api-key", envvar="AGENTMESH_API_KEY", help="API key (or set AGENTMESH_API_KEY)")
@click.option(
    "--framework",
    type=click.Choice(["crewai", "langgraph", "autogen", "generic"], case_sensitive=False),
    help="Override framework auto-detection",
)
@click.option("--endpoint", default="https://api.useagentmesh.com", help="Custom endpoint for self-hosted")
def init(api_key: str | None, framework: str | None, endpoint: str) -> None:
    """Initialize AgentMesh in your current project."""

    click.echo()
    click.secho("  AgentMesh Init", fg="cyan", bold=True)
    click.echo()

    # ---- Step 1: detect framework ----
    if not framework:
        detected = detect_framework(".")
        if detected:
            framework = detected
            click.echo(click.style("  [detect] ", fg="green") + f"Detected {framework} project")
        else:
            framework = "generic"
            click.echo(click.style("  [detect] ", fg="yellow") + "No specific framework detected. Using generic setup.")
    else:
        click.echo(click.style("  [detect] ", fg="green") + f"Using framework: {framework}")

    # ---- Step 2: load or run scan ----
    from agentmesh.cli.scan_cache import load_scan_cache, save_scan_cache, ensure_gitignore_cache

    scan_data = load_scan_cache(".")
    if scan_data:
        scanned_at = scan_data.get("scanned_at", "")
        # Calculate age for display
        age_label = "recently"
        try:
            scan_time = datetime.fromisoformat(scanned_at)
            age_seconds = (datetime.now(timezone.utc) - scan_time).total_seconds()
            if age_seconds < 120:
                age_label = f"{int(age_seconds)} seconds ago"
            else:
                age_label = f"{int(age_seconds / 60)} minutes ago"
        except (ValueError, TypeError):
            pass

        n_agents = len(scan_data.get("agents", []))
        n_tools = len(scan_data.get("tools", []))
        n_models = len(scan_data.get("models", []))
        score = scan_data.get("score", "?")
        fw_name = scan_data.get("framework", framework) or framework
        fw_ver = scan_data.get("framework_version", "")
        project = scan_data.get("project_name", ".")

        click.echo(click.style("  [scan]   ", fg="green") + f"Found cached scan results ({age_label})")
        fw_display = f"{fw_name} {fw_ver}".strip() if fw_ver else fw_name
        click.echo(f"           Project: {project} │ Framework: {fw_display}")
        click.echo(f"           Agents: {n_agents} │ Tools: {n_tools} │ Models: {n_models} │ Score: {score}/100")
    else:
        click.echo(click.style("  [scan]   ", fg="yellow") + "No cached scan found. Running scan first...")
        click.echo()
        from agentmesh.cli.scanner import run_scan
        result = run_scan(".")
        save_scan_cache(result, ".")
        ensure_gitignore_cache(".")
        scan_data = load_scan_cache(".", max_age_seconds=9999)
        click.echo()
        click.echo(click.style("  [scan]   ", fg="green") + "Scan complete. Using results for config generation.")

    # ---- Step 3: get API key ----
    click.echo()
    if not api_key:
        env_key = os.environ.get("AGENTMESH_API_KEY")
        if env_key:
            api_key = env_key
            click.echo(click.style("  [auth]   ", fg="green") + "Using API key from AGENTMESH_API_KEY env var")
        else:
            click.echo("  Get a free API key at: " + click.style("https://app.useagentmesh.com/signup", fg="cyan", underline=True))
            api_key = click.prompt("  Enter your API key", hide_input=False)

    # ---- Step 4: validate API key ----
    click.echo(click.style("  [auth]   ", fg="green") + "Validating API key...")
    tenant_plan = "free"
    try:
        import httpx

        with httpx.Client(timeout=10.0) as http:
            resp = http.get(
                f"{endpoint.rstrip('/')}/api/v1/stats",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code == 401:
            click.secho("  [error]  Invalid API key. Get one at https://app.useagentmesh.com/signup", fg="red")
            raise SystemExit(1)
        if resp.status_code >= 400:
            click.secho(f"  [warn]   Could not validate key (HTTP {resp.status_code}). Continuing anyway.", fg="yellow")
        else:
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            tenant_plan = data.get("plan", "free")
            click.echo(click.style("  [auth]   ", fg="green") + f"Key validated │ Plan: {tenant_plan.capitalize()}")
    except (Exception,):
        click.secho("  [warn]   Could not reach backend. Continuing in offline mode.", fg="yellow")

    # Extract tenant_id from key
    parts = api_key.split("_")
    tenant_id = parts[2] if len(parts) >= 3 else "default"

    # ---- Step 5: check for existing config ----
    config_path = Path(_CONFIG_FILENAME)
    if config_path.exists():
        click.echo()
        click.echo(click.style("  [config] ", fg="yellow") + f"{_CONFIG_FILENAME} already exists.")
        choice = click.prompt(
            "           [o]verwrite  [m]erge new tools  [s]kip",
            type=click.Choice(["o", "m", "s"], case_sensitive=False),
            default="s",
        )
        if choice == "s":
            click.echo("  Aborted.")
            return
        if choice == "m":
            # Merge: read existing, we'll update agents/tools from scan
            try:
                existing = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
                # Keep existing endpoint/tenant/api_key_env
                endpoint = existing.get("endpoint", endpoint)
                tenant_id = existing.get("tenant_id", tenant_id)
            except yaml.YAMLError:
                pass  # Fall through to full overwrite

    # ---- Step 6: generate .agentmesh.yaml ----
    fw_version = scan_data.get("framework_version") if scan_data else None
    yaml_content = _generate_yaml(
        tenant_id=tenant_id,
        endpoint=endpoint,
        framework=framework,
        framework_version=fw_version,
        scan_data=scan_data,
    )

    config_path.write_text(yaml_content, encoding="utf-8")

    n_agents = len(scan_data.get("agents", [])) if scan_data else 0
    n_tools = len(scan_data.get("tools", [])) if scan_data else 0
    click.echo()
    click.echo(click.style("  ✓ ", fg="green") + f"Created {_CONFIG_FILENAME} (pre-configured with {n_agents} agents, {n_tools} tools)")

    # ---- Step 7: ensure cache dir in .gitignore ----
    ensure_gitignore_cache(".")

    # ---- Step 8: suggest .env for API key ----
    env_path = Path(".env")
    if env_path.exists():
        env_content = env_path.read_text(encoding="utf-8")
        if "AGENTMESH_API_KEY" not in env_content:
            click.echo(click.style("  [hint]   ", fg="yellow") + f"Add to .env: AGENTMESH_API_KEY={api_key}")
    else:
        if os.name == "nt":
            click.echo(click.style("  [hint]   ", fg="yellow") + f'Set env var: $env:AGENTMESH_API_KEY = "{api_key}"')
        else:
            click.echo(click.style("  [hint]   ", fg="yellow") + f"Set env var: export AGENTMESH_API_KEY={api_key}")

    # ---- Step 9: print next steps ----
    click.echo()
    click.secho("  Next steps:", fg="cyan", bold=True)
    click.echo()
    click.echo("  1. Review and edit " + click.style(".agentmesh.yaml", fg="white", bold=True) + " — your tools are pre-filled")
    click.echo()
    click.echo("  2. Add governance to your code (one line):")
    click.echo(click.style("     from agentmesh import govern", fg="white"))
    click.echo(click.style("     crew = govern(crew)  # or graph = govern(graph)", fg="white"))
    click.echo()
    click.echo("  3. Run: " + click.style("agentmesh push", fg="cyan") + "     Upload config to AgentMesh platform")
    click.echo("  4. Run: " + click.style("agentmesh status", fg="cyan") + "   Verify everything is connected")
    click.echo()
    click.echo("  Docs: " + click.style("https://docs.useagentmesh.com/quickstart", fg="cyan", underline=True))
    click.echo()
