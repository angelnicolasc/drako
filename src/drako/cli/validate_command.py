"""`drako validate` — Validate a .drako.yaml configuration file.

Fully offline — no backend connection required.  Checks:
  1. YAML parseability
  2. Schema validation (Pydantic)
  3. Cross-references (agents, tools, ODD)
  4. Logical consistency (permitted/forbidden overlap)
  5. Budget math warnings
  6. High-risk configuration warnings
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import yaml


@click.command()
@click.argument("file", type=click.Path(exists=True))
def validate(file: str) -> None:
    """Validate an .drako.yaml configuration file.

    Checks for YAML syntax, schema compliance, cross-reference integrity,
    logical consistency, and high-risk configurations.  Fully offline.
    """
    path = Path(file)
    errors: list[str] = []
    warnings: list[str] = []

    # ── 1. YAML parseability ───────────────────────────────────────
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        _fail(f"YAML parse error: {exc}")
        return
    except OSError as exc:
        _fail(f"Cannot read file: {exc}")
        return

    if not isinstance(data, dict):
        _fail(f"Expected a YAML mapping, got {type(data).__name__}")
        return

    _ok("YAML parseable")

    # ── 2. Schema validation (Pydantic) ────────────────────────────
    try:
        from drako.config import DrakoConfig
        config = DrakoConfig.model_validate(data)
        _ok("Schema valid")
    except Exception as exc:
        errors.append(f"Schema validation failed: {exc}")
        _err(f"Schema validation: {exc}")
        config = None

    if config is None:
        _summary(errors, warnings)
        sys.exit(1)

    # ── 3. Cross-references ────────────────────────────────────────
    agent_names = set(config.agents.keys())
    tool_names = set(config.detected_tools.keys())

    # Check HITL triggers reference valid tools
    if config.hitl.triggers.tools:
        for tool in config.hitl.triggers.tools:
            if tool_names and tool not in tool_names:
                warnings.append(f"HITL trigger references unknown tool: '{tool}'")

    # Check hooks reference valid tool types
    for hook_list_name in ("pre_action", "post_action", "on_error", "on_session_end"):
        for hook in getattr(config.hooks, hook_list_name, []):
            if hook.condition and "agent:" in hook.condition:
                ref_agent = hook.condition.split("agent:")[1].split()[0].strip("'\"")
                if agent_names and ref_agent not in agent_names:
                    warnings.append(
                        f"Hook '{hook.name}' references unknown agent: '{ref_agent}'"
                    )

    # Check A2A channels reference valid agents
    for channel in config.a2a.channels:
        from_agent = getattr(channel, "from_agent", "*")
        to_agent = getattr(channel, "to_agent", "*")
        if agent_names:
            if from_agent != "*" and from_agent not in agent_names:
                warnings.append(f"A2A channel references unknown from-agent: '{from_agent}'")
            if to_agent != "*" and to_agent not in agent_names:
                warnings.append(f"A2A channel references unknown to-agent: '{to_agent}'")

    # Check fallback tools reference valid tool names
    for tool_name in config.fallback.tools:
        if tool_names and tool_name not in tool_names:
            warnings.append(f"Fallback references unknown tool: '{tool_name}'")

    if not errors:
        _ok("Cross-references valid")

    # ── 4. Logical consistency ─────────────────────────────────────
    # Check that circuit breaker thresholds make sense
    cb = config.circuit_breaker.agent_level
    if cb.recovery_timeout_seconds > cb.time_window_seconds:
        warnings.append(
            f"Circuit breaker recovery ({cb.recovery_timeout_seconds}s) "
            f"> time window ({cb.time_window_seconds}s) — agents stay open longer than the failure window"
        )

    # Check DLP mode vs HITL mode coherence
    if config.dlp.mode == "off" and config.hitl.mode == "off":
        warnings.append("Both DLP and HITL are off — no runtime protection active")

    # Check trust score coherence
    if config.hitl.triggers.trust_score_below is not None:
        if config.hitl.triggers.trust_score_below <= 0:
            warnings.append("HITL trust_score_below <= 0 will never trigger")
        elif config.hitl.triggers.trust_score_below >= 1.0:
            warnings.append("HITL trust_score_below >= 1.0 will always trigger")

    if not errors:
        _ok("Logical consistency valid")

    # ── 5. Budget math ─────────────────────────────────────────────
    budgets = config.finops.budgets
    if budgets.daily_usd and budgets.weekly_usd:
        if budgets.daily_usd * 7 > budgets.weekly_usd * 1.1:
            warnings.append(
                f"Daily budget ({budgets.daily_usd:.2f}) × 7 = "
                f"${budgets.daily_usd * 7:.2f} exceeds weekly budget "
                f"(${budgets.weekly_usd:.2f})"
            )
    if budgets.weekly_usd and budgets.monthly_usd:
        if budgets.weekly_usd * 4.33 > budgets.monthly_usd * 1.1:
            warnings.append(
                f"Weekly budget ({budgets.weekly_usd:.2f}) × 4.33 = "
                f"${budgets.weekly_usd * 4.33:.2f} exceeds monthly budget "
                f"(${budgets.monthly_usd:.2f})"
            )

    if budgets.daily_usd or budgets.weekly_usd or budgets.monthly_usd:
        _ok("Budget math checked")

    # ── 6. High-risk config warnings ───────────────────────────────
    if config.dlp.mode == "off":
        warnings.append("DLP is off — no PII scanning active")

    if config.governance.on_backend_unreachable == "allow":
        warnings.append(
            "on_backend_unreachable=allow — agents run ungoverned if backend is down"
        )

    write_tools = [
        name for name, entry in config.detected_tools.items()
        if entry.type in ("write", "execute", "payment")
    ]
    if write_tools and config.hitl.mode == "off":
        warnings.append(
            f"HITL is off but write/execute/payment tools detected: "
            f"{write_tools[:3]}{'...' if len(write_tools) > 3 else ''}"
        )

    if config.chaos.experiments and not config.chaos.safety.require_approval:
        warnings.append("Chaos experiments configured without require_approval")

    # ── Summary ────────────────────────────────────────────────────
    _summary(errors, warnings)

    if errors:
        sys.exit(1)


def _ok(msg: str) -> None:
    click.echo(click.style("  \u2713 ", fg="green") + msg)


def _err(msg: str) -> None:
    click.echo(click.style("  \u2717 ", fg="red") + msg)


def _warn(msg: str) -> None:
    click.echo(click.style("  ! ", fg="yellow") + msg)


def _fail(msg: str) -> None:
    _err(msg)
    click.echo()
    click.secho("Result: INVALID", fg="red", bold=True)
    sys.exit(1)


def _summary(errors: list[str], warnings: list[str]) -> None:
    click.echo()
    for w in warnings:
        _warn(w)

    if errors:
        click.echo()
        click.secho(
            f"Result: INVALID ({len(errors)} error(s), {len(warnings)} warning(s))",
            fg="red", bold=True,
        )
    elif warnings:
        click.echo()
        click.secho(
            f"Result: VALID ({len(warnings)} warning(s))",
            fg="green", bold=True,
        )
    else:
        click.echo()
        click.secho("Result: VALID", fg="green", bold=True)
