"""Rich terminal report for `agentmesh scan`.

Generates a marketing-grade terminal output using the Rich library.
Developers take screenshots of this and share on Twitter/X.
"""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich import box

if TYPE_CHECKING:
    from agentmesh.cli.bom import AgentBOM
    from agentmesh.cli.discovery import ProjectMetadata
    from agentmesh.cli.policies.base import Finding


# ---------------------------------------------------------------------------
# Color mapping
# ---------------------------------------------------------------------------

_GRADE_COLORS = {
    "A": "green",
    "B": "bright_green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "red",
}

_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",   # red circle
    "HIGH": "\U0001f7e0",       # orange circle
    "MEDIUM": "\U0001f7e1",     # yellow circle
    "LOW": "\U0001f535",        # blue circle
}


# ---------------------------------------------------------------------------
# Score bar rendering
# ---------------------------------------------------------------------------

def _render_score_bar(score: int) -> str:
    """Render a progress bar for the score."""
    filled = score // 5
    empty = 20 - filled
    return "\u2588" * filled + "\u2591" * empty


# ---------------------------------------------------------------------------
# Main render function
# ---------------------------------------------------------------------------

def render_report(
    bom: AgentBOM,
    findings: list[Finding],
    score: int,
    grade: str,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    console: Console | None = None,
) -> None:
    """Render the full scan report to the terminal.

    If *console* is None a new Console writing to stderr is created.
    Pass a ``Console(file=StringIO())`` for testing.
    """
    if console is None:
        console = Console(stderr=True)

    console.print()

    # ---- Header Panel ----
    framework_str = ", ".join(
        f"{fw.name} {fw.version or ''}" for fw in bom.frameworks
    ) if bom.frameworks else "No framework detected"

    header = Text()
    header.append("\U0001f4c1 Project: ", style="bold")
    header.append(str(metadata.root.name) + "\n")
    header.append("\U0001f50d Framework: ", style="bold")
    header.append(framework_str + "\n")
    header.append("\u23f1\ufe0f  Scan completed in ", style="bold")
    header.append(f"{scan_duration_ms / 1000:.1f}s")

    console.print(Panel(
        header,
        title="[bold cyan]AgentMesh Scan Report[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    console.print()

    # ---- Agent BOM Table ----
    bom_table = Table(
        title="\U0001f3d7\ufe0f  AGENT BOM (Bill of Materials)",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        title_style="bold",
    )
    bom_table.add_column("Component", style="cyan", width=14)
    bom_table.add_column("Details", style="white")

    agent_names = ", ".join(a.name for a in bom.agents[:8]) or "None detected"
    if len(bom.agents) > 8:
        agent_names += f" (+{len(bom.agents) - 8} more)"
    bom_table.add_row("Agents", f"{len(bom.agents)} ({agent_names})")

    tool_names = ", ".join(t.name for t in bom.tools[:8]) or "None detected"
    if len(bom.tools) > 8:
        tool_names += f" (+{len(bom.tools) - 8} more)"
    bom_table.add_row("Tools", f"{len(bom.tools)} ({tool_names})")

    model_names = ", ".join(m.name for m in bom.models[:5]) or "None detected"
    bom_table.add_row("Models", f"{len(bom.models)} ({model_names})")

    bom_table.add_row("MCP Servers", str(len(bom.mcp_servers)))
    bom_table.add_row("Prompts", f"{len(bom.prompts)} system prompts detected")
    bom_table.add_row("Framework", framework_str)

    console.print(bom_table)
    console.print()

    # ---- Governance Score ----
    grade_color = _GRADE_COLORS.get(grade, "white")
    bar = _render_score_bar(score)

    score_text = Text()
    score_text.append("\U0001f4ca GOVERNANCE SCORE: ", style="bold")
    score_text.append(f"{score}/100 ", style=f"bold {grade_color}")
    score_text.append(f"[{grade}] ", style=f"bold {grade_color}")
    score_text.append(bar, style=grade_color)
    score_text.append(f" {score}%", style=f"dim {grade_color}")

    console.print(Panel(score_text, border_style=grade_color))
    console.print()

    # ---- Findings by Severity ----
    findings_by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_severity.setdefault(f.severity, []).append(f)

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        items = findings_by_severity.get(severity, [])
        if not items:
            continue

        color = _SEVERITY_COLORS.get(severity, "white")
        emoji = _SEVERITY_EMOJI.get(severity, "\u2022")

        console.print(
            f"{emoji} [bold {color}]{severity}[/bold {color}] ({len(items)} finding{'s' if len(items) != 1 else ''})",
        )
        console.print()

        for f in items:
            # Finding header
            location = ""
            if f.file_path:
                location = f"  File: {f.file_path}"
                if f.line_number:
                    location += f":{f.line_number}"

            finding_text = Text()
            finding_text.append(f"{f.policy_id}", style=f"bold {color}")
            finding_text.append(f" \u2502 {f.title}\n", style="bold")
            finding_text.append(f"  {f.message}\n", style="white")
            if location:
                finding_text.append(f"{location}\n", style="dim")

            if f.code_snippet:
                finding_text.append(f"  Found: ", style="dim")
                finding_text.append(f"{f.code_snippet}\n", style="dim italic")

            console.print(finding_text, end="")

            if f.fix_snippet:
                console.print(f"  [bold green]Fix:[/bold green]")
                console.print(Syntax(
                    f.fix_snippet,
                    "python",
                    theme="monokai",
                    line_numbers=False,
                    padding=1,
                ))

            console.print()

    # ---- Summary ----
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    summary_parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts[sev] > 0:
            color = _SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{counts[sev]} {sev.lower()}[/{color}]")

    if summary_parts:
        console.print(f"\U0001f4c8 Summary: " + " \u2502 ".join(summary_parts))
    else:
        console.print("\u2705 [green]No findings! Your project has excellent governance.[/green]")

    # Improvement hint
    if score < 80 and counts["CRITICAL"] > 0:
        potential = min(100, score + counts["CRITICAL"] * 15)
        console.print(f"   Fix the {counts['CRITICAL']} critical issue{'s' if counts['CRITICAL'] != 1 else ''} to reach score {potential}+")

    console.print()

    # ---- CTA ----
    console.print(
        "\U0001f4a1 [bold]Improve your score:[/bold]"
    )
    console.print(
        "   [cyan]pip install useagentmesh[/cyan]"
    )
    console.print(
        "   [cyan]agentmesh init[/cyan]   # Add governance middleware to your project"
    )
    console.print()


def render_report_to_string(
    bom: AgentBOM,
    findings: list[Finding],
    score: int,
    grade: str,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
) -> str:
    """Render the report to a string (for testing)."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100)
    render_report(bom, findings, score, grade, metadata, scan_duration_ms, console=console)
    return buf.getvalue()
