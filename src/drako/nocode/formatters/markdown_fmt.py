"""Markdown formatter for `drako nocode scan` — useful for PR comments."""

from __future__ import annotations

from datetime import date

from drako.nocode.graph import NocodeFinding, NocodeWorkflow
from drako.nocode.scoring import score_workflow


def format_markdown(workflow: NocodeWorkflow, findings: list[NocodeFinding]) -> str:
    score, grade = score_workflow(findings)
    lines: list[str] = []
    lines.append(f"# Drako nocode report — {workflow.name}")
    lines.append("")
    lines.append(
        f"- Platform: **{workflow.platform}**  "
        f"\n- Nodes: **{len(workflow.nodes)}**  "
        f"\n- Analyzed: **{date.today().isoformat()}**  "
        f"\n- Score: **{score} / 100 ({grade})**"
    )
    lines.append("")
    if not findings:
        lines.append("No governance issues detected.")
        return "\n".join(lines) + "\n"

    lines.append("| ID | Severity | Node | Issue |")
    lines.append("|----|----------|------|-------|")
    for f in findings:
        node = f.node_id or "-"
        msg = f.message.replace("|", "\\|")
        lines.append(f"| {f.policy_id} | {f.severity} | {node} | {msg} |")
    return "\n".join(lines) + "\n"
