"""Default text formatter for `drako nocode scan` and `drako nocode bom`."""

from __future__ import annotations

from datetime import date

from drako.nocode.graph import NocodeFinding, NocodeWorkflow
from drako.nocode.scoring import score_workflow

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _group_by_severity(findings: list[NocodeFinding]) -> dict[str, list[NocodeFinding]]:
    grouped: dict[str, list[NocodeFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    return grouped


def format_text(workflow: NocodeWorkflow, findings: list[NocodeFinding]) -> str:
    score, grade = score_workflow(findings)
    grouped = _group_by_severity(findings)

    lines: list[str] = []
    lines.append(f'Workflow "{workflow.name}" — Drako Governance Report')
    lines.append(
        f"Platform: {workflow.platform} | Nodes: {len(workflow.nodes)} | "
        f"Analyzed: {date.today().isoformat()}"
    )
    lines.append("")

    any_findings = False
    for severity in _SEVERITY_ORDER:
        bucket = grouped.get(severity, [])
        if not bucket:
            continue
        any_findings = True
        lines.append(f"{severity} ({len(bucket)})")
        for f in bucket:
            target = f.node_id or ""
            header = f"  {f.policy_id}  {target}".rstrip()
            lines.append(header)
            lines.append(f"    {f.message}")
        lines.append("")

    if not any_findings:
        lines.append("No governance issues detected.")
        lines.append("")

    lines.append(f"Governance Score: {score} / 100 ({grade})")
    return "\n".join(lines) + "\n"


def format_bom_text(workflow: NocodeWorkflow) -> str:
    """Render the normalised graph as a labelled bill of materials."""
    lines: list[str] = []
    lines.append(f'Workflow "{workflow.name}" — Bill of Materials')
    lines.append(f"Platform: {workflow.platform}")
    lines.append("")
    lines.append(f"Nodes ({len(workflow.nodes)}):")
    for node in workflow.nodes.values():
        flags = []
        if node.receives_user_input:
            flags.append("user_input")
        if node.credentials:
            flags.append(f"creds={','.join(node.credentials)}")
        suffix = f" [{' '.join(flags)}]" if flags else ""
        lines.append(f"  - {node.id} :: {node.type} ({node.platform_type}){suffix}")
    lines.append("")
    lines.append(f"Edges ({len(workflow.edges)}):")
    for edge in workflow.edges:
        carry = f" carries={','.join(edge.carries)}" if edge.carries else ""
        lines.append(f"  - {edge.source} -> {edge.target}{carry}")
    return "\n".join(lines) + "\n"
