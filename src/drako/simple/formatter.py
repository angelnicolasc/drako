"""Plain-text formatter for `drako scan --simple`.

No SARIF, no OWASP IDs, no AST jargon. Show at most ten findings, sorted by
severity, with one sentence describing the problem and one sentence
describing the fix. Anything beyond ten is summarised in a single tail line.
"""

from __future__ import annotations

from typing import Iterable

from drako.cli.policies.base import Finding
from drako.simple.router import route_fix
from drako.simple.rules import is_whitelisted

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
_SEVERITY_LABEL = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

_MAX_FINDINGS = 10


def _filter_whitelisted(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if is_whitelisted(f.policy_id)]


def _sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 9))


def _location(finding: Finding) -> str:
    if finding.file_path and finding.line_number:
        return f"{finding.file_path} (line {finding.line_number})"
    if finding.file_path:
        return finding.file_path
    return "your project"


def _problem_sentence(finding: Finding) -> str:
    """Return a one-sentence plain-English problem description."""
    base = finding.message.strip().split("\n", 1)[0].rstrip(".")
    location = _location(finding)
    if finding.file_path:
        return f"{base} — {location}."
    return f"{base}."


def format_simple(
    findings: Iterable[Finding],
    framework_names: Iterable[str],
) -> str:
    """Render a plain-text simple report from findings.

    Only whitelisted rule IDs are surfaced; up to 10 are shown sorted by
    severity. Returns the full report as a single string ready for stdout.
    """
    framework_names = list(framework_names)
    whitelisted = _sort_by_severity(_filter_whitelisted(findings))

    if not whitelisted:
        return (
            "🟢 No critical issues found in your agent.\n"
            "\n"
            "Great work. For the full governance report, run: drako scan\n"
        )

    total = len(whitelisted)
    severity_counts: dict[str, int] = {}
    for f in whitelisted:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    top_sev = next(iter(_sort_by_severity(whitelisted))).severity
    headline_count = severity_counts.get(top_sev, total)
    headline_label = _SEVERITY_LABEL.get(top_sev, "issues")
    plural = "issue" if headline_count == 1 else "issues"

    lines: list[str] = []
    lines.append(
        f"{_SEVERITY_EMOJI.get(top_sev, '🔴')} "
        f"{headline_count} {headline_label} {plural} in your agent. "
        "Here's how to fix them:"
    )
    lines.append("")

    shown = whitelisted[:_MAX_FINDINGS]
    for f in shown:
        emoji = _SEVERITY_EMOJI.get(f.severity, "•")
        lines.append(f"  {emoji} {_problem_sentence(f)}")
        lines.append(f"     → {route_fix(f, framework_names)}")
        lines.append("")

    if total > _MAX_FINDINGS:
        remaining = total - _MAX_FINDINGS
        lines.append(
            f"...and {remaining} more — run 'drako scan' for the full report"
        )
        lines.append("")

    lines.append("Full report: drako scan")
    return "\n".join(lines) + "\n"
