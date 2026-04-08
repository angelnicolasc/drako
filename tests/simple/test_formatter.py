"""Behavioural tests for the simple-mode plain-text formatter."""

from drako.cli.policies.base import Finding
from drako.simple.formatter import format_simple


def _f(policy_id: str, severity: str, message: str, path: str | None = None) -> Finding:
    return Finding(
        policy_id=policy_id,
        category="Security",
        severity=severity,
        title=f"{policy_id} title",
        message=message,
        file_path=path,
        line_number=12 if path else None,
    )


def test_single_critical_renders_with_red_emoji() -> None:
    out = format_simple(
        [_f("SEC-001", "CRITICAL", "Your API key is hardcoded", "agents/researcher.py")],
        framework_names=["crewai"],
    )
    assert "🔴" in out
    assert "agents/researcher.py" in out
    assert "line 12" in out
    assert "Full report: drako scan" in out


def test_severity_sort_order() -> None:
    out = format_simple(
        [
            _f("DET-001", "MEDIUM", "Temperature not set"),
            _f("SEC-001", "CRITICAL", "Hardcoded credential"),
            _f("GOV-001", "HIGH", "No audit logging"),
        ],
        framework_names=[],
    )
    crit = out.index("Hardcoded credential")
    high = out.index("No audit logging")
    med = out.index("Temperature not set")
    assert crit < high < med


def test_max_ten_findings_with_tail() -> None:
    findings = [
        _f("SEC-001", "CRITICAL", f"Issue number {i}", f"file_{i}.py")
        for i in range(15)
    ]
    out = format_simple(findings, framework_names=["langchain"])
    assert "...and 5 more" in out
    # First ten should be present
    assert "Issue number 0" in out
    # 11th onwards should be omitted
    assert "Issue number 10" not in out


def test_no_jargon_in_output() -> None:
    out = format_simple(
        [_f("SEC-002", "HIGH", "Prompt injection risk", "main.py")],
        framework_names=["langchain"],
    )
    lower = out.lower()
    assert "sarif" not in lower
    assert "owasp" not in lower
    assert "ast" not in lower.split()  # whole-word check
