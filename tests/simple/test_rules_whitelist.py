"""Whitelist filter must drop non-whitelisted rules."""

from drako.cli.policies.base import Finding
from drako.simple.formatter import format_simple
from drako.simple.rules import SIMPLE_RULE_WHITELIST, is_whitelisted


def _f(policy_id: str, severity: str = "HIGH") -> Finding:
    return Finding(
        policy_id=policy_id,
        category="Security",
        severity=severity,
        title=f"{policy_id} title",
        message=f"{policy_id} message",
    )


def test_whitelist_membership() -> None:
    assert is_whitelisted("SEC-001")
    assert is_whitelisted("ODD-001")
    assert not is_whitelisted("SEC-999")
    assert not is_whitelisted("HOOK-001")


def test_whitelist_size_matches_spec() -> None:
    assert len(SIMPLE_RULE_WHITELIST) == 12


def test_formatter_drops_non_whitelisted() -> None:
    findings = [
        _f("SEC-001"),
        _f("SEC-999"),  # not in whitelist
        _f("DET-001"),
        _f("HOOK-001"),  # not in whitelist
    ]
    out = format_simple(findings, framework_names=["crewai"])
    assert "SEC-999" not in out
    assert "HOOK-001" not in out


def test_empty_findings_renders_clean_message() -> None:
    out = format_simple([], framework_names=[])
    assert "No critical issues" in out
