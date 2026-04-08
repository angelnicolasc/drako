"""Curated whitelist of rule IDs surfaced in `drako scan --simple`.

These are the rules a solo developer can act on without prior knowledge of
SARIF, OWASP, or compliance frameworks. Every rule listed here MUST have a
corresponding fix in at least crewai, langchain, and direct_api fix modules.
"""

from __future__ import annotations

SIMPLE_RULE_WHITELIST: list[str] = [
    "SEC-001",  # hardcoded credentials
    "SEC-002",  # prompt injection
    "SEC-003",  # unsandboxed code execution
    "SEC-004",  # filesystem access without restriction
    "SEC-005",  # network access without allowlist
    "SEC-007",  # user input reaching shell/SQL
    "GOV-001",  # no audit logging
    "GOV-003",  # self-modifying prompts
    "DET-001",  # temperature not set
    "DET-003",  # no timeout configured
    "DET-005",  # no iteration limit
    "ODD-001",  # no operational boundary defined
]

SIMPLE_RULE_SET: frozenset[str] = frozenset(SIMPLE_RULE_WHITELIST)


def is_whitelisted(policy_id: str) -> bool:
    """Return True if a rule is part of the simple-mode whitelist."""
    return policy_id in SIMPLE_RULE_SET
