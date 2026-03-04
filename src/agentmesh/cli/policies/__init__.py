"""Policy evaluation engine for `agentmesh scan`.

Evaluates project against 33 built-in governance, security,
compliance, operational, magnitude, identity, and best-practice policy rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmesh.cli.policies.base import Finding
from agentmesh.cli.policies.security import SECURITY_POLICIES
from agentmesh.cli.policies.governance import GOVERNANCE_POLICIES
from agentmesh.cli.policies.compliance import COMPLIANCE_POLICIES
from agentmesh.cli.policies.bestpractices import BEST_PRACTICE_POLICIES
from agentmesh.cli.policies.operational import OPERATIONAL_POLICIES
from agentmesh.cli.policies.magnitude import MAGNITUDE_POLICIES
from agentmesh.cli.policies.identity import IDENTITY_POLICIES

if TYPE_CHECKING:
    from agentmesh.cli.bom import AgentBOM
    from agentmesh.cli.discovery import ProjectMetadata

ALL_POLICIES = SECURITY_POLICIES + GOVERNANCE_POLICIES + COMPLIANCE_POLICIES + BEST_PRACTICE_POLICIES + OPERATIONAL_POLICIES + MAGNITUDE_POLICIES + IDENTITY_POLICIES


def evaluate_all_policies(bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
    """Run all policy rules and return findings."""
    findings: list[Finding] = []
    for policy in ALL_POLICIES:
        findings.extend(policy.evaluate(bom, metadata))
    return findings


__all__ = ["evaluate_all_policies", "Finding", "ALL_POLICIES"]
