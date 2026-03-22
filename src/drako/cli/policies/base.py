"""Base policy class and Finding dataclass for the scan policy engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


@dataclass
class Finding:
    """A single finding from a policy evaluation."""
    policy_id: str            # e.g. "SEC-001"
    category: str             # "Security", "Governance", "Compliance", "Best Practices"
    severity: str             # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    title: str                # Short title
    message: str              # Detailed description
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None   # The problematic code
    fix_snippet: str | None = None    # How to fix it
    impact: str | None = None
    attack_scenario: str | None = None
    references: list[str] = field(default_factory=list)
    remediation_effort: str | None = None  # "trivial" | "moderate" | "significant"


class BasePolicy(ABC):
    """Abstract base class for all scan policy rules."""

    policy_id: str = ""
    category: str = ""
    severity: str = ""
    title: str = ""
    impact: str = ""
    attack_scenario: str = ""
    references: list[str] = []
    remediation_effort: str = "moderate"  # "trivial" | "moderate" | "significant"

    def _finding(self, message: str, **kwargs: object) -> Finding:
        """Create a Finding pre-filled with this policy's metadata."""
        return Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            impact=self.impact,
            attack_scenario=self.attack_scenario,
            references=list(self.references),
            remediation_effort=self.remediation_effort,
            message=message,
            **kwargs,
        )

    @abstractmethod
    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        """Evaluate this policy against the project. Return list of findings."""
        ...
