"""Base class for framework-specific governance rules.

Framework rules only fire when the corresponding framework is detected
in the project's BOM. If the framework is absent, the rule is silently
skipped (not reported as passed or failed).
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class FrameworkPolicy(BasePolicy):
    """Abstract base for framework-specific policy rules.

    Subclasses set ``required_framework`` to the canonical framework name
    (e.g. ``"crewai"``, ``"autogen"``).  ``evaluate()`` checks the BOM
    and delegates to ``_evaluate_framework()`` only when the framework
    is present.
    """

    required_framework: str = ""
    category: str = "Framework"

    # ------------------------------------------------------------------
    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        """Skip evaluation when the target framework is not detected."""
        if not any(
            fw.name == self.required_framework for fw in bom.frameworks
        ):
            return []
        return self._evaluate_framework(bom, metadata)

    @abstractmethod
    def _evaluate_framework(
        self, bom: AgentBOM, metadata: ProjectMetadata
    ) -> list[Finding]:
        """Evaluate framework-specific governance rules."""
        ...
