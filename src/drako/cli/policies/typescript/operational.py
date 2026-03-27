"""TypeScript operational policy rules (ODD-*).

Detects missing operational boundaries and tool allowlisting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding
from drako.cli.policies.typescript._utils import is_ts_file

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


def _content_has_pattern(content: str, patterns: list[str]) -> bool:
    lower = content.lower()
    return any(p in lower for p in patterns)


# ---------------------------------------------------------------------------
# ODD-001: No operational boundaries
# ---------------------------------------------------------------------------


class ODD001TS(BasePolicy):
    policy_id = "ODD-001"
    category = "Operational"
    severity = "MEDIUM"
    title = "No operational boundaries defined"
    impact = (
        "Without operational boundaries (tool allowlists, resource limits), "
        "agents can access any tool or resource, increasing blast radius."
    )
    attack_scenario = (
        "An agent intended only for search tasks discovers it can also "
        "call a delete endpoint, and a prompt injection causes data loss."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]
    remediation_effort = "moderate"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_ts = "\n".join(
            c for p, c in metadata.file_contents.items() if is_ts_file(p)
        )
        if not all_ts.strip():
            return []

        has_agents = _content_has_pattern(all_ts, [
            "agent(", "createagent", "new agent",
            "generatetext(", "streamtext(",
        ])
        has_boundaries = _content_has_pattern(all_ts, [
            "allowedtools", "allowed_tools", "toolallowlist",
            "tool_allowlist", "maxsteps", "max_steps",
            "maxturns", "max_turns", "maxiterations", "max_iterations",
            "ratelimit", "rate_limit", "tokenlimit", "token_limit",
        ])

        if has_agents and not has_boundaries:
            return [self._finding(
                "Agent definitions found but no operational boundaries "
                "(tool allowlists, step limits, rate limits) detected.",
                fix_snippet=(
                    "const agent = createAgent({\n"
                    "  tools: [searchTool, calcTool],  // explicit allowlist\n"
                    "  maxSteps: 10,                    // prevent infinite loops\n"
                    "  maxTokens: 4096,                 // limit token spend\n"
                    "});"
                ),
            )]

        return []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TS_OPERATIONAL_POLICIES: list[BasePolicy] = [
    ODD001TS(),
]
