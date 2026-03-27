"""TypeScript compliance policy rules (COM-*).

Detects missing logging for EU AI Act Article 12 compliance.
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
# COM-001: No logging (EU AI Act Art. 12)
# ---------------------------------------------------------------------------


class COM001TS(BasePolicy):
    policy_id = "COM-001"
    category = "Compliance"
    severity = "HIGH"
    title = "No automatic logging of events (EU AI Act Art. 12)"
    impact = (
        "EU AI Act Article 12 mandates automatic logging of AI system events. "
        "Non-compliance may result in fines up to 3% of global revenue."
    )
    attack_scenario = (
        "During a regulatory audit, the organisation cannot produce event "
        "logs showing what the AI agent did, resulting in a compliance violation."
    )
    references = [
        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_ts = "\n".join(
            c for p, c in metadata.file_contents.items() if is_ts_file(p)
        )
        if not all_ts.strip():
            return []

        has_logging = _content_has_pattern(all_ts, [
            "winston", "pino", "bunyan", "loglevel",
            "logger.", "log.info", "log.warn", "log.error",
            "auditlog", "audit_log", "audit_trail",
            "drako", "governancemiddleware",
        ])

        if not has_logging:
            return [self._finding(
                "No structured logging detected in TypeScript project. "
                "EU AI Act Art. 12 requires automatic logging of AI system events.",
                fix_snippet=(
                    "import pino from 'pino';\n"
                    "const logger = pino({ name: 'ai-audit', level: 'info' });\n"
                    "// Log all agent interactions for Art. 12 compliance"
                ),
            )]

        return []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TS_COMPLIANCE_POLICIES: list[BasePolicy] = [
    COM001TS(),
]
