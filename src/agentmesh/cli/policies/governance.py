"""Governance policy rules (GOV-001 through GOV-006)."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from agentmesh.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from agentmesh.cli.bom import AgentBOM
    from agentmesh.cli.discovery import ProjectMetadata

# Patterns indicating audit logging is configured
_AUDIT_PATTERNS = [
    "audit_log", "audit_trail", "with_compliance", "agentmesh",
    "GovernanceMiddleware", "ComplianceMiddleware", "log_action",
    "AuditLog", "audit_logger",
]

# Patterns indicating policy enforcement
_POLICY_PATTERNS = [
    "evaluate_policy", "policy_check", "check_policy", "governance",
    "PolicyEngine", "policy_enforcement", "GovernanceMiddleware",
]

# Patterns indicating rate limiting
_RATE_LIMIT_PATTERNS = [
    "rate_limit", "ratelimit", "throttle", "RateLimiter",
    "rate_limiter", "calls_per_minute", "max_calls",
]

# Patterns indicating human-in-the-loop
_HITL_PATTERNS = [
    "human_in_the_loop", "hitl", "require_approval", "human_approval",
    "ask_human", "confirm_action", "manual_review", "approval_required",
]

# Patterns indicating circuit breaker
_CIRCUIT_BREAKER_PATTERNS = [
    "circuit_breaker", "CircuitBreaker", "pybreaker", "circuitbreaker",
    "breaker", "circuit_open",
]


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    """Check if any pattern exists in the combined content."""
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


# ---------------------------------------------------------------------------
# GOV-001: No audit logging configured
# ---------------------------------------------------------------------------

class GOV001(BasePolicy):
    policy_id = "GOV-001"
    category = "Governance"
    severity = "HIGH"
    title = "No audit logging configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _AUDIT_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No audit logging detected in the project. All agent actions should be logged for traceability.",
                fix_snippet='from agentmesh import GovernanceMiddleware\n\nmiddleware = GovernanceMiddleware(api_key="your-key")\ncrew = Crew(agents=[...], middleware=middleware)\n# All agent actions are now automatically logged',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-002: No policy enforcement middleware
# ---------------------------------------------------------------------------

class GOV002(BasePolicy):
    policy_id = "GOV-002"
    category = "Governance"
    severity = "MEDIUM"
    title = "No policy enforcement middleware"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _POLICY_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No policy enforcement middleware detected. Agents can perform any action without governance checks.",
                fix_snippet='from agentmesh import with_compliance\n\n# Wrap your crew/graph with governance middleware\ncrew = with_compliance(my_crew, config_path=".agentmesh.yaml")\n# Policies are now evaluated before every agent action',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-003: No rate limiting on tool calls
# ---------------------------------------------------------------------------

class GOV003(BasePolicy):
    policy_id = "GOV-003"
    category = "Governance"
    severity = "MEDIUM"
    title = "No rate limiting on tool calls"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _RATE_LIMIT_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"No rate limiting detected on {len(bom.tools)} tool(s). Agents could make unlimited API/tool calls.",
                fix_snippet='# Add rate limiting to tool calls\nfrom functools import wraps\nimport time\n\ndef rate_limit(max_calls: int = 10, period: int = 60):\n    calls = []\n    def decorator(func):\n        @wraps(func)\n        def wrapper(*args, **kwargs):\n            now = time.time()\n            calls[:] = [t for t in calls if now - t < period]\n            if len(calls) >= max_calls:\n                raise RuntimeError("Rate limit exceeded")\n            calls.append(now)\n            return func(*args, **kwargs)\n        return wrapper\n    return decorator',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-004: No human-in-the-loop for destructive actions
# ---------------------------------------------------------------------------

class GOV004(BasePolicy):
    policy_id = "GOV-004"
    category = "Governance"
    severity = "HIGH"
    title = "No human-in-the-loop for destructive actions"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Check if there are tools with filesystem write or code execution
        destructive_tools = [
            t for t in bom.tools
            if t.has_filesystem_access or t.has_code_execution
        ]

        if not destructive_tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _HITL_PATTERNS):
            tool_names = ", ".join(t.name for t in destructive_tools[:5])
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"No human approval required for destructive tools: {tool_names}",
                fix_snippet='# Add human-in-the-loop for high-risk operations\n@middleware.require_approval(tools=["write_file", "delete_file"])\ndef run_agent():\n    # Agent will pause and ask for human approval\n    # before executing write_file or delete_file\n    crew.kickoff()',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-005: No circuit breaker configured
# ---------------------------------------------------------------------------

class GOV005(BasePolicy):
    policy_id = "GOV-005"
    category = "Governance"
    severity = "MEDIUM"
    title = "No circuit breaker configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _CIRCUIT_BREAKER_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No circuit breaker pattern detected. Failed tool/LLM calls could cascade without automatic recovery.",
                fix_snippet='import pybreaker\n\n# Circuit breaker trips after 5 failures, resets after 30s\nllm_breaker = pybreaker.CircuitBreaker(\n    fail_max=5,\n    reset_timeout=30,\n)\n\n@llm_breaker\ndef call_llm(prompt: str) -> str:\n    return client.chat(prompt)',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-006: Agent can modify its own system prompt
# ---------------------------------------------------------------------------

class GOV006(BasePolicy):
    policy_id = "GOV-006"
    category = "Governance"
    severity = "CRITICAL"
    title = "Agent can modify its own system prompt"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                # Look for self.system_prompt = ... or self.prompt = ...
                # OUTSIDE of __init__
                if isinstance(node, ast.FunctionDef) and node.name != "__init__":
                    for child in ast.walk(node):
                        if isinstance(child, ast.Assign):
                            for target in child.targets:
                                if (isinstance(target, ast.Attribute)
                                        and isinstance(target.value, ast.Name)
                                        and target.value.id == "self"
                                        and target.attr in ("system_prompt", "prompt", "instructions", "system_message")):
                                    line_content = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else ""
                                    findings.append(Finding(
                                        policy_id=self.policy_id,
                                        category=self.category,
                                        severity=self.severity,
                                        title=self.title,
                                        message=f'Agent modifies its own "{target.attr}" in method "{node.name}"',
                                        file_path=rel_path,
                                        line_number=child.lineno,
                                        code_snippet=line_content[:80],
                                        fix_snippet='# Make system prompts immutable — set once in __init__\nclass MyAgent:\n    def __init__(self, prompt: str):\n        self._frozen_prompt = prompt\n\n    @property\n    def system_prompt(self) -> str:\n        return self._frozen_prompt  # Read-only',
                                    ))

        return findings


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

GOVERNANCE_POLICIES: list[BasePolicy] = [
    GOV001(),
    GOV002(),
    GOV003(),
    GOV004(),
    GOV005(),
    GOV006(),
]
