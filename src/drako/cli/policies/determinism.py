"""Determinism policy rules (DET-001 through DET-007).

These rules measure how predictable and reproducible an agent's behavior is
in production. The Determinism Score is separate from the Governance Score
and speaks to reliability engineers, not compliance officers.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Matches LLM API call patterns (method calls, not constructors)
_LLM_CALL_PATTERNS = re.compile(
    r"(?:chat\.completions\.create|completions\.create|"
    r"\.invoke|\.generate|\.predict|\.agenerate|"
    r"\.ainvoke|\.apredict|\.run|\.acreate)",
)

# Matches LLM wrapper constructors that accept per-call params (temperature, etc.)
# Does NOT include raw SDK constructors (OpenAI(), Anthropic()) where these params
# are set on method calls instead.
_LLM_CONSTRUCTOR_PATTERNS = re.compile(
    r"^(?:ChatOpenAI|ChatAnthropic|AzureChatOpenAI|"
    r"ChatGoogleGenerativeAI|Gemini|Ollama|ChatOllama)$",
)

_TEMPERATURE_KWARG = "temperature"
_TIMEOUT_KWARG = "timeout"
_SEED_KWARG = "seed"

_RETRY_PATTERNS = re.compile(
    r"(?:retry|retries|max_retries|tenacity|backoff|fallback|on_error)",
    re.IGNORECASE,
)

_EXTERNAL_API_CALLS = re.compile(
    r"(?:httpx\.(?:get|post|put|delete|patch)|"
    r"requests\.(?:get|post|put|delete|patch)|"
    r"urllib\.request\.urlopen|"
    r"aiohttp\.ClientSession)",
    re.IGNORECASE,
)

_ITERATION_LIMIT_PATTERNS = re.compile(
    r"(?:max_iterations|max_loops|recursion_limit|max_retries|max_turns|"
    r"max_rounds|max_steps|iteration_limit|loop_limit)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# DET-001: Non-deterministic temperature setting
# ---------------------------------------------------------------------------

class DET001(BasePolicy):
    policy_id = "DET-001"
    category = "Determinism"
    severity = "HIGH"
    title = "LLM temperature not set or greater than zero"
    impact = (
        "Non-zero temperature causes the LLM to produce different outputs "
        "for identical inputs, making agent behavior unpredictable across runs."
    )
    attack_scenario = (
        "A customer support agent with temperature=0.7 gives contradictory "
        "answers to the same question, eroding user trust and causing "
        "compliance issues."
    )
    references = [
        "https://platform.openai.com/docs/api-reference/completions/create#temperature",
    ]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = _get_call_name(node)
                if not func_name or not _is_llm_call(func_name):
                    continue

                temp_value = _get_kwarg_value(node, _TEMPERATURE_KWARG)
                if temp_value is None:
                    # temperature not set at all
                    findings.append(self._finding(
                        f"LLM call '{func_name}' does not set temperature explicitly. "
                        "Set temperature=0 for deterministic output.",
                        file_path=rel_path,
                        line_number=getattr(node, "lineno", None),
                        code_snippet=f"{func_name}(...)",
                        fix_snippet=f"{func_name}(..., temperature=0)",
                    ))
                elif isinstance(temp_value, (int, float)) and temp_value > 0:
                    findings.append(self._finding(
                        f"LLM call '{func_name}' has temperature={temp_value}. "
                        "Set temperature=0 for deterministic output.",
                        file_path=rel_path,
                        line_number=getattr(node, "lineno", None),
                        code_snippet=f"temperature={temp_value}",
                        fix_snippet="temperature=0",
                    ))

        return findings


# ---------------------------------------------------------------------------
# DET-002: No timeout configured on LLM calls
# ---------------------------------------------------------------------------

class DET002(BasePolicy):
    policy_id = "DET-002"
    category = "Determinism"
    severity = "HIGH"
    title = "No timeout configured on LLM calls"
    impact = (
        "Without a timeout, an LLM API call can hang indefinitely, causing "
        "the agent workflow to stall and potentially consume resources."
    )
    attack_scenario = (
        "An LLM provider has a partial outage. Without timeout, the agent "
        "hangs for 10+ minutes, the orchestrator retries, and the system "
        "accumulates zombie processes."
    )
    references = [
        "https://docs.python.org/3/library/http.client.html#http.client.HTTPConnection.request",
    ]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = _get_call_name(node)
                if not func_name or not _is_llm_call(func_name):
                    continue

                timeout_value = _get_kwarg_value(node, _TIMEOUT_KWARG)
                if timeout_value is None:
                    findings.append(self._finding(
                        f"LLM call '{func_name}' does not set a timeout. "
                        "Add timeout=30 to prevent indefinite hangs.",
                        file_path=rel_path,
                        line_number=getattr(node, "lineno", None),
                        code_snippet=f"{func_name}(...)",
                        fix_snippet=f"{func_name}(..., timeout=30)",
                    ))

        return findings


# ---------------------------------------------------------------------------
# DET-003: No retry/fallback on LLM call
# ---------------------------------------------------------------------------

class DET003(BasePolicy):
    policy_id = "DET-003"
    category = "Determinism"
    severity = "MEDIUM"
    title = "No retry or fallback on LLM call"
    impact = (
        "A single transient API error kills the entire workflow. "
        "Retries with exponential backoff significantly improve reliability."
    )
    attack_scenario = (
        "The LLM provider returns a 503 during a rate-limit spike. "
        "Without retry, the agent fails permanently instead of "
        "recovering after a brief wait."
    )
    references = [
        "https://docs.aws.amazon.com/general/latest/gr/api-retries.html",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            has_llm_call = bool(
                _LLM_CALL_PATTERNS.search(content)
                or _LLM_CONSTRUCTOR_PATTERNS.search(content)
            )
            has_retry = bool(_RETRY_PATTERNS.search(content))

            if has_llm_call and not has_retry:
                findings.append(self._finding(
                    "File contains LLM calls but no retry/fallback pattern detected. "
                    "Add retries with exponential backoff for resilience.",
                    file_path=rel_path,
                ))

        return findings


# ---------------------------------------------------------------------------
# DET-004: External dependency without error handling
# ---------------------------------------------------------------------------

class DET004(BasePolicy):
    policy_id = "DET-004"
    category = "Determinism"
    severity = "HIGH"
    title = "External API call without error handling"
    impact = (
        "If an external API is down, the agent crashes instead of "
        "degrading gracefully. Critical for production reliability."
    )
    attack_scenario = (
        "A tool calls a third-party API without try/except. The API "
        "returns a 500 error, the tool raises an unhandled exception, "
        "and the entire agent workflow terminates."
    )
    references = [
        "https://docs.python.org/3/tutorial/errors.html",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            # Find external API calls not inside try/except
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                call_str = _get_call_name(node)
                if not call_str or not _EXTERNAL_API_CALLS.search(call_str):
                    continue

                # Check if this call is inside a try/except block
                if not _is_inside_try(tree, node):
                    findings.append(self._finding(
                        f"External API call '{call_str}' is not wrapped in "
                        "try/except. Add error handling for resilience.",
                        file_path=rel_path,
                        line_number=getattr(node, "lineno", None),
                        code_snippet=call_str,
                    ))

        return findings


# ---------------------------------------------------------------------------
# DET-005: No max_iterations or recursion limit
# ---------------------------------------------------------------------------

class DET005(BasePolicy):
    policy_id = "DET-005"
    category = "Determinism"
    severity = "MEDIUM"
    title = "No iteration or recursion limit configured"
    impact = (
        "Without a max_iterations limit, an agent can loop infinitely, "
        "consuming unbounded tokens and time."
    )
    attack_scenario = (
        "An agent enters a reasoning loop where it repeatedly calls the "
        "same tool. Without a limit, the loop runs until the token budget "
        "is exhausted or the process is killed."
    )
    references = [
        "https://docs.crewai.com/concepts/agents#agent-attributes",
    ]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        if not bom.agents:
            return findings

        # Check if any source file mentions iteration limits
        all_source = "\n".join(metadata.file_contents.values())
        has_limit = bool(_ITERATION_LIMIT_PATTERNS.search(all_source))

        if not has_limit:
            findings.append(self._finding(
                "No iteration or recursion limit detected in agent configuration. "
                "Add max_iterations to prevent infinite loops.",
            ))

        return findings


# ---------------------------------------------------------------------------
# DET-006: Non-deterministic tool ordering
# ---------------------------------------------------------------------------

class DET006(BasePolicy):
    policy_id = "DET-006"
    category = "Determinism"
    severity = "MEDIUM"
    title = "Non-deterministic tool selection"
    impact = (
        "When tool selection depends entirely on the LLM without constraints, "
        "the same input can produce different tool call sequences across runs."
    )
    attack_scenario = (
        "An agent with 10 tools and no ordering constraint sometimes calls "
        "search, analyze, report and other times analyze, search, report. "
        "This makes debugging impossible and violates audit requirements."
    )
    references = [
        "https://docs.crewai.com/concepts/tools",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for agent in bom.agents:
            if len(agent.tools) > 5:
                findings.append(self._finding(
                    f"Agent '{agent.name}' has {len(agent.tools)} tools with no "
                    "explicit ordering or priority. Consider reducing tool count "
                    "or defining tool selection constraints.",
                    file_path=agent.file_path,
                    line_number=agent.line_number,
                ))

        return findings


# ---------------------------------------------------------------------------
# DET-007: No seed configured for reproducibility
# ---------------------------------------------------------------------------

class DET007(BasePolicy):
    policy_id = "DET-007"
    category = "Determinism"
    severity = "LOW"
    title = "No seed configured for LLM reproducibility"
    impact = (
        "Without a seed parameter, LLM outputs cannot be reproduced for "
        "debugging or audit purposes."
    )
    attack_scenario = (
        "A production incident occurs but the team cannot reproduce the "
        "exact LLM responses that led to the failure because no seed "
        "was set during the original run."
    )
    references = [
        "https://platform.openai.com/docs/api-reference/completions/create#seed",
    ]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = _get_call_name(node)
                if not func_name or not _is_llm_call(func_name):
                    continue

                seed_value = _get_kwarg_value(node, _SEED_KWARG)
                if seed_value is None:
                    findings.append(self._finding(
                        f"LLM call '{func_name}' does not set a seed. "
                        "Add seed=42 for reproducible outputs during debugging.",
                        file_path=rel_path,
                        line_number=getattr(node, "lineno", None),
                        code_snippet=f"{func_name}(...)",
                        fix_snippet=f"{func_name}(..., seed=42)",
                    ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_llm_call(func_name: str) -> bool:
    """Check if a function name represents an LLM API call.

    Matches method-level calls like client.chat.completions.create() and
    LLM wrapper constructors like ChatOpenAI() (which accept temperature etc.
    as constructor args). Does NOT match raw SDK constructors like OpenAI()
    which don't take these per-call parameters.
    """
    return bool(
        _LLM_CALL_PATTERNS.search(func_name)
        or _LLM_CONSTRUCTOR_PATTERNS.match(func_name)
    )


def _get_call_name(node: ast.Call) -> str | None:
    """Extract the function/method name from an ast.Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        obj = node.func
        while isinstance(obj, ast.Attribute):
            parts.append(obj.attr)
            obj = obj.value
        if isinstance(obj, ast.Name):
            parts.append(obj.id)
        return ".".join(reversed(parts))
    return None


def _get_kwarg_value(node: ast.Call, kwarg_name: str) -> object | None:
    """Get the value of a keyword argument from an ast.Call node.

    Returns the Python value for simple constants, True for non-constant
    expressions, or None if the kwarg is not present.
    """
    for kw in node.keywords:
        if kw.arg == kwarg_name:
            if isinstance(kw.value, ast.Constant):
                return kw.value.value
            return True  # present but non-literal
    return None


def _is_inside_try(tree: ast.AST, target_node: ast.AST) -> bool:
    """Check if a node is inside a try/except block.

    Uses parent tracking via a walk that sets parent references.
    """
    target_line = getattr(target_node, "lineno", None)
    if target_line is None:
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            try_start = node.lineno
            # Find the end of the try block (last handler or finally)
            try_end = try_start
            for handler in node.handlers:
                for child in ast.walk(handler):
                    line = getattr(child, "lineno", 0)
                    if line > try_end:
                        try_end = line
            if node.finalbody:
                for child in ast.walk(node):
                    line = getattr(child, "lineno", 0)
                    if line > try_end:
                        try_end = line

            if try_start <= target_line <= try_end:
                return True

    return False


# ---------------------------------------------------------------------------
# Exported list
# ---------------------------------------------------------------------------

DETERMINISM_POLICIES = [
    DET001(),
    DET002(),
    DET003(),
    DET004(),
    DET005(),
    DET006(),
    DET007(),
]
