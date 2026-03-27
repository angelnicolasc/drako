"""TypeScript determinism policy rules (DET-*).

Detects non-deterministic LLM configurations: missing temperature
settings and missing timeout parameters.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding
from drako.cli.policies.typescript._utils import get_parser, is_ts_file

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata

_LLM_CALL_NAMES = frozenset({
    "create",  # openai.chat.completions.create(...)
    "generateText", "streamText",  # Vercel AI SDK
    "invoke", "call",  # LangChain.js
    "generate", "complete",
})

_LLM_CONSTRUCTOR_NAMES = frozenset({
    "OpenAI", "Anthropic", "ChatOpenAI", "ChatAnthropic",
    "GoogleGenerativeAI", "createOpenAI", "createAnthropic",
})

_TEMPERATURE_RE = re.compile(r"\btemperature\s*[=:]\s*([0-9.]+)")
_TIMEOUT_RE = re.compile(r"\btimeout\s*[=:]\s*")


# ---------------------------------------------------------------------------
# DET-001: Temperature not set
# ---------------------------------------------------------------------------


class DET001TS(BasePolicy):
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
        parser = get_parser()
        if parser is None:
            return findings

        for rel_path, content in metadata.file_contents.items():
            if not is_ts_file(rel_path):
                continue
            tree = parser.parse(content, rel_path)

            # Check function calls to LLM APIs
            for call in parser.find_function_calls(tree):
                if call.name not in _LLM_CALL_NAMES:
                    continue

                # Look for temperature in the arguments text
                temp_match = _TEMPERATURE_RE.search(call.args_text)
                if temp_match is None:
                    findings.append(self._finding(
                        f"LLM call `{call.full_name}` does not set temperature explicitly. "
                        "Set temperature: 0 for deterministic output.",
                        file_path=rel_path,
                        line_number=call.line,
                        code_snippet=f"{call.full_name}({call.args_text[:50]})",
                        fix_snippet=f"{call.full_name}({{ ..., temperature: 0 }})",
                    ))
                else:
                    temp_val = float(temp_match.group(1))
                    if temp_val > 0:
                        findings.append(self._finding(
                            f"LLM call `{call.full_name}` has temperature={temp_val}. "
                            "Set temperature: 0 for deterministic output.",
                            file_path=rel_path,
                            line_number=call.line,
                            code_snippet=f"temperature: {temp_val}",
                            fix_snippet="temperature: 0",
                        ))

            # Check constructor calls (new OpenAI({ ... }))
            for call in parser.find_new_expressions(tree):
                if call.name not in _LLM_CONSTRUCTOR_NAMES:
                    continue
                temp_match = _TEMPERATURE_RE.search(call.args_text)
                if temp_match is not None:
                    temp_val = float(temp_match.group(1))
                    if temp_val > 0:
                        findings.append(self._finding(
                            f"`new {call.name}()` configured with temperature={temp_val}. "
                            "Use temperature: 0 for deterministic output.",
                            file_path=rel_path,
                            line_number=call.line,
                            code_snippet=f"temperature: {temp_val}",
                            fix_snippet="temperature: 0",
                        ))

        return findings


# ---------------------------------------------------------------------------
# DET-002: No timeout on LLM calls
# ---------------------------------------------------------------------------


class DET002TS(BasePolicy):
    policy_id = "DET-002"
    category = "Determinism"
    severity = "MEDIUM"
    title = "No timeout on LLM API calls"
    impact = (
        "LLM API calls without timeouts can hang indefinitely, "
        "causing cascading failures in production systems."
    )
    attack_scenario = (
        "OpenAI API experiences a slowdown. Without timeouts, all "
        "agent threads block forever, bringing down the service."
    )
    references = [
        "https://platform.openai.com/docs/guides/error-codes",
    ]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []
        parser = get_parser()
        if parser is None:
            return findings

        for rel_path, content in metadata.file_contents.items():
            if not is_ts_file(rel_path):
                continue
            tree = parser.parse(content, rel_path)

            for call in parser.find_function_calls(tree):
                if call.name not in _LLM_CALL_NAMES:
                    continue
                if not _TIMEOUT_RE.search(call.args_text):
                    findings.append(self._finding(
                        f"LLM call `{call.full_name}` has no timeout configured.",
                        file_path=rel_path,
                        line_number=call.line,
                        code_snippet=f"{call.full_name}({call.args_text[:50]})",
                        fix_snippet=f"{call.full_name}({{ ..., timeout: 30_000 }})",
                    ))

            for call in parser.find_new_expressions(tree):
                if call.name not in _LLM_CONSTRUCTOR_NAMES:
                    continue
                if not _TIMEOUT_RE.search(call.args_text):
                    findings.append(self._finding(
                        f"`new {call.name}()` has no timeout configured.",
                        file_path=rel_path,
                        line_number=call.line,
                        code_snippet=f"new {call.name}({call.args_text[:50]})",
                        fix_snippet=f"new {call.name}({{ ..., timeout: 30_000 }})",
                    ))

        return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TS_DETERMINISM_POLICIES: list[BasePolicy] = [
    DET001TS(),
    DET002TS(),
]
