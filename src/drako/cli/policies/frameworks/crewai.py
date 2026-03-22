"""CrewAI framework-specific governance rules (FW-CREWAI-001 through FW-CREWAI-003)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from drako.cli.policies.frameworks.base import FrameworkPolicy

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata
    from drako.cli.policies.base import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    """Return the value node of a keyword argument in an ast.Call."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: ast.expr) -> bool:
    """Check if an AST node represents a truthy constant (True)."""
    return isinstance(node, ast.Constant) and node.value is True


def _get_call_name(node: ast.Call) -> str | None:
    """Get the simple function/class name from an ast.Call."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


# ---------------------------------------------------------------------------
# FW-CREWAI-001: Code execution enabled without sandbox
# ---------------------------------------------------------------------------

class FW_CREWAI_001(FrameworkPolicy):
    policy_id = "FW-CREWAI-001"
    required_framework = "crewai"
    severity = "CRITICAL"
    title = "Code execution enabled without sandbox"
    impact = (
        "CrewAI's code execution runs Python eval/exec in the same process "
        "with full filesystem and network access. A prompt injection in any "
        "upstream tool result can execute arbitrary code on your server."
    )
    attack_scenario = (
        "Attacker injects code via a tool result (e.g. web scraper). The "
        "researcher agent passes the result to a code-execution-enabled "
        "agent, which evaluates the payload with full system privileges."
    )
    references = [
        "https://docs.crewai.com/concepts/agents#agent-attributes",
        "https://cwe.mitre.org/data/definitions/94.html",
    ]
    remediation_effort = "moderate"

    def _evaluate_framework(
        self, bom: AgentBOM, metadata: ProjectMetadata
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()
            # Track whether any sandbox wrapper is present in the file
            file_has_sandbox = _file_has_sandbox_patterns(tree)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)
                if call_name not in ("Agent", "CrewAgent"):
                    continue

                code_exec_val = _get_keyword_value(node, "allow_code_execution")
                if code_exec_val is None or not _is_true(code_exec_val):
                    continue

                # Check if there's a sandbox-related keyword on this call
                has_sandbox_kw = any(
                    kw.arg in ("sandbox", "execution_mode", "code_execution_mode")
                    and kw.value
                    for kw in node.keywords
                    if kw.arg is not None
                )

                if not has_sandbox_kw and not file_has_sandbox:
                    line_content = (
                        lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else ""
                    )
                    findings.append(self._finding(
                        "CrewAI Agent has allow_code_execution=True without "
                        "any sandboxing wrapper or restricted execution environment.",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "# Use a sandboxed executor or Docker-based code execution\n"
                            "agent = Agent(\n"
                            '    role="coder",\n'
                            "    allow_code_execution=True,\n"
                            '    code_execution_mode="docker",  # or use e2b/modal sandbox\n'
                            ")"
                        ),
                    ))

        return findings


def _file_has_sandbox_patterns(tree: ast.AST) -> bool:
    """Check if a parsed AST contains sandbox-related code patterns.

    Only matches code constructs (imports, calls, keyword args), not
    comments or docstrings, to avoid false negatives.
    """
    for node in ast.walk(tree):
        # import e2b / import modal / from docker ...
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in ("e2b", "modal", "docker"):
                    return True
        if isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in ("e2b", "modal", "docker"):
                return True
        # code_execution_mode="..." keyword in any call
        if isinstance(node, ast.keyword) and node.arg in (
            "code_execution_mode", "sandbox", "execution_mode",
        ):
            return True
        # SandboxedCodeExecution(...) or RestrictedPythonExecutor(...)
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in (
                "SandboxedCodeExecution", "RestrictedPythonExecutor",
                "DockerExecutor", "E2BCodeInterpreter",
            ):
                return True
    return False


def _file_has_memory_isolation(tree: ast.AST) -> bool:
    """Check AST for memory isolation patterns (imports, calls, kwargs)."""
    isolation_names = {
        "ShortTermMemory", "LongTermMemory", "EntityMemory",
        "memory_config", "private_memory",
    }
    for node in ast.walk(tree):
        # import ShortTermMemory, etc.
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in isolation_names:
                    return True
        # memory_config= keyword argument
        if isinstance(node, ast.keyword) and node.arg in isolation_names:
            return True
        # ShortTermMemory() call
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in isolation_names:
                return True
    return False


# ---------------------------------------------------------------------------
# FW-CREWAI-002: No memory isolation between agents
# ---------------------------------------------------------------------------

class FW_CREWAI_002(FrameworkPolicy):
    policy_id = "FW-CREWAI-002"
    required_framework = "crewai"
    severity = "HIGH"
    title = "No memory isolation between agents"
    impact = (
        "Shared memory allows one compromised agent to poison the context "
        "for all other agents. An injection in the researcher agent's results "
        "persists in memory and influences the writer agent's decisions."
    )
    attack_scenario = (
        "Attacker poisons a web source that the researcher agent reads. "
        "The injected instructions are stored in shared memory and later "
        "retrieved by the writer agent, which follows them to exfiltrate data."
    )
    references = [
        "https://docs.crewai.com/concepts/memory",
        "https://cwe.mitre.org/data/definitions/1299.html",
    ]
    remediation_effort = "significant"

    def _evaluate_framework(
        self, bom: AgentBOM, metadata: ProjectMetadata
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Only relevant in multi-agent setups
        crewai_agents = [a for a in bom.agents if a.framework == "crewai"]
        if len(crewai_agents) < 2:
            return findings

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)
                if call_name != "Crew":
                    continue

                memory_val = _get_keyword_value(node, "memory")
                if memory_val is None or not _is_true(memory_val):
                    continue

                # Check if memory isolation is configured
                has_isolation = any(
                    kw.arg in (
                        "memory_config", "embedder", "long_term_memory",
                        "short_term_memory", "entity_memory",
                    )
                    for kw in node.keywords
                    if kw.arg is not None
                )

                # Also check file-level AST for per-agent memory config
                file_has_isolation = _file_has_memory_isolation(tree)

                if not has_isolation and not file_has_isolation:
                    line_content = (
                        lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else ""
                    )
                    findings.append(self._finding(
                        "Multi-agent CrewAI setup with shared memory enabled "
                        "but no per-agent memory isolation configured.",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "from crewai.memory import ShortTermMemory, EntityMemory\n"
                            "crew = Crew(\n"
                            "    agents=[researcher, writer],\n"
                            "    memory=True,\n"
                            "    memory_config={\n"
                            '        "provider": "rag",\n'
                            '        "isolation": "per_agent",\n'
                            "    },\n"
                            ")"
                        ),
                    ))

        return findings


# ---------------------------------------------------------------------------
# FW-CREWAI-003: Delegation without boundary enforcement
# ---------------------------------------------------------------------------

class FW_CREWAI_003(FrameworkPolicy):
    policy_id = "FW-CREWAI-003"
    required_framework = "crewai"
    severity = "HIGH"
    title = "Delegation without boundary enforcement"
    impact = (
        "Delegation lets Agent A instruct Agent B to perform actions A is "
        "forbidden from taking. Without boundary enforcement on delegation "
        "targets, tool restrictions on the delegating agent are meaningless."
    )
    attack_scenario = (
        "A restricted 'research' agent with allow_delegation=True delegates "
        "to a 'coder' agent that has file-write and code-execution tools. "
        "A prompt injection in research data causes the research agent to "
        "delegate a malicious task to the coder agent."
    )
    references = [
        "https://docs.crewai.com/concepts/agents#agent-attributes",
        "https://cwe.mitre.org/data/definitions/269.html",
    ]
    remediation_effort = "moderate"

    def _evaluate_framework(
        self, bom: AgentBOM, metadata: ProjectMetadata
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()
            # Collect all agent definitions in this file to check tool restrictions
            agents_with_tools: set[str] = set()
            all_agent_calls: list[tuple[ast.Call, int]] = []

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)
                if call_name not in ("Agent", "CrewAgent"):
                    continue
                all_agent_calls.append((node, node.lineno))

                tools_val = _get_keyword_value(node, "tools")
                if tools_val is not None:
                    # Agent has explicit tool list
                    role_val = _get_keyword_value(node, "role")
                    if role_val and isinstance(role_val, ast.Constant):
                        agents_with_tools.add(str(role_val.value))

            # Now check delegation agents
            for call_node, lineno in all_agent_calls:
                deleg_val = _get_keyword_value(call_node, "allow_delegation")
                if deleg_val is None or not _is_true(deleg_val):
                    continue

                # If there are other agents without explicit tool restrictions
                # in the same file, this is a delegation boundary issue
                total_agents = len(all_agent_calls)
                agents_with_explicit_tools = len(agents_with_tools)

                # Flag if any agent in the crew lacks explicit tools
                if total_agents > 1 and agents_with_explicit_tools < total_agents:
                    line_content = (
                        lines[lineno - 1].strip()
                        if lineno <= len(lines)
                        else ""
                    )
                    findings.append(self._finding(
                        "Agent with allow_delegation=True but not all agents "
                        "in the crew have explicit tool restrictions.",
                        file_path=rel_path,
                        line_number=lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "# Ensure ALL agents have explicit tool lists\n"
                            "researcher = Agent(\n"
                            '    role="researcher",\n'
                            "    allow_delegation=True,\n"
                            "    tools=[search_tool],  # explicit tool list\n"
                            ")\n"
                            "writer = Agent(\n"
                            '    role="writer",\n'
                            "    tools=[write_tool],  # explicit — no code execution\n"
                            ")"
                        ),
                    ))

        return findings


CREWAI_POLICIES = [FW_CREWAI_001(), FW_CREWAI_002(), FW_CREWAI_003()]
