"""Semantic Kernel framework-specific governance rules (FW-SK-001, FW-SK-002)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from drako.cli.policies.frameworks.base import FrameworkPolicy

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata
    from drako.cli.policies.base import Finding


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _get_full_attr(node: ast.expr) -> str:
    """Get dotted attribute name like 'kernel.add_plugin'."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


# ---------------------------------------------------------------------------
# FW-SK-001: All plugins auto-imported
# ---------------------------------------------------------------------------

class FW_SK_001(FrameworkPolicy):
    policy_id = "FW-SK-001"
    required_framework = "semantic_kernel"
    severity = "HIGH"
    title = "All plugins auto-imported without filtering"
    impact = (
        "Importing all plugin functions exposes every capability to the "
        "planner. The LLM can invoke any function, including administrative "
        "or destructive ones intended only for internal use."
    )
    attack_scenario = (
        "A plugin module contains both read_data() and delete_all_data() "
        "functions. Importing the entire plugin without filtering allows "
        "the planner to invoke delete_all_data() if the LLM decides it's "
        "relevant to the user's query."
    )
    references = [
        "https://learn.microsoft.com/en-us/semantic-kernel/concepts/plugins/",
        "https://cwe.mitre.org/data/definitions/284.html",
    ]
    remediation_effort = "trivial"

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

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                # Check for various plugin import patterns
                full_name = ""
                if isinstance(node.func, ast.Attribute):
                    full_name = _get_full_attr(node.func)
                call_name = _get_call_name(node)

                is_plugin_import = call_name in (
                    "add_plugin",
                    "import_plugin_from_module",
                    "import_native_plugin_from_directory",
                    "import_plugin_from_directory",
                ) or "add_plugin" in full_name

                if not is_plugin_import:
                    continue

                # Check if function_name filtering is used
                has_filter = False
                for kw in node.keywords:
                    if kw.arg in ("function_name", "functions", "include"):
                        has_filter = True
                        break

                # Check if the import is inside a loop (mass import)
                # or if it uses directory/module import (bulk)
                is_bulk = call_name in (
                    "import_native_plugin_from_directory",
                    "import_plugin_from_directory",
                    "import_plugin_from_module",
                )

                if not has_filter and is_bulk:
                    line_content = (
                        lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else ""
                    )
                    findings.append(self._finding(
                        "Semantic Kernel plugin imported without explicit "
                        "function filtering — all functions exposed to planner.",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "# Import only specific functions\n"
                            "kernel.add_plugin(\n"
                            "    plugin=my_plugin,\n"
                            '    plugin_name="my_plugin",\n'
                            '    functions=["safe_read", "safe_search"],  # explicit allowlist\n'
                            ")"
                        ),
                    ))

        return findings


# ---------------------------------------------------------------------------
# FW-SK-002: No cost guard on planner
# ---------------------------------------------------------------------------

_COST_GUARD_KEYWORDS = frozenset({
    "max_tokens", "max_steps", "max_iterations",
    "budget", "cost_limit", "step_limit",
    "max_auto_invoke_attempts",
})


def _file_has_cost_guard(tree: ast.AST) -> bool:
    """Check AST for cost guard patterns (keyword args, variable assignments)."""
    for node in ast.walk(tree):
        # keyword argument: max_steps=5
        if isinstance(node, ast.keyword) and node.arg in _COST_GUARD_KEYWORDS:
            return True
        # variable assignment: max_auto_invoke_attempts = 5
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _COST_GUARD_KEYWORDS:
                    return True
    return False


_PLANNER_CLASSES = frozenset({
    "ActionPlanner", "SequentialPlanner", "StepwisePlanner",
    "HandlebarsPlanner", "FunctionCallingStepwisePlanner",
})


class FW_SK_002(FrameworkPolicy):
    policy_id = "FW-SK-002"
    required_framework = "semantic_kernel"
    severity = "MEDIUM"
    title = "No cost guard on planner"
    impact = (
        "SK planners can chain unlimited function calls. Without cost guards, "
        "a misbehaving or injection-influenced planner can make hundreds of "
        "LLM calls, generate unbounded costs, and amplify blast radius."
    )
    attack_scenario = (
        "A user query triggers the planner to create a long plan. Each "
        "step makes an LLM call. Without cost guards, the planner runs "
        "100+ steps before reaching a conclusion, costing hundreds of "
        "dollars in API fees."
    )
    references = [
        "https://learn.microsoft.com/en-us/semantic-kernel/concepts/planning/",
        "https://cwe.mitre.org/data/definitions/770.html",
    ]
    remediation_effort = "trivial"

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

            # Check for budget/cost patterns via AST
            has_cost_guard = _file_has_cost_guard(tree)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)

                if call_name in _PLANNER_CLASSES and not has_cost_guard:
                    line_content = (
                        lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else ""
                    )
                    findings.append(self._finding(
                        "Semantic Kernel planner instantiated without cost "
                        "guards (max_steps, max_tokens, budget constraints).",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "from semantic_kernel.planners import SequentialPlanner\n\n"
                            "planner = SequentialPlanner(\n"
                            "    kernel=kernel,\n"
                            "    service_id='planner',\n"
                            ")\n"
                            "# Set execution limits\n"
                            "settings = kernel.get_prompt_execution_settings_class()\n"
                            "settings.max_auto_invoke_attempts = 5  # limit tool calls"
                        ),
                    ))

        return findings


SK_POLICIES = [FW_SK_001(), FW_SK_002()]
