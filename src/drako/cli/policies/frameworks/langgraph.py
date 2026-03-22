"""LangGraph framework-specific governance rules (FW-LANGGRAPH-001, FW-LANGGRAPH-002)."""

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

_HUMAN_GATE_PATTERNS = frozenset({
    "interrupt_before", "interrupt_after", "human_approval",
    "HumanApprovalCallbackHandler", "human_in_the_loop",
    "ask_human", "human_review", "human_gate",
})

_CHECKPOINTER_PATTERNS = frozenset({
    "MemorySaver", "SqliteSaver", "PostgresSaver", "AsyncPostgresSaver",
    "checkpointer", "RedisSaver",
})

_DESTRUCTIVE_TOOL_NAMES = frozenset({
    "write", "delete", "remove", "execute", "run", "send",
    "create", "update", "drop", "truncate", "post", "put",
    "patch", "deploy", "publish", "transfer", "pay",
})


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _file_has_checkpointer(tree: ast.AST) -> bool:
    """Check AST for checkpointer patterns (imports, calls, kwargs)."""
    for node in ast.walk(tree):
        # import MemorySaver / from langgraph.checkpoint...
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in _CHECKPOINTER_PATTERNS:
                    return True
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[-1] in _CHECKPOINTER_PATTERNS:
                    return True
        # checkpointer= keyword argument
        if isinstance(node, ast.keyword) and node.arg == "checkpointer":
            return True
        # MemorySaver() etc. calls
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in _CHECKPOINTER_PATTERNS:
                return True
    return False


# ---------------------------------------------------------------------------
# FW-LANGGRAPH-001: Unrestricted tool node without human gate
# ---------------------------------------------------------------------------

class FW_LANGGRAPH_001(FrameworkPolicy):
    policy_id = "FW-LANGGRAPH-001"
    required_framework = "langgraph"
    severity = "HIGH"
    title = "Unrestricted tool node without human gate"
    impact = (
        "ToolNode executes all bound tools unconditionally. Without a human "
        "gate, any LLM-decided tool invocation runs immediately — including "
        "destructive operations like file deletion or database writes."
    )
    attack_scenario = (
        "LLM is tricked via prompt injection to invoke a destructive tool "
        "(e.g. delete_file, drop_table). Since ToolNode has no human "
        "approval gate, the action executes immediately and irreversibly."
    )
    references = [
        "https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/",
        "https://langchain-ai.github.io/langgraph/reference/prebuilt/#langgraph.prebuilt.tool_node.ToolNode",
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
            has_tool_node = False
            tool_node_line = 0
            has_human_gate = False

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)
                if call_name == "ToolNode":
                    has_tool_node = True
                    tool_node_line = node.lineno

                # Check for human gate patterns in code constructs
                if call_name in (
                    "HumanApprovalCallbackHandler", "human_approval",
                    "ask_human", "human_review",
                ):
                    has_human_gate = True

            # Also check keyword arguments for interrupt_before/after
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg in (
                    "interrupt_before", "interrupt_after",
                    "human_in_the_loop", "human_approval",
                ):
                    has_human_gate = True

            if has_tool_node and not has_human_gate:
                line_content = (
                    lines[tool_node_line - 1].strip()
                    if tool_node_line <= len(lines)
                    else ""
                )
                findings.append(self._finding(
                    "LangGraph ToolNode used without a human-in-the-loop gate. "
                    "All bound tools execute unconditionally on LLM decision.",
                    file_path=rel_path,
                    line_number=tool_node_line,
                    code_snippet=line_content,
                    fix_snippet=(
                        "from langgraph.checkpoint.memory import MemorySaver\n\n"
                        "# Add interrupt_before to require human approval\n"
                        "graph = builder.compile(\n"
                        "    checkpointer=MemorySaver(),\n"
                        '    interrupt_before=["tools"],\n'
                        ")"
                    ),
                ))

        return findings


# ---------------------------------------------------------------------------
# FW-LANGGRAPH-002: No checkpointing on destructive operations
# ---------------------------------------------------------------------------

class FW_LANGGRAPH_002(FrameworkPolicy):
    policy_id = "FW-LANGGRAPH-002"
    required_framework = "langgraph"
    severity = "MEDIUM"
    title = "No checkpointing on destructive operations"
    impact = (
        "Without checkpointing, multi-step workflows cannot roll back when "
        "a later step fails or relies on incorrect earlier decisions. "
        "Destructive actions (file writes, API calls) cannot be undone."
    )
    attack_scenario = (
        "A multi-step workflow writes to a database in step 2, then fails "
        "in step 4. Without checkpointing, there is no record of the "
        "intermediate state and no way to roll back the database write."
    )
    references = [
        "https://langchain-ai.github.io/langgraph/concepts/persistence/",
        "https://langchain-ai.github.io/langgraph/how-tos/persistence/",
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

            # Check if file has checkpointer patterns via AST
            has_checkpointer = _file_has_checkpointer(tree)
            if has_checkpointer:
                continue

            # Look for StateGraph with ToolNode or tool-like nodes
            has_graph = False
            graph_line = 0
            has_destructive_tools = False

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)

                if call_name == "StateGraph":
                    has_graph = True
                    graph_line = node.lineno

                if call_name == "ToolNode":
                    has_destructive_tools = True

            # Also check @tool functions for destructive patterns
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    name_lower = node.name.lower()
                    if any(d in name_lower for d in _DESTRUCTIVE_TOOL_NAMES):
                        is_tool = any(
                            (isinstance(dec, ast.Name) and dec.id == "tool")
                            or (isinstance(dec, ast.Call)
                                and isinstance(dec.func, ast.Name)
                                and dec.func.id == "tool")
                            for dec in node.decorator_list
                        )
                        if is_tool:
                            has_destructive_tools = True

            if has_graph and has_destructive_tools and not has_checkpointer:
                line_content = (
                    lines[graph_line - 1].strip()
                    if graph_line <= len(lines)
                    else ""
                )
                findings.append(self._finding(
                    "LangGraph StateGraph with destructive tool operations "
                    "but no checkpointing configured on compile().",
                    file_path=rel_path,
                    line_number=graph_line,
                    code_snippet=line_content,
                    fix_snippet=(
                        "from langgraph.checkpoint.memory import MemorySaver\n\n"
                        "graph = builder.compile(\n"
                        "    checkpointer=MemorySaver(),  # enables rollback\n"
                        ")"
                    ),
                ))

        return findings


LANGGRAPH_POLICIES = [FW_LANGGRAPH_001(), FW_LANGGRAPH_002()]
