"""LangChain-flavoured fix suggestions for `drako scan --simple`."""

from __future__ import annotations

from typing import Callable

from drako.cli.policies.base import Finding


def _sec001(_f: Finding) -> str:
    return (
        "Move credentials out of source. Use ChatOpenAI() with no api_key argument "
        "and let it pick up OPENAI_API_KEY from the environment."
    )


def _sec002(_f: Finding) -> str:
    return (
        "Use a ChatPromptTemplate with explicit role-tagged messages and pass user "
        "input only via the {input} placeholder, never via string concatenation."
    )


def _sec003(_f: Finding) -> str:
    return (
        "Replace PythonREPLTool with PythonAstREPLTool, or remove the tool from the "
        "agent and route code generation to a sandboxed runner."
    )


def _sec004(_f: Finding) -> str:
    return (
        "Use FileManagementToolkit(root_dir='./workspace', selected_tools=[...]) so "
        "file ops are confined to a single directory."
    )


def _sec005(_f: Finding) -> str:
    return (
        "Replace RequestsGetTool with a custom Tool whose URL is validated against "
        "an allowlist before each call."
    )


def _sec007(_f: Finding) -> str:
    return (
        "Stop passing chain inputs into ShellTool. Replace it with a Tool that "
        "executes a fixed command and treats user input as a single argv element."
    )


def _gov001(_f: Finding) -> str:
    return (
        "Attach a CallbackHandler (e.g. FileCallbackHandler or LangSmith) to the "
        "chain so every LLM call is logged to a durable sink."
    )


def _gov003(_f: Finding) -> str:
    return (
        "Build the prompt once with ChatPromptTemplate.from_messages([...]) and do "
        "not mutate the resulting object at runtime."
    )


def _det001(_f: Finding) -> str:
    return (
        "Pass temperature=0 to the chat model: ChatOpenAI(model='gpt-4o', "
        "temperature=0)."
    )


def _det003(_f: Finding) -> str:
    return (
        "Pass request_timeout=30 (or similar) to the chat model so a hung HTTP "
        "call cannot block the chain forever."
    )


def _det005(_f: Finding) -> str:
    return (
        "Pass max_iterations=<n> when constructing the AgentExecutor so the agent "
        "cannot loop indefinitely."
    )


def _odd001(_f: Finding) -> str:
    return (
        "Add a system message to the ChatPromptTemplate that lists the agent's "
        "allowed scope and instructs it to refuse anything else."
    )


FIXES: dict[str, Callable[[Finding], str]] = {
    "SEC-001": _sec001,
    "SEC-002": _sec002,
    "SEC-003": _sec003,
    "SEC-004": _sec004,
    "SEC-005": _sec005,
    "SEC-007": _sec007,
    "GOV-001": _gov001,
    "GOV-003": _gov003,
    "DET-001": _det001,
    "DET-003": _det003,
    "DET-005": _det005,
    "ODD-001": _odd001,
}
