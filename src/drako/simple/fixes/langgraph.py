"""LangGraph-flavoured fix suggestions for `drako scan --simple`."""

from __future__ import annotations

from typing import Callable

from drako.cli.policies.base import Finding


def _sec001(_f: Finding) -> str:
    return (
        "Move credentials to environment variables and read them inside the node "
        "function via os.environ, never inside the graph definition file."
    )


def _sec002(_f: Finding) -> str:
    return (
        "Add a validation node before the LLM node and have its conditional edge "
        "route unsafe inputs to a refusal node."
    )


def _sec003(_f: Finding) -> str:
    return (
        "Replace the python_exec node with a sandboxed runner, or remove it from "
        "the graph entirely."
    )


def _sec004(_f: Finding) -> str:
    return (
        "Make file-access nodes accept only paths inside a configured working "
        "directory and reject anything else in the node body."
    )


def _sec005(_f: Finding) -> str:
    return (
        "Wrap HTTP-calling nodes in a helper that checks the URL host against an "
        "allowlist before issuing the request."
    )


def _sec007(_f: Finding) -> str:
    return (
        "Use parameterized SQL inside db nodes; never f-string user input into "
        "the query."
    )


def _gov001(_f: Finding) -> str:
    return (
        "Use a checkpointer (e.g. SqliteSaver) so every state transition is "
        "persisted, then export it as the audit trail."
    )


def _gov003(_f: Finding) -> str:
    return (
        "Define the system prompt as a module-level constant and reference it "
        "from each node; do not write it back into the graph state."
    )


def _det001(_f: Finding) -> str:
    return (
        "Construct the chat model with temperature=0 in the node factory so every "
        "node uses a deterministic LLM."
    )


def _det003(_f: Finding) -> str:
    return (
        "Pass a timeout to the chat model and use graph.invoke(..., "
        "config={'recursion_limit': N}) to bound execution."
    )


def _det005(_f: Finding) -> str:
    return (
        "Set recursion_limit on the compiled graph (e.g. graph.compile().with_config("
        "recursion_limit=25)) so cyclic edges cannot loop forever."
    )


def _odd001(_f: Finding) -> str:
    return (
        "Document the graph's allowed scope in the system prompt and add a "
        "guardrail node that routes out-of-scope state to END."
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
