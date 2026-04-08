"""Fix suggestions for projects calling OpenAI/Anthropic SDKs directly.

Used as the fallback fix module when no agent framework is detected. The
advice here aims at developers wiring up `openai`, `anthropic`, or similar
client libraries without an orchestration framework on top.
"""

from __future__ import annotations

from typing import Callable

from drako.cli.policies.base import Finding


def _sec001(_f: Finding) -> str:
    return (
        "Move the API key out of source. Read it from os.environ['OPENAI_API_KEY'] "
        "(or ANTHROPIC_API_KEY) and load secrets from a .env file via python-dotenv."
    )


def _sec002(_f: Finding) -> str:
    return (
        "Never concatenate user input directly into the system prompt. Pass it as a "
        "separate user-role message and validate length and content first."
    )


def _sec003(_f: Finding) -> str:
    return (
        "Disable the code-execution tool, or run untrusted code inside a sandbox "
        "(e.g. e2b, microsandbox) instead of exec()/subprocess on the host."
    )


def _sec004(_f: Finding) -> str:
    return (
        "Restrict filesystem access to a single working directory and reject paths "
        "that escape it (resolve and check against an allowlist)."
    )


def _sec005(_f: Finding) -> str:
    return (
        "Wrap network calls behind an httpx client configured with an allowlist of "
        "hostnames; reject any URL whose host is not on the list."
    )


def _sec007(_f: Finding) -> str:
    return (
        "Stop interpolating user input into shell or SQL strings. Use subprocess "
        "with a list argv, or parameterized SQL with placeholders."
    )


def _gov001(_f: Finding) -> str:
    return (
        "Wrap every model call in a logger that records the prompt, response, and "
        "timestamp to an append-only file or database."
    )


def _gov003(_f: Finding) -> str:
    return (
        "Treat the system prompt as immutable: load it once at startup and refuse "
        "any code path that overwrites it at runtime."
    )


def _det001(_f: Finding) -> str:
    return (
        "Pass temperature=0 (or a small fixed value) to the chat completion call "
        "to make outputs reproducible."
    )


def _det003(_f: Finding) -> str:
    return (
        "Add a timeout to the client (e.g. OpenAI(timeout=30) or "
        "httpx.Timeout(30)) so a hung call cannot block the process forever."
    )


def _det005(_f: Finding) -> str:
    return (
        "Cap your retry/loop logic with a hard max_iterations counter so the "
        "process cannot loop indefinitely."
    )


def _odd001(_f: Finding) -> str:
    return (
        "Document the operating boundary in code: a constant listing what topics, "
        "domains, and actions are allowed. Reject anything else early."
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
