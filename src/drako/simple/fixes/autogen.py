"""AutoGen-flavoured fix suggestions for `drako scan --simple`."""

from __future__ import annotations

from typing import Callable

from drako.cli.policies.base import Finding


def _sec001(_f: Finding) -> str:
    return (
        "Move api_key out of llm_config dicts. Read it from os.environ and inject "
        "it once at startup."
    )


def _sec002(_f: Finding) -> str:
    return (
        "Filter messages with a register_reply hook that rejects unsafe content "
        "before the assistant agent processes them."
    )


def _sec003(_f: Finding) -> str:
    return (
        "Set code_execution_config={'use_docker': True} on the UserProxyAgent so "
        "code runs in an isolated container, never on the host."
    )


def _sec004(_f: Finding) -> str:
    return (
        "Set code_execution_config={'work_dir': './workspace'} so the agent's "
        "filesystem access is confined to that directory."
    )


def _sec005(_f: Finding) -> str:
    return (
        "Wrap any web-calling tool registered with register_function in a URL "
        "validator that enforces an allowlist."
    )


def _sec007(_f: Finding) -> str:
    return (
        "Replace shell-execution tools with structured function calls registered "
        "via register_function and parameterized arguments."
    )


def _gov001(_f: Finding) -> str:
    return (
        "Register a logging hook with register_reply on every agent so each "
        "message is appended to an audit file."
    )


def _gov003(_f: Finding) -> str:
    return (
        "Set system_message at agent construction and never call update_system_message "
        "at runtime."
    )


def _det001(_f: Finding) -> str:
    return (
        "Set 'temperature': 0 in the llm_config dict passed to AssistantAgent."
    )


def _det003(_f: Finding) -> str:
    return (
        "Set 'timeout': 60 in the llm_config dict so the model call cannot hang "
        "indefinitely."
    )


def _det005(_f: Finding) -> str:
    return (
        "Pass max_consecutive_auto_reply=<n> on the UserProxyAgent so the chat "
        "loop terminates after a bounded number of turns."
    )


def _odd001(_f: Finding) -> str:
    return (
        "Spell out the agent's allowed scope in system_message and have a "
        "termination_msg check that ends the conversation when scope is exceeded."
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
