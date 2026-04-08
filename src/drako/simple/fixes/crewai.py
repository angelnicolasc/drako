"""CrewAI-flavoured fix suggestions for `drako scan --simple`."""

from __future__ import annotations

from typing import Callable

from drako.cli.policies.base import Finding


def _sec001(_f: Finding) -> str:
    return (
        "Move credentials out of agent definitions. Read them from environment "
        "variables and pass them to LLM(api_key=os.environ['OPENAI_API_KEY'])."
    )


def _sec002(_f: Finding) -> str:
    return (
        "Validate task inputs before they reach the agent. Add a guardrail "
        "function to your Task that rejects unsafe content before backstory templating."
    )


def _sec003(_f: Finding) -> str:
    return (
        "Replace any custom code-execution tool with crewai_tools.CodeInterpreterTool "
        "(which sandboxes execution) or remove the tool from the agent."
    )


def _sec004(_f: Finding) -> str:
    return (
        "Use crewai_tools.FileReadTool / DirectoryReadTool with an explicit "
        "directory= argument so the agent cannot read outside that path."
    )


def _sec005(_f: Finding) -> str:
    return (
        "Restrict the WebsiteSearchTool / ScrapeWebsiteTool to a single domain by "
        "passing website='https://your-allowlisted-host.com' on construction."
    )


def _sec007(_f: Finding) -> str:
    return (
        "Stop passing raw task inputs into shell-running tools. Wrap the tool with "
        "an input validator or replace it with a parameterized equivalent."
    )


def _gov001(_f: Finding) -> str:
    return (
        "Enable CrewAI's step_callback on the Crew to log every agent step to "
        "your audit sink (file, DB, or Drako proxy)."
    )


def _gov003(_f: Finding) -> str:
    return (
        "Treat Agent.backstory and Agent.goal as constants. Set them at "
        "construction time and never reassign them at runtime."
    )


def _det001(_f: Finding) -> str:
    return (
        "Set llm = LLM(model='gpt-4o', temperature=0) when constructing the agent "
        "so the same input always produces the same plan."
    )


def _det003(_f: Finding) -> str:
    return (
        "Pass max_execution_time=<seconds> on the Agent so a stuck task cannot "
        "block the crew indefinitely."
    )


def _det005(_f: Finding) -> str:
    return (
        "Set max_iter=<n> on the Agent so it cannot loop forever when a tool "
        "keeps failing."
    )


def _odd001(_f: Finding) -> str:
    return (
        "Define the agent's allowed scope in Agent.role and Agent.goal explicitly, "
        "and add a guardrail tool that refuses out-of-scope requests."
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
