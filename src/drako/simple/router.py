"""Route findings to the right framework-specific fix module.

Uses the highest-confidence framework returned by drako's detector. Falls
back to direct_api when no agent framework is recognised — solo developers
calling OpenAI/Anthropic directly are the dominant case.
"""

from __future__ import annotations

from typing import Callable, Iterable

from drako.cli.policies.base import Finding
from drako.simple.fixes import FIX_MODULES

# Map of normalised framework names to fix-module keys.
_FRAMEWORK_ALIASES = {
    "crewai": "crewai",
    "langchain": "langchain",
    "langgraph": "langgraph",
    "autogen": "autogen",
    "pyautogen": "autogen",
}


def select_module(framework_names: Iterable[str]) -> str:
    """Select the fix module key for the highest-confidence framework.

    Returns the module key (one of FIX_MODULES) — defaults to "direct_api".
    """
    for name in framework_names:
        key = _FRAMEWORK_ALIASES.get(name.lower())
        if key:
            return key
    return "direct_api"


def route_fix(finding: Finding, framework_names: Iterable[str]) -> str:
    """Return a one-sentence fix string for a finding under the given framework.

    Falls back through: framework module → direct_api module → generic message.
    """
    module_key = select_module(framework_names)
    fixes: dict[str, Callable[[Finding], str]] = FIX_MODULES[module_key]
    fn = fixes.get(finding.policy_id)
    if fn is None and module_key != "direct_api":
        fn = FIX_MODULES["direct_api"].get(finding.policy_id)
    if fn is None:
        return (
            finding.fix_snippet
            or "Run `drako scan --details` for the full remediation guide."
        )
    return fn(finding)
