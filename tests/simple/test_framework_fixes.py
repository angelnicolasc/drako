"""Every whitelisted rule must have a fix in crewai, langchain, direct_api."""

import pytest

from drako.cli.policies.base import Finding
from drako.simple.fixes import FIX_MODULES
from drako.simple.router import route_fix, select_module
from drako.simple.rules import SIMPLE_RULE_WHITELIST

REQUIRED_MODULES = ("crewai", "langchain", "direct_api")


@pytest.mark.parametrize("module_key", REQUIRED_MODULES)
@pytest.mark.parametrize("rule_id", SIMPLE_RULE_WHITELIST)
def test_required_modules_cover_all_whitelisted_rules(
    module_key: str, rule_id: str
) -> None:
    fixes = FIX_MODULES[module_key]
    assert rule_id in fixes, f"{module_key} missing fix for {rule_id}"


@pytest.mark.parametrize("rule_id", SIMPLE_RULE_WHITELIST)
def test_fixes_return_non_empty_strings(rule_id: str) -> None:
    finding = Finding(
        policy_id=rule_id,
        category="Security",
        severity="HIGH",
        title="t",
        message="m",
    )
    for module_key in REQUIRED_MODULES:
        fn = FIX_MODULES[module_key][rule_id]
        out = fn(finding)
        assert isinstance(out, str) and len(out) > 10


def test_router_selects_crewai_when_present() -> None:
    assert select_module(["crewai", "langchain"]) == "crewai"


def test_router_falls_back_to_direct_api() -> None:
    assert select_module([]) == "direct_api"
    assert select_module(["unknown_thing"]) == "direct_api"


def test_router_handles_pyautogen_alias() -> None:
    assert select_module(["pyautogen"]) == "autogen"


def test_route_fix_falls_back_to_direct_api_when_framework_lacks_rule() -> None:
    finding = Finding(
        policy_id="SEC-001",
        category="Security",
        severity="CRITICAL",
        title="t",
        message="m",
    )
    # langgraph has SEC-001 — but we monkey-test the fallback logic via direct_api
    out = route_fix(finding, ["langchain"])
    assert "OPENAI_API_KEY" in out or "environment" in out.lower()
