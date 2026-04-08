"""ComplianceContext build from scan + answers."""

import json
from pathlib import Path

from drako.comply.mapping import build_context
from drako.comply.storage import save


def test_build_context_merges_scan_and_answers(tmp_path: Path) -> None:
    drako_dir = tmp_path / ".drako"
    drako_dir.mkdir()
    (drako_dir / ".last_scan.json").write_text(
        json.dumps(
            {
                "project_name": "OnboardingBot",
                "framework": "crewai",
                "score": 72,
                "agents": [{"name": "Reviewer", "framework": "crewai"}],
                "tools": [],
                "models": [],
                "scanned_at": "2026-04-08T10:00:00+00:00",
            }
        )
    )
    save(
        {
            "system_name": "Onboarding Bot",
            "system_version": "1.0",
            "deployment_regions": ["EU"],
            "domain": "finance",
            "known_limitations": ["English only"],
        },
        tmp_path,
    )
    ctx = build_context(tmp_path)
    assert ctx.system_name == "Onboarding Bot"
    assert ctx.governance_score == 72
    assert ctx.frameworks == ["crewai"]
    assert ctx.deployment_regions == ["EU"]
    assert ctx.known_limitations == ["English only"]
    assert len(ctx.agents) == 1


def test_build_context_with_no_inputs_does_not_crash(tmp_path: Path) -> None:
    ctx = build_context(tmp_path)
    assert ctx.system_name == ""
    assert ctx.governance_score == 0
