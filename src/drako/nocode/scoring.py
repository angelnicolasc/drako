"""Governance scoring for nocode workflows.

We deliberately reuse `drako.cli.scoring` so that the score and grade for
a workflow follow the exact same rubric as a code project — one source of
truth across the whole product surface.
"""

from __future__ import annotations

from drako.cli.scoring import calculate_score, score_to_grade
from drako.nocode.graph import NocodeFinding


def score_workflow(findings: list[NocodeFinding]) -> tuple[int, str]:
    """Return (score 0-100, letter grade) for a list of nocode findings."""
    score = calculate_score(list(findings))
    return score, score_to_grade(score)
