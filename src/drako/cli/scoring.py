"""Governance score calculation for `drako scan`.

Scoring formula (start at 100, deduct per severity with caps):
  - CRITICAL: -15 each, cap -60
  - HIGH:     -8 each,  cap -40
  - MEDIUM:   -3 each,  cap -20
  - LOW:      -1 each,  cap -10

Category caps (applied after severity caps):
  - Framework: -30 max

Score range: 0-100
Grading: A (90-100), B (75-89), C (60-74), D (40-59), F (0-39)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.policies.base import Finding

# Points deducted per finding of each severity
_PER_FINDING = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
}

# Maximum total deduction per severity category
_CAPS = {
    "CRITICAL": 60,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 10,
}

# Maximum total deduction per finding category (only categories that need caps)
_CATEGORY_CAPS: dict[str, int] = {
    "Framework": 30,
    "Determinism": 25,
}


def calculate_score(findings: list[Finding]) -> int:
    """Calculate governance score from findings.

    Only vulnerability findings affect the score. Recommendations are
    shown separately and do not lower the governance score.

    Returns an integer 0-100.
    """
    # Filter out recommendations — only vulnerabilities affect the score
    findings = [f for f in findings if getattr(f, "finding_type", "vulnerability") == "vulnerability"]

    # If no category caps apply, use the fast path (existing behaviour)
    capped_categories = {
        f.category for f in findings if f.category in _CATEGORY_CAPS
    }

    if not capped_categories:
        # Fast path: no category caps involved — original algorithm
        return _score_by_severity(findings)

    # Slow path: separate capped-category findings from the rest
    uncapped: list[Finding] = []
    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category in _CATEGORY_CAPS:
            by_category.setdefault(f.category, []).append(f)
        else:
            uncapped.append(f)

    # Score the uncapped findings normally
    base_deduction = 100 - _score_by_severity(uncapped)

    # Add capped-category deductions
    cat_deduction = 0
    for cat, cat_findings in by_category.items():
        raw = _raw_deduction(cat_findings)
        cat_deduction += min(raw, _CATEGORY_CAPS[cat])

    score = 100 - base_deduction - cat_deduction
    return max(0, min(100, score))


def _score_by_severity(findings: list[Finding]) -> int:
    """Original severity-only scoring (no category caps)."""
    deductions: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in findings:
        sev = finding.severity
        if sev in deductions:
            deductions[sev] = min(
                deductions[sev] + _PER_FINDING[sev],
                _CAPS[sev],
            )

    return max(0, min(100, 100 - sum(deductions.values())))


def _raw_deduction(findings: list[Finding]) -> int:
    """Compute raw severity-capped deduction for a subset of findings."""
    deductions: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.severity
        if sev in deductions:
            deductions[sev] = min(
                deductions[sev] + _PER_FINDING[sev],
                _CAPS[sev],
            )
    return sum(deductions.values())


def score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def calculate_determinism_score(findings: list[Finding]) -> int:
    """Calculate determinism score from DET-* findings only.

    Uses the same severity deduction model as the governance score
    but only considers findings with category == "Determinism".
    Returns an integer 0-100.
    """
    det_findings = [f for f in findings if f.category == "Determinism"]
    return _score_by_severity(det_findings)


def findings_summary(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
