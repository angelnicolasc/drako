"""Generate JSON and HTML governance rating reports."""

from __future__ import annotations

import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

DRAKO_VERSION = "2.1.0"

METHODOLOGY = (
    "Framework ratings are based on governance analysis of official examples "
    "and evaluation of framework-level security defaults. Scores reflect "
    "governance posture \u2014 not code quality, performance, or feature "
    "completeness. A low governance score means the framework makes it easy "
    "to build insecure agents, not that the framework itself is insecure. "
    "Frameworks can improve their score by adding security defaults, audit "
    "logging, and governance primitives.\n\n"
    "Drako is independent and has no commercial relationship with any "
    "framework vendor. These ratings are generated using the same open "
    "scanner available to everyone."
)

# Grading thresholds.
_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (55, "D"),
    (0, "F"),
]

_GRADE_COLORS: dict[str, str] = {
    "A": "#2ecc71",
    "B": "#27ae60",
    "C": "#f39c12",
    "D": "#e67e22",
    "F": "#e74c3c",
}


def _score_to_grade(score: float) -> str:
    clamped = max(0, min(100, score))
    for threshold, grade in _GRADE_THRESHOLDS:
        if clamped >= threshold:
            return grade
    return "F"


def _grade_color(grade: str) -> str:
    return _GRADE_COLORS.get(grade, "#e74c3c")


def build_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the full JSON report structure from per-framework results.

    Each item in *results* must contain:
      - name, display_name
      - example_scores: list of dicts with path / score / findings
      - default_modifier: int
      - default_details: dict
      - strengths: list[str]
      - errors: list[str]  (optional)
    """
    generated_at = datetime.now(timezone.utc).isoformat()
    frameworks: dict[str, Any] = {}
    all_scores: list[float] = []

    for fw in results:
        example_scores: list[dict] = fw.get("example_scores", [])
        raw_scores = [e["score"] for e in example_scores if e.get("score") is not None]

        if raw_scores:
            avg_example = statistics.mean(raw_scores)
        else:
            avg_example = 50.0  # neutral baseline when no examples scanned

        default_mod: int = fw.get("default_modifier", 0)

        # Weighted: 60% example average + 40% defaults contribution.
        # Defaults are expressed as a modifier on a 0-100 scale centred at 50.
        defaults_normalised = max(0.0, min(100.0, 50.0 + default_mod))
        composite = 0.6 * avg_example + 0.4 * defaults_normalised
        composite = max(0.0, min(100.0, composite))

        grade = _score_to_grade(composite)
        all_scores.append(composite)

        # Collect top findings across all examples.
        top_findings: list[dict] = []
        for ex in example_scores:
            for finding in ex.get("findings", [])[:3]:
                top_findings.append(finding)
        top_findings = sorted(
            top_findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                f.get("severity", "low"), 4
            ),
        )[:10]

        # Identify governance gaps.
        gaps: list[str] = []
        details = fw.get("default_details", {})
        breakdown = details.get("breakdown", {})
        for key, info in breakdown.items():
            if not info.get("enabled") and key != "code_execution_default":
                gaps.append(info["label"])
        if details.get("code_execution_penalty_applied"):
            gaps.insert(0, "Code execution enabled by default")

        frameworks[fw["name"]] = {
            "display_name": fw["display_name"],
            "grade": grade,
            "grade_color": _grade_color(grade),
            "score": round(composite, 1),
            "example_avg": round(avg_example, 1),
            "defaults_score": round(defaults_normalised, 1),
            "example_scores": example_scores,
            "default_analysis": fw.get("default_details", {}),
            "default_modifier": default_mod,
            "top_findings": top_findings,
            "strengths": fw.get("strengths", []),
            "governance_gaps": gaps,
            "errors": fw.get("errors", []),
        }

    # Summary statistics.
    summary: dict[str, Any] = {}
    if all_scores:
        summary["mean_score"] = round(statistics.mean(all_scores), 1)
        summary["median_score"] = round(statistics.median(all_scores), 1)
        summary["min_score"] = round(min(all_scores), 1)
        summary["max_score"] = round(max(all_scores), 1)
        summary["frameworks_rated"] = len(all_scores)
    else:
        summary["frameworks_rated"] = 0

    return {
        "generated_at": generated_at,
        "drako_version": DRAKO_VERSION,
        "methodology": METHODOLOGY,
        "frameworks": frameworks,
        "summary_stats": summary,
    }


def write_json_report(report: dict[str, Any], output_dir: Path) -> Path:
    """Write the report as a JSON file and return its path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "framework_ratings.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_html_report(report: dict[str, Any], output_dir: Path) -> Path:
    """Render the Jinja2 HTML template and write it to *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    template_dir = Path(__file__).resolve().parent / "templates"

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
    )
    template = env.get_template("ratings_page.html")

    # Sort frameworks by score descending for the ranking table.
    ranked = sorted(
        report["frameworks"].items(),
        key=lambda kv: kv[1]["score"],
        reverse=True,
    )

    html = template.render(
        report=report,
        ranked=ranked,
        grade_color=_grade_color,
    )

    path = output_dir / "framework_ratings.html"
    path.write_text(html, encoding="utf-8")
    return path
