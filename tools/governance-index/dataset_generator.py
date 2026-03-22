# mypy: strict
"""Benchmark dataset generator.

Converts scan results into the benchmark_dataset.json format
used by `drako scan --benchmark`. The output schema exactly
matches sdk/src/drako/data/benchmark_dataset.json so that
compute_benchmark() works unchanged.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scan_runner import RepoScanResult


def _percentile(sorted_values: list[int], p: float) -> int:
    """Compute percentile from a sorted list (nearest-rank method)."""
    if not sorted_values:
        return 0
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(sorted_values):
        return sorted_values[-1]
    d = k - f
    return round(sorted_values[f] + d * (sorted_values[c] - sorted_values[f]))


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _median(values: list[int]) -> int:
    if not values:
        return 0
    return int(statistics.median(values))


def generate_dataset(results: list[RepoScanResult]) -> dict[str, object]:
    """Generate benchmark dataset matching the existing schema.

    Args:
        results: List of scan results from index building.

    Returns:
        Dict matching benchmark_dataset.json schema, ready for json.dump().
    """
    scores = sorted([r.score for r in results])

    # Framework breakdown
    by_framework: dict[str, list[int]] = defaultdict(list)
    for r in results:
        fw = r.framework.lower() if r.framework != "unknown" else "other"
        by_framework[fw].append(r.score)

    framework_stats: dict[str, dict[str, int]] = {}
    for fw, fw_scores in sorted(by_framework.items()):
        fw_sorted = sorted(fw_scores)
        framework_stats[fw] = {
            "count": len(fw_sorted),
            "median": _median(fw_sorted),
            "p25": _percentile(fw_sorted, 25),
            "p75": _percentile(fw_sorted, 75),
        }

    # Severity medians
    critical_counts: list[int] = []
    high_counts: list[int] = []
    medium_counts: list[int] = []
    low_counts: list[int] = []

    for r in results:
        critical_counts.append(r.findings_by_severity.get("CRITICAL", 0))
        high_counts.append(r.findings_by_severity.get("HIGH", 0))
        medium_counts.append(r.findings_by_severity.get("MEDIUM", 0))
        low_counts.append(r.findings_by_severity.get("LOW", 0))

    # Grade distribution
    grade_dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for r in results:
        g = _grade_from_score(r.score)
        grade_dist[g] = grade_dist.get(g, 0) + 1

    return {
        "version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "projects_scanned": len(results),
        "distribution": {
            "scores": scores,
            "by_framework": framework_stats,
            "by_severity": {
                "critical_findings_median": _median(critical_counts),
                "high_findings_median": _median(high_counts),
                "medium_findings_median": _median(medium_counts),
                "low_findings_median": _median(low_counts),
            },
            "grade_distribution": grade_dist,
        },
    }


def save_dataset(
    dataset: dict[str, object],
    output_dir: Path,
    sdk_data_dir: Path | None = None,
) -> list[Path]:
    """Save dataset to output directory and optionally to SDK data dir.

    Args:
        dataset: The benchmark dataset dict.
        output_dir: Primary output directory.
        sdk_data_dir: If provided, also write to this SDK path.

    Returns:
        List of paths where the dataset was written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []

    primary = output_dir / "benchmark_dataset.json"
    primary.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    paths.append(primary)

    if sdk_data_dir is not None:
        sdk_data_dir.mkdir(parents=True, exist_ok=True)
        sdk_path = sdk_data_dir / "benchmark_dataset.json"
        sdk_path.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
        paths.append(sdk_path)

    return paths
