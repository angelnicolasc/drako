# mypy: strict
"""Report generator for the Public Agent Governance Index.

Produces:
- output/index.json — anonymized per-repo results
- output/index.html — public-facing HTML page with aggregate stats
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scan_runner import RepoScanResult

_GRADE_COLORS: dict[str, str] = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}


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


def generate_json_report(
    results: list[RepoScanResult],
    output_dir: Path,
) -> Path:
    """Generate anonymized JSON index report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "index.json"

    scores = [r.score for r in results]
    avg_score = round(sum(scores) / len(scores)) if scores else 0

    # Anonymized: no repo names, only framework + score
    entries = [
        {
            "framework": r.framework,
            "score": r.score,
            "grade": r.grade,
            "agents": r.agents,
            "tools": r.tools,
            "findings_by_severity": r.findings_by_severity,
        }
        for r in sorted(results, key=lambda x: x.score, reverse=True)
    ]

    data = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "projects_scanned": len(results),
        "average_score": avg_score,
        "entries": entries,
    }

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def generate_html_report(
    results: list[RepoScanResult],
    output_dir: Path,
) -> Path:
    """Generate public-facing HTML index page."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "index.html"

    scores = [r.score for r in results]
    avg_score = round(sum(scores) / len(scores)) if scores else 0
    median_score = sorted(scores)[len(scores) // 2] if scores else 0

    # Grade distribution
    grade_dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for r in results:
        g = _grade_from_score(r.score)
        grade_dist[g] += 1

    grade_bars = ""
    for g in ["A", "B", "C", "D", "F"]:
        count = grade_dist[g]
        pct = round(count / len(results) * 100) if results else 0
        color = _GRADE_COLORS[g]
        grade_bars += (
            f'<div style="display:flex;align-items:center;margin-bottom:8px">'
            f'<span style="width:30px;color:{color};font-weight:700">{g}</span>'
            f'<div style="flex:1;background:#21262d;height:24px;border-radius:4px;overflow:hidden">'
            f'<div style="width:{pct}%;background:{color};height:100%;border-radius:4px"></div>'
            f'</div>'
            f'<span style="width:60px;text-align:right;color:#8b949e">{count} ({pct}%)</span>'
            f'</div>'
        )

    # Score histogram (10 buckets)
    buckets: list[int] = [0] * 10
    for s in scores:
        bucket_idx = min(s // 10, 9)
        buckets[bucket_idx] += 1

    max_bucket = max(buckets) if buckets else 1
    histogram_bars = ""
    for i, count in enumerate(buckets):
        height = round(count / max_bucket * 120) if max_bucket > 0 else 0
        label = f"{i * 10}-{i * 10 + 9}"
        histogram_bars += (
            f'<div style="display:flex;flex-direction:column;align-items:center;flex:1">'
            f'<div style="width:80%;background:#30363d;height:120px;display:flex;align-items:flex-end;border-radius:4px 4px 0 0">'
            f'<div style="width:100%;height:{height}px;background:#58a6ff;border-radius:4px 4px 0 0"></div>'
            f'</div>'
            f'<div style="font-size:0.7em;color:#8b949e;margin-top:4px">{label}</div>'
            f'</div>'
        )

    # Framework comparison
    fw_data: dict[str, list[int]] = defaultdict(list)
    for r in results:
        fw = r.framework if r.framework != "unknown" else "other"
        fw_data[fw].append(r.score)

    fw_rows = ""
    for fw, fw_scores in sorted(fw_data.items(), key=lambda x: -len(x[1])):
        fw_avg = round(sum(fw_scores) / len(fw_scores))
        fw_color = _GRADE_COLORS.get(_grade_from_score(fw_avg), "#9f9f9f")
        fw_rows += (
            f'<tr>'
            f'<td>{fw}</td>'
            f'<td style="text-align:center">{len(fw_scores)}</td>'
            f'<td style="text-align:center;color:{fw_color};font-weight:700">{fw_avg}</td>'
            f'<td style="text-align:center">{min(fw_scores)}</td>'
            f'<td style="text-align:center">{max(fw_scores)}</td>'
            f'</tr>'
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Public Agent Governance Index — Drako</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0d1117; color: #f0f6fc; font-family: system-ui, -apple-system, sans-serif; padding: 40px; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{ font-size: 2em; margin-bottom: 8px; }}
  h2 {{ font-size: 1.4em; margin: 32px 0 16px; }}
  .subtitle {{ color: #8b949e; margin-bottom: 32px; }}
  .stats {{ display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; min-width: 140px; }}
  .stat-value {{ font-size: 2em; font-weight: 700; }}
  .stat-label {{ color: #8b949e; font-size: 0.9em; }}
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 8px 12px; color: #8b949e; font-weight: 600; font-size: 0.85em; text-transform: uppercase; border-bottom: 1px solid #30363d; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; }}
  .methodology {{ margin-top: 32px; }}
  .methodology p {{ color: #8b949e; line-height: 1.6; margin-bottom: 8px; }}
  footer {{ margin-top: 48px; color: #484f58; font-size: 0.85em; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>Public Agent Governance Index</h1>
  <p class="subtitle">Governance analysis of {len(results)} open-source AI agent projects</p>

  <div class="stats">
    <div class="stat">
      <div class="stat-value">{len(results)}</div>
      <div class="stat-label">Projects Scanned</div>
    </div>
    <div class="stat">
      <div class="stat-value">{avg_score}</div>
      <div class="stat-label">Average Score</div>
    </div>
    <div class="stat">
      <div class="stat-value">{median_score}</div>
      <div class="stat-label">Median Score</div>
    </div>
  </div>

  <h2>Grade Distribution</h2>
  <div class="section">
    {grade_bars}
  </div>

  <h2>Score Distribution</h2>
  <div class="section">
    <div style="display:flex;gap:4px;align-items:flex-end">
      {histogram_bars}
    </div>
  </div>

  <h2>Framework Comparison</h2>
  <div class="section">
    <table>
      <thead>
        <tr><th>Framework</th><th style="text-align:center">Projects</th><th style="text-align:center">Avg Score</th><th style="text-align:center">Min</th><th style="text-align:center">Max</th></tr>
      </thead>
      <tbody>{fw_rows}</tbody>
    </table>
  </div>

  <div class="methodology section">
    <h2>Methodology</h2>
    <p>The Public Agent Governance Index scans the top {len(results)} open-source AI agent
    projects on GitHub (by star count) using the Drako governance scanner. Each project
    is analyzed for 73+ security and compliance rules covering credential management,
    tool permissions, audit logging, human-in-the-loop gates, and framework-specific best practices.</p>
    <p>Results are anonymized — no repository names are disclosed. The aggregate data powers
    the <code>drako scan --benchmark</code> percentile comparison feature.</p>
    <p>Scores follow Drako convention: A (90-100), B (75-89), C (60-74), D (40-59), F (0-39).
    Deductions are severity-weighted with caps to prevent single-category dominance.</p>
  </div>

  <footer>
    Generated by Drako Governance Index &mdash; {timestamp}<br>
    <a href="https://getdrako.com" style="color:#484f58">getdrako.com</a>
  </footer>
</div>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path
