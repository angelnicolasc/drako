# mypy: strict
"""Report generator for MCP governance directory.

Produces:
- output/directory.json — structured data for API ingestion
- output/directory.html — standalone HTML directory page
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from governance_analyzer import ServerAnalysis


def generate_json_report(
    analyses: list[ServerAnalysis],
    output_dir: Path,
) -> Path:
    """Generate JSON directory report.

    Returns path to the generated file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "directory.json"

    data = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "servers_analyzed": len(analyses),
        "servers": [
            {
                "name": a.server_name,
                "category": a.category,
                "description": a.description,
                "score": a.score,
                "grade": a.grade,
                "characteristics": [
                    {
                        "name": c.name,
                        "present": c.present,
                        "evidence": c.evidence,
                        "weight": c.weight,
                        "score": c.score,
                    }
                    for c in a.characteristics
                ],
            }
            for a in sorted(analyses, key=lambda x: x.score, reverse=True)
        ],
        "summary": {
            "average_score": round(sum(a.score for a in analyses) / len(analyses)) if analyses else 0,
            "grade_distribution": _grade_distribution(analyses),
            "by_category": _by_category(analyses),
        },
    }

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _grade_distribution(analyses: list[ServerAnalysis]) -> dict[str, int]:
    dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for a in analyses:
        if a.grade in dist:
            dist[a.grade] += 1
    return dist


def _by_category(analyses: list[ServerAnalysis]) -> dict[str, dict[str, float | int]]:
    from collections import defaultdict
    cats: dict[str, list[int]] = defaultdict(list)
    for a in analyses:
        cats[a.category].append(a.score)
    result: dict[str, dict[str, float | int]] = {}
    for cat, scores in sorted(cats.items()):
        result[cat] = {
            "count": len(scores),
            "average_score": round(sum(scores) / len(scores), 1),
        }
    return result


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_GRADE_COLORS: dict[str, str] = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}


def generate_html_report(
    analyses: list[ServerAnalysis],
    output_dir: Path,
) -> Path:
    """Generate standalone HTML directory page.

    Returns path to the generated file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "directory.html"

    sorted_analyses = sorted(analyses, key=lambda x: x.score, reverse=True)

    rows = ""
    for a in sorted_analyses:
        color = _GRADE_COLORS.get(a.grade, "#9f9f9f")
        chars_html = ""
        for c in a.characteristics:
            icon = "\u2713" if c.present else "\u2717"
            icon_color = "#22c55e" if c.present else "#ef4444"
            chars_html += (
                f'<span title="{c.name}: {c.evidence}" '
                f'style="color:{icon_color};margin-right:8px;cursor:help">'
                f'{icon}</span>'
            )
        rows += f"""
        <tr>
          <td><strong>{a.server_name}</strong><br><small style="color:#8b949e">{a.description}</small></td>
          <td><span style="color:#8b949e">{a.category}</span></td>
          <td style="text-align:center"><strong>{a.score}</strong></td>
          <td style="text-align:center"><span style="color:{color};font-weight:700;font-size:1.2em">{a.grade}</span></td>
          <td>{chars_html}</td>
        </tr>"""

    avg_score = round(sum(a.score for a in analyses) / len(analyses)) if analyses else 0
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Drako MCP Governance Directory</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0d1117; color: #f0f6fc; font-family: system-ui, -apple-system, sans-serif; padding: 40px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 2em; margin-bottom: 8px; }}
  .subtitle {{ color: #8b949e; margin-bottom: 32px; }}
  .stats {{ display: flex; gap: 32px; margin-bottom: 32px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; }}
  .stat-value {{ font-size: 2em; font-weight: 700; }}
  .stat-label {{ color: #8b949e; font-size: 0.9em; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; color: #8b949e; text-align: left; padding: 12px 16px; font-weight: 600; font-size: 0.85em; text-transform: uppercase; }}
  td {{ padding: 12px 16px; border-top: 1px solid #21262d; }}
  tr:hover td {{ background: #1c2128; }}
  .legend {{ margin-top: 32px; color: #8b949e; font-size: 0.85em; }}
  .legend span {{ margin-right: 16px; }}
  .methodology {{ margin-top: 48px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; }}
  .methodology h2 {{ font-size: 1.3em; margin-bottom: 12px; }}
  .methodology p {{ color: #8b949e; line-height: 1.6; margin-bottom: 8px; }}
  footer {{ margin-top: 48px; color: #484f58; font-size: 0.85em; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>Drako MCP Governance Directory</h1>
  <p class="subtitle">Governance analysis of {len(analyses)} popular MCP servers</p>

  <div class="stats">
    <div class="stat">
      <div class="stat-value">{len(analyses)}</div>
      <div class="stat-label">Servers Analyzed</div>
    </div>
    <div class="stat">
      <div class="stat-value">{avg_score}</div>
      <div class="stat-label">Average Score</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Server</th>
        <th>Category</th>
        <th style="text-align:center">Score</th>
        <th style="text-align:center">Grade</th>
        <th>Characteristics</th>
      </tr>
    </thead>
    <tbody>{rows}
    </tbody>
  </table>

  <div class="legend">
    <strong>Characteristics:</strong>
    <span>\u2713 Permissions</span>
    <span>\u2713 Audit Logging</span>
    <span>\u2713 Credential Handling</span>
    <span>\u2713 Rate Limiting</span>
    <span>\u2713 Input Validation</span>
    <span>\u2713 Error Boundaries</span>
  </div>

  <div class="methodology">
    <h2>Methodology</h2>
    <p>Each MCP server is evaluated across 6 governance dimensions by inspecting
    its manifest (package.json) and primary source file. Characteristics are
    weighted: Tool Permissions (20%), Credential Handling (20%), Audit Logging (15%),
    Rate Limiting (15%), Input Validation (15%), Error Boundaries (15%).</p>
    <p>Detection uses pattern matching on source code — a practical tradeoff for
    analyzing TypeScript codebases from Python. Results are deterministic and
    reproducible given the same source content.</p>
    <p>Grades follow the Drako convention: A (90-100), B (75-89), C (60-74), D (40-59), F (0-39).</p>
  </div>

  <footer>
    Generated by Drako MCP Directory Scanner &mdash; {timestamp}<br>
    <a href="https://getdrako.com" style="color:#484f58">getdrako.com</a>
  </footer>
</div>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path
