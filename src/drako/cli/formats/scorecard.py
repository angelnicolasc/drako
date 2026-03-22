"""SVG scorecard generation for `drako scan --share`.

Produces a 1200x630 SVG score card optimized for Twitter/LinkedIn OG images.
Saved locally to `.drako/scorecard.svg` — no network calls, no external deps.

Design mirrors the backend share card (app/api/v1/share.py) so the local
preview matches what social platforms render from the hosted OG image.
"""
from __future__ import annotations

_CARD_WIDTH: int = 1200
_CARD_HEIGHT: int = 630

_GRADE_COLORS: dict[str, str] = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}

_GRADE_BG: dict[str, str] = {
    "A": "#052e16",
    "B": "#1a2e05",
    "C": "#2e2b05",
    "D": "#2e1a05",
    "F": "#2e0505",
}

_SVG_TEMPLATE: str = """\
<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" \
viewBox="0 0 {width} {height}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="{bg_color}"/>
      <stop offset="100%" stop-color="#0d1117"/>
    </linearGradient>
    <linearGradient id="bar" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="{color}" stop-opacity="0.8"/>
      <stop offset="100%" stop-color="{color}"/>
    </linearGradient>
  </defs>

  <!-- Background -->
  <rect width="{width}" height="{height}" rx="16" fill="url(#bg)"/>
  <rect x="40" y="40" width="{inner_w}" height="{inner_h}" rx="12" \
fill="none" stroke="#30363d" stroke-width="1"/>

  <!-- Title -->
  <text x="80" y="100" font-family="system-ui, -apple-system, sans-serif" \
font-size="28" font-weight="700" fill="#f0f6fc">Drako Governance Report</text>

  <!-- Score -->
  <text x="80" y="200" font-family="system-ui, -apple-system, sans-serif" \
font-size="96" font-weight="800" fill="{color}">{score}</text>
  <text x="{score_suffix_x}" y="190" \
font-family="system-ui, -apple-system, sans-serif" \
font-size="36" fill="#8b949e">/100</text>
  <text x="{grade_x}" y="190" \
font-family="system-ui, -apple-system, sans-serif" \
font-size="48" font-weight="700" fill="{color}">[{grade}]</text>

  <!-- Score bar -->
  <rect x="80" y="240" width="600" height="16" rx="8" fill="#21262d"/>
  <rect x="80" y="240" width="{bar_width}" height="16" rx="8" fill="url(#bar)"/>

  <!-- Stats -->
  <text x="80" y="320" font-family="system-ui, -apple-system, sans-serif" \
font-size="22" fill="#8b949e">\
{agents} agents  |  {tools} tools  |  {models} models  |  {framework}</text>

  <!-- Findings -->
  <text x="80" y="380" font-family="system-ui, -apple-system, sans-serif" \
font-size="22" fill="{critical_color}">\
{critical_icon} {findings_critical} critical findings</text>
  <text x="80" y="420" font-family="system-ui, -apple-system, sans-serif" \
font-size="22" fill="{high_color}">\
{high_icon} {findings_high} high findings</text>

  <!-- CTA -->
  <rect x="80" y="480" width="340" height="48" rx="8" \
fill="{color}" opacity="0.15"/>
  <text x="100" y="512" font-family="monospace" font-size="18" \
fill="{color}">pip install drako</text>

  <!-- Branding -->
  <text x="80" y="570" font-family="system-ui, -apple-system, sans-serif" \
font-size="16" fill="#484f58">\
Scanned with Drako \u2014 getdrako.com</text>
</svg>"""


def generate_scorecard_svg(
    score: int,
    grade: str,
    agents: int,
    tools: int,
    models: int,
    framework: str,
    findings_critical: int,
    findings_high: int,
) -> str:
    """Generate a 1200x630 SVG score card for social sharing.

    Pure function — no I/O, no external dependencies. The SVG is designed
    to render correctly as a Twitter/LinkedIn OG image.

    Args:
        score: Governance score 0-100.
        grade: Letter grade A-F.
        agents: Number of agents detected.
        tools: Number of tools detected.
        models: Number of models detected.
        framework: Primary framework name (e.g. "crewai 0.70").
        findings_critical: Count of CRITICAL findings.
        findings_high: Count of HIGH findings.

    Returns:
        SVG markup as a string.
    """
    color = _GRADE_COLORS.get(grade, "#9f9f9f")
    bg_color = _GRADE_BG.get(grade, "#0d1117")
    bar_width = int(score / 100 * 600)

    critical_color = "#ef4444" if findings_critical > 0 else "#22c55e"
    high_color = "#f97316" if findings_high > 0 else "#22c55e"
    critical_icon = "\u2717" if findings_critical > 0 else "\u2713"
    high_icon = "\u2717" if findings_high > 0 else "\u2713"

    # Dynamic X positions based on score digit count
    score_digits = len(str(score))
    score_suffix_x = 80 + score_digits * 55
    grade_x = score_suffix_x + 120

    return _SVG_TEMPLATE.format(
        width=_CARD_WIDTH,
        height=_CARD_HEIGHT,
        inner_w=_CARD_WIDTH - 80,
        inner_h=_CARD_HEIGHT - 80,
        bg_color=bg_color,
        color=color,
        score=score,
        score_suffix_x=score_suffix_x,
        grade_x=grade_x,
        grade=grade,
        bar_width=bar_width,
        agents=agents,
        tools=tools,
        models=models,
        framework=framework,
        critical_color=critical_color,
        high_color=high_color,
        critical_icon=critical_icon,
        high_icon=high_icon,
        findings_critical=findings_critical,
        findings_high=findings_high,
    )
