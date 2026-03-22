"""Tests for SVG scorecard and badge generation (Feature 6).

Covers:
- generate_scorecard_svg() for all grades
- SVG dimensions and content fields
- save_scorecard() file creation
- share text URL integration
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from drako.cli.formats.scorecard import (
    _CARD_HEIGHT,
    _CARD_WIDTH,
    _GRADE_COLORS,
    generate_scorecard_svg,
)
from drako.cli.share import generate_share_texts, save_scorecard


# ---------------------------------------------------------------------------
# generate_scorecard_svg
# ---------------------------------------------------------------------------

class TestGenerateScorecardSvg:

    def test_returns_valid_svg(self) -> None:
        svg = generate_scorecard_svg(
            score=85, grade="B", agents=3, tools=5, models=2,
            framework="crewai 0.70", findings_critical=0, findings_high=1,
        )
        assert svg.startswith("<svg")
        assert svg.strip().endswith("</svg>")

    def test_viewbox_dimensions(self) -> None:
        svg = generate_scorecard_svg(
            score=50, grade="C", agents=1, tools=2, models=1,
            framework="langgraph", findings_critical=1, findings_high=3,
        )
        assert f'viewBox="0 0 {_CARD_WIDTH} {_CARD_HEIGHT}"' in svg
        assert f'width="{_CARD_WIDTH}"' in svg
        assert f'height="{_CARD_HEIGHT}"' in svg

    @pytest.mark.parametrize("grade,expected_color", [
        ("A", "#22c55e"),
        ("B", "#84cc16"),
        ("C", "#eab308"),
        ("D", "#f97316"),
        ("F", "#ef4444"),
    ])
    def test_grade_colors(self, grade: str, expected_color: str) -> None:
        svg = generate_scorecard_svg(
            score=50, grade=grade, agents=1, tools=1, models=1,
            framework="test", findings_critical=0, findings_high=0,
        )
        assert expected_color in svg

    def test_all_fields_present(self) -> None:
        svg = generate_scorecard_svg(
            score=72, grade="C", agents=4, tools=8, models=3,
            framework="autogen 0.4", findings_critical=2, findings_high=5,
        )
        assert "72" in svg
        assert "[C]" in svg
        assert "4 agents" in svg
        assert "8 tools" in svg
        assert "3 models" in svg
        assert "autogen 0.4" in svg
        assert "2 critical findings" in svg
        assert "5 high findings" in svg
        assert "Drako Governance Report" in svg
        assert "pip install drako" in svg

    def test_zero_findings_shows_checkmarks(self) -> None:
        svg = generate_scorecard_svg(
            score=95, grade="A", agents=2, tools=3, models=1,
            framework="crewai", findings_critical=0, findings_high=0,
        )
        # Check icon (✓) for zero findings, green colors
        assert "#22c55e" in svg  # green color for 0 findings

    def test_nonzero_findings_shows_x_marks(self) -> None:
        svg = generate_scorecard_svg(
            score=30, grade="F", agents=1, tools=1, models=1,
            framework="test", findings_critical=3, findings_high=7,
        )
        # Red color for critical, orange for high
        assert "#ef4444" in svg
        assert "#f97316" in svg

    def test_score_100(self) -> None:
        svg = generate_scorecard_svg(
            score=100, grade="A", agents=1, tools=1, models=1,
            framework="test", findings_critical=0, findings_high=0,
        )
        assert "100" in svg
        assert "[A]" in svg

    def test_score_0(self) -> None:
        svg = generate_scorecard_svg(
            score=0, grade="F", agents=0, tools=0, models=0,
            framework="Unknown", findings_critical=10, findings_high=20,
        )
        assert "[F]" in svg
        assert "0 agents" in svg

    def test_unknown_grade_fallback(self) -> None:
        svg = generate_scorecard_svg(
            score=50, grade="X", agents=1, tools=1, models=1,
            framework="test", findings_critical=0, findings_high=0,
        )
        assert "#9f9f9f" in svg  # fallback color


# ---------------------------------------------------------------------------
# save_scorecard
# ---------------------------------------------------------------------------

class TestSaveScorecard:

    @staticmethod
    def _make_stub_result(
        score: int = 85,
        grade: str = "B",
    ) -> object:
        """Create a minimal ScanResult-like stub for testing."""
        from dataclasses import dataclass, field

        @dataclass
        class FW:
            name: str = "crewai"
            version: str = "0.70"
            confidence: float = 1.0

        @dataclass
        class BOM:
            agents: list = field(default_factory=lambda: ["a1", "a2"])
            tools: list = field(default_factory=lambda: ["t1"])
            models: list = field(default_factory=lambda: ["m1"])
            frameworks: list = field(default_factory=lambda: [FW()])
            mcp_servers: list = field(default_factory=list)
            prompts: list = field(default_factory=list)
            permissions: list = field(default_factory=list)

        @dataclass
        class Finding:
            severity: str = "HIGH"

        @dataclass
        class Result:
            score: int = 0
            grade: str = ""
            bom: BOM = field(default_factory=BOM)
            findings: list = field(default_factory=lambda: [Finding(), Finding()])

        return Result(score=score, grade=grade)

    def test_creates_scorecard_and_badge(self) -> None:
        result = self._make_stub_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            scorecard_path, badge_path = save_scorecard(result, tmpdir)  # type: ignore[arg-type]

            assert scorecard_path.exists()
            assert badge_path.exists()
            assert scorecard_path.name == "scorecard.svg"
            assert badge_path.name == "badge.svg"
            assert scorecard_path.parent.name == ".drako"

    def test_scorecard_is_valid_svg(self) -> None:
        result = self._make_stub_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            scorecard_path, _ = save_scorecard(result, tmpdir)  # type: ignore[arg-type]
            content = scorecard_path.read_text(encoding="utf-8")
            assert content.startswith("<svg")
            assert f'width="{_CARD_WIDTH}"' in content

    def test_badge_is_valid_svg(self) -> None:
        result = self._make_stub_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            _, badge_path = save_scorecard(result, tmpdir)  # type: ignore[arg-type]
            content = badge_path.read_text(encoding="utf-8")
            assert content.startswith("<svg")
            assert "Drako" in content

    def test_creates_drako_dir_if_missing(self) -> None:
        result = self._make_stub_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            drako_dir = Path(tmpdir) / ".drako"
            assert not drako_dir.exists()
            save_scorecard(result, tmpdir)  # type: ignore[arg-type]
            assert drako_dir.exists()


# ---------------------------------------------------------------------------
# Share text URL integration
# ---------------------------------------------------------------------------

class TestShareTextUrls:

    def test_share_texts_without_url(self) -> None:
        texts = generate_share_texts(
            score=80, grade="B", agents=2, tools=3,
            framework="crewai", findings_critical=0,
            findings_high=1, findings_total=5,
        )
        assert "https://" not in texts.twitter
        assert "https://" not in texts.reddit
        assert "https://" not in texts.linkedin

    def test_share_texts_with_url(self) -> None:
        url = "https://app.getdrako.com/scans/abc123"
        texts = generate_share_texts(
            score=80, grade="B", agents=2, tools=3,
            framework="crewai", findings_critical=0,
            findings_high=1, findings_total=5,
            scan_url=url,
        )
        assert url in texts.twitter
        assert url in texts.reddit
        assert url in texts.linkedin

    def test_share_texts_url_none_is_no_op(self) -> None:
        texts = generate_share_texts(
            score=50, grade="D", agents=1, tools=1,
            framework="test", findings_critical=2,
            findings_high=3, findings_total=10,
            scan_url=None,
        )
        # Should still be valid share texts without URLs
        assert "pip install drako" in texts.twitter or "drako" in texts.twitter.lower()
