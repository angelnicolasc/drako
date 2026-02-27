"""Tests for the Rich terminal report."""
import pytest
from pathlib import Path

from agentmesh.cli.discovery import collect_project_files, detect_frameworks
from agentmesh.cli.bom import generate_bom
from agentmesh.cli.policies import evaluate_all_policies
from agentmesh.cli.scoring import calculate_score, score_to_grade
from agentmesh.cli.report import render_report_to_string

FIXTURES = Path(__file__).parent / "fixtures"


class TestRenderReport:
    def test_report_contains_sections(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)
        findings = evaluate_all_policies(bom, metadata)
        score = calculate_score(findings)
        grade = score_to_grade(score)

        output = render_report_to_string(
            bom=bom,
            findings=findings,
            score=score,
            grade=grade,
            metadata=metadata,
            scan_duration_ms=1234,
        )

        # Report should contain key sections
        assert "AgentMesh Scan Report" in output
        assert "AGENT BOM" in output
        assert "GOVERNANCE SCORE" in output
        assert str(score) in output
        assert grade in output
        assert "CRITICAL" in output

    def test_report_clean_project(self):
        metadata = collect_project_files(FIXTURES / "langgraph_clean")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)
        findings = evaluate_all_policies(bom, metadata)
        score = calculate_score(findings)
        grade = score_to_grade(score)

        output = render_report_to_string(
            bom=bom,
            findings=findings,
            score=score,
            grade=grade,
            metadata=metadata,
            scan_duration_ms=500,
        )

        assert "AgentMesh Scan Report" in output
        assert str(score) in output

    def test_report_no_crash_empty(self):
        """Report should not crash with minimal data."""
        from agentmesh.cli.bom import AgentBOM
        from agentmesh.cli.discovery import ProjectMetadata

        output = render_report_to_string(
            bom=AgentBOM(),
            findings=[],
            score=100,
            grade="A",
            metadata=ProjectMetadata(root=Path("/empty")),
            scan_duration_ms=100,
        )
        assert "100" in output
        assert "A" in output
