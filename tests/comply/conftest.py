"""Shared comply fixtures."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from drako.comply.mapping import ComplianceContext


@pytest.fixture
def sample_ctx() -> ComplianceContext:
    return ComplianceContext(
        system_name="Onboarding Bot",
        system_version="1.4.2",
        provider_entity="ACME Corp",
        deployment_environment="production",
        deployment_regions=["EU-West", "EU-Central"],
        system_purpose="Automate KYC document review for new customers.",
        intended_users="Compliance officers",
        domain="finance",
        high_risk_rationale="Processes financial data of natural persons.",
        deployment_timeline="Q3 2026",
        training_data_sources=["public filings", "internal labelled set"],
        data_provenance="Curated by ACME compliance team.",
        data_retention_policy="Retain logs for 24 months.",
        pii_categories=["name", "address"],
        data_subject_rights="Email privacy@acme.example",
        oversight_responsible_name="Jane Smith",
        oversight_responsible_role="Head of Compliance",
        escalation_path="security@acme.example",
        incident_response_procedure="Pager rotation, 30-min SLA.",
        update_cadence="Quarterly",
        known_limitations=["English-only documents"],
        known_failure_modes=["OCR errors on low-res scans"],
        residual_risks=["False negatives on tampered IDs"],
        out_of_scope_use_cases=["Children under 18"],
        user_notification_mechanism="Banner in account dashboard",
        other_regulations=["GDPR"],
        existing_certifications=["SOC2 Type II"],
        third_party_audits="2026 SOC2 audit by Ernst Doe",
        legal_counsel_involvement="Reviewed by ACME GC",
        signature_authority="CFO",
        agents=[{"name": "Reviewer", "framework": "crewai", "file_path": "agents/reviewer.py"}],
        tools=[{"name": "ocr", "has_filesystem_access": True, "has_network_access": False, "has_code_execution": False}],
        models=[{"name": "gpt-4o", "file_path": "agents/reviewer.py"}],
        frameworks=["crewai"],
        risk_findings=[{"policy_id": "SEC-001", "severity": "CRITICAL", "message": "Hardcoded credential"}],
        governance_score=72,
        determinism_score=88,
        audit_trail_enabled=True,
        hitl_configured=True,
        hitl_triggers=["review_outcome"],
        generated_at=datetime(2026, 4, 8, 10, 22, tzinfo=timezone.utc),
    )
