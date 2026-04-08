"""Build a `ComplianceContext` from scan output, BOM, runtime config, answers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from drako import __version__ as DRAKO_VERSION
from drako.cli.scan_cache import load_scan_cache
from drako.comply.storage import load as load_answers


@dataclass
class ComplianceContext:
    # Identity
    system_name: str = ""
    system_version: str = ""
    provider_entity: str = ""
    deployment_environment: str = ""
    deployment_regions: list[str] = field(default_factory=list)

    # Purpose
    system_purpose: str = ""
    intended_users: str = ""
    domain: str = ""
    high_risk_rationale: str = ""
    deployment_timeline: str = ""

    # Data
    training_data_sources: list[str] = field(default_factory=list)
    data_provenance: str = ""
    data_retention_policy: str = ""
    pii_categories: list[str] = field(default_factory=list)
    data_subject_rights: str = ""

    # Oversight
    oversight_responsible_name: str = ""
    oversight_responsible_role: str = ""
    escalation_path: str = ""
    incident_response_procedure: str = ""
    update_cadence: str = ""

    # Limitations
    known_limitations: list[str] = field(default_factory=list)
    known_failure_modes: list[str] = field(default_factory=list)
    residual_risks: list[str] = field(default_factory=list)
    out_of_scope_use_cases: list[str] = field(default_factory=list)
    user_notification_mechanism: str = ""

    # Compliance context
    other_regulations: list[str] = field(default_factory=list)
    existing_certifications: list[str] = field(default_factory=list)
    third_party_audits: str = ""
    legal_counsel_involvement: str = ""
    signature_authority: str = ""

    # From BOM / scan
    agents: list[dict] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    models: list[dict] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    risk_findings: list[dict] = field(default_factory=list)
    governance_score: int = 0
    determinism_score: int = 100

    # Runtime config
    audit_trail_enabled: bool = False
    hitl_configured: bool = False
    hitl_triggers: list[str] = field(default_factory=list)

    # Meta
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    drako_version: str = DRAKO_VERSION
    scan_timestamp: str = ""


def _str(answers: dict[str, Any], key: str) -> str:
    value = answers.get(key, "")
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value or "")


def _list(answers: dict[str, Any], key: str) -> list[str]:
    value = answers.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [piece.strip() for piece in value.split(",") if piece.strip()]
    return [str(value)]


def _read_runtime_config(directory: Path) -> tuple[bool, bool, list[str]]:
    """Best-effort: read .drako.yaml audit + HITL info without hard-coupling."""
    try:
        from drako.config import load_drako_config

        config = load_drako_config(directory / ".drako.yaml")
    except Exception:
        return False, False, []

    audit = bool(getattr(config, "audit_trail_enabled", False) or getattr(config, "audit", None))
    hitl_obj = getattr(config, "hitl", None) or getattr(config, "human_in_the_loop", None)
    if hitl_obj is None:
        return audit, False, []
    triggers: list[str] = []
    raw_triggers = getattr(hitl_obj, "triggers", None)
    if isinstance(raw_triggers, list):
        triggers = [str(t) for t in raw_triggers]
    return audit, True, triggers


def build_context(directory: str | Path = ".") -> ComplianceContext:
    """Compose the compliance context from every available source."""
    directory = Path(directory)
    answers = load_answers(directory)
    scan = load_scan_cache(str(directory), max_age_seconds=10 ** 9) or {}
    audit, hitl, triggers = _read_runtime_config(directory)

    return ComplianceContext(
        # Identity
        system_name=_str(answers, "system_name") or scan.get("project_name", ""),
        system_version=_str(answers, "system_version"),
        provider_entity=_str(answers, "provider_entity"),
        deployment_environment=_str(answers, "deployment_environment"),
        deployment_regions=_list(answers, "deployment_regions"),
        # Purpose
        system_purpose=_str(answers, "system_purpose"),
        intended_users=_str(answers, "intended_users"),
        domain=_str(answers, "domain"),
        high_risk_rationale=_str(answers, "high_risk_rationale"),
        deployment_timeline=_str(answers, "deployment_timeline"),
        # Data
        training_data_sources=_list(answers, "training_data_sources"),
        data_provenance=_str(answers, "data_provenance"),
        data_retention_policy=_str(answers, "data_retention_policy"),
        pii_categories=_list(answers, "pii_categories"),
        data_subject_rights=_str(answers, "data_subject_rights"),
        # Oversight
        oversight_responsible_name=_str(answers, "oversight_responsible_name"),
        oversight_responsible_role=_str(answers, "oversight_responsible_role"),
        escalation_path=_str(answers, "escalation_path"),
        incident_response_procedure=_str(answers, "incident_response_procedure"),
        update_cadence=_str(answers, "update_cadence"),
        # Limitations
        known_limitations=_list(answers, "known_limitations"),
        known_failure_modes=_list(answers, "known_failure_modes"),
        residual_risks=_list(answers, "residual_risks"),
        out_of_scope_use_cases=_list(answers, "out_of_scope_use_cases"),
        user_notification_mechanism=_str(answers, "user_notification_mechanism"),
        # Compliance context
        other_regulations=_list(answers, "other_regulations"),
        existing_certifications=_list(answers, "existing_certifications"),
        third_party_audits=_str(answers, "third_party_audits"),
        legal_counsel_involvement=_str(answers, "legal_counsel_involvement"),
        signature_authority=_str(answers, "signature_authority"),
        # BOM / scan
        agents=list(scan.get("agents") or []),
        tools=list(scan.get("tools") or []),
        models=list(scan.get("models") or []),
        frameworks=[scan["framework"]] if scan.get("framework") else [],
        risk_findings=[],  # last_scan.json keeps only summary; full findings not persisted yet
        governance_score=int(scan.get("score", 0)),
        determinism_score=int(scan.get("determinism_score", 100)),
        # Runtime
        audit_trail_enabled=audit,
        hitl_configured=hitl,
        hitl_triggers=triggers,
        # Meta
        scan_timestamp=str(scan.get("scanned_at", "")),
    )
