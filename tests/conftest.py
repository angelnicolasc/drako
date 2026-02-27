"""Shared fixtures for the AgentMesh SDK test suite."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest
import yaml


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure no leaked env vars between tests."""
    monkeypatch.delenv("AGENTMESH_API_KEY", raising=False)
    monkeypatch.delenv("AGENTMESH_ENDPOINT", raising=False)
    monkeypatch.delenv("AGENTMESH_TENANT_ID", raising=False)


@pytest.fixture()
def api_key() -> str:
    return "am_live_testtenant_secretkey123"


@pytest.fixture()
def tenant_id() -> str:
    return "testtenant"


@pytest.fixture()
def endpoint() -> str:
    return "https://api.agentmesh.test"


@pytest.fixture()
def config_file(tmp_path, api_key, tenant_id, endpoint, monkeypatch):
    """Write a temporary .agentmesh.yaml and set the API key env."""
    config_data = {
        "version": "1.0",
        "tenant_id": tenant_id,
        "api_key_env": "AGENTMESH_API_KEY",
        "endpoint": endpoint,
        "framework": "crewai",
        "tools": {
            "audit_log_action": True,
            "verify_agent_identity": True,
            "evaluate_policy": True,
        },
        "guardrails": {"prompt_injection_detection": True, "dlp_scanning": False},
        "trust": {"enabled": True, "decay_half_life_hours": 168, "circuit_breaker_threshold": 3},
        "bft": {"enabled": False, "quorum_size": 4},
    }
    path = tmp_path / ".agentmesh.yaml"
    with open(path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
    monkeypatch.setenv("AGENTMESH_API_KEY", api_key)
    return str(path)
