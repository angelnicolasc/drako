"""Parser smoke tests for n8n and Flowise exports."""

import json
from pathlib import Path

import pytest

from drako.nocode.parsers import N8nParser, FlowiseParser, parse
from drako.nocode.parsers.base import ParserError

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_n8n_clean_workflow_parses() -> None:
    wf = N8nParser().parse(_load("n8n/clean.json"))
    assert wf.platform == "n8n"
    assert wf.name == "Clean Workflow"
    assert "Webhook" in wf.nodes
    assert wf.nodes["Webhook"].type == "webhook"
    assert wf.nodes["Webhook"].receives_user_input is True
    assert wf.nodes["Lookup"].type == "db_query"
    assert wf.nodes["Reply"].type == "llm_call"
    assert any(e.source == "Webhook" and e.target == "Validate Input" for e in wf.edges)


def test_n8n_unknown_type_falls_back_to_data_transform() -> None:
    payload = {"name": "x", "nodes": [{"name": "Q", "type": "n8n-nodes-base.totallyUnknown"}], "connections": {}}
    wf = N8nParser().parse(payload)
    assert wf.nodes["Q"].type == "data_transform"


def test_n8n_missing_nodes_raises() -> None:
    with pytest.raises(ParserError):
        N8nParser().parse({"name": "x"})


def test_flowise_clean_chatflow_parses() -> None:
    wf = FlowiseParser().parse(_load("flowise/clean.json"))
    assert wf.platform == "flowise"
    assert wf.nodes["n1"].type == "webhook"
    assert wf.nodes["n1"].receives_user_input is True
    assert wf.nodes["n3"].type == "llm_call"
    assert wf.nodes["n3"].credentials == ["oai_creds"]
    assert len(wf.edges) == 2


def test_dispatch_via_parse_helper() -> None:
    wf = parse("n8n", _load("n8n/clean.json"))
    assert wf.platform == "n8n"
    with pytest.raises(ParserError):
        parse("notreal", {"nodes": []})
