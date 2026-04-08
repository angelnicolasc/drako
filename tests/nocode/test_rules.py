"""Positive + negative coverage for every NC rule."""

from drako.nocode.graph import NocodeEdge, NocodeNode, NocodeWorkflow
from drako.nocode.reachability import propagate_user_input
from drako.nocode.rules import RULE_METADATA, evaluate_all
from drako.nocode.rules.registry import (
    nc001_sql_injection,
    nc002_llm_unvalidated,
    nc003_plaintext_creds,
    nc004_code_exec_no_validation,
    nc005_webhook_no_auth,
    nc006_dynamic_http,
    nc007_pii_no_logging,
    nc008_no_error_handling,
    nc009_llm_no_temperature,
    nc010_write_no_hitl,
)


def _wf(nodes: list[NocodeNode], edges: list[NocodeEdge] | None = None) -> NocodeWorkflow:
    wf = NocodeWorkflow(name="t", platform="n8n")
    wf.nodes = {n.id: n for n in nodes}
    wf.edges = list(edges or [])
    propagate_user_input(wf)
    return wf


def _node(id_: str, type_: str, **kwargs: object) -> NocodeNode:
    return NocodeNode(id=id_, name=id_, type=type_, platform_type=type_, **kwargs)  # type: ignore[arg-type]


# ---- NC-001 ---------------------------------------------------------------

def test_nc001_positive_user_input_to_db() -> None:
    wf = _wf(
        [_node("wh", "webhook", receives_user_input=True), _node("db", "db_query")],
        [NocodeEdge("wh", "db")],
    )
    assert any(f.policy_id == "NC-001" for f in nc001_sql_injection(wf))


def test_nc001_negative_with_sanitization_node() -> None:
    wf = _wf(
        [
            _node("wh", "webhook", receives_user_input=True),
            _node("validate", "data_transform", config={"sanitize": True}),
            _node("db", "db_query"),
        ],
        [NocodeEdge("wh", "validate"), NocodeEdge("validate", "db")],
    )
    assert nc001_sql_injection(wf) == []


# ---- NC-002 ---------------------------------------------------------------

def test_nc002_positive() -> None:
    wf = _wf(
        [_node("wh", "webhook", receives_user_input=True), _node("llm", "llm_call")],
        [NocodeEdge("wh", "llm")],
    )
    assert any(f.policy_id == "NC-002" for f in nc002_llm_unvalidated(wf))


def test_nc002_negative_when_llm_isolated() -> None:
    wf = _wf([_node("llm", "llm_call")], [])
    assert nc002_llm_unvalidated(wf) == []


# ---- NC-003 ---------------------------------------------------------------

def test_nc003_positive_inline_secret() -> None:
    wf = _wf([_node("db", "db_query", config={"password": "supersecret"})])
    findings = nc003_plaintext_creds(wf)
    assert any(f.policy_id == "NC-003" for f in findings)


def test_nc003_negative_with_credential_manager() -> None:
    wf = _wf([_node("db", "db_query", credentials=["mysql_creds"])])
    assert nc003_plaintext_creds(wf) == []


def test_nc003_negative_with_template_reference() -> None:
    wf = _wf([_node("db", "db_query", config={"password": "{{ $credentials.mysql.password }}"})])
    assert nc003_plaintext_creds(wf) == []


# ---- NC-004 ---------------------------------------------------------------

def test_nc004_positive() -> None:
    wf = _wf(
        [_node("wh", "webhook", receives_user_input=True), _node("exec", "code_exec")],
        [NocodeEdge("wh", "exec")],
    )
    assert any(f.policy_id == "NC-004" for f in nc004_code_exec_no_validation(wf))


def test_nc004_negative_with_validation() -> None:
    wf = _wf(
        [
            _node("wh", "webhook", receives_user_input=True),
            _node("guard", "data_transform", config={"validate": True}),
            _node("exec", "code_exec"),
        ],
        [NocodeEdge("wh", "guard"), NocodeEdge("guard", "exec")],
    )
    assert nc004_code_exec_no_validation(wf) == []


# ---- NC-005 ---------------------------------------------------------------

def test_nc005_positive_webhook_no_auth() -> None:
    wf = _wf([_node("wh", "webhook", receives_user_input=True, config={"path": "/x"})])
    assert any(f.policy_id == "NC-005" for f in nc005_webhook_no_auth(wf))


def test_nc005_negative_with_header_auth() -> None:
    wf = _wf([_node("wh", "webhook", receives_user_input=True, config={"authentication": "headerAuth"})])
    assert nc005_webhook_no_auth(wf) == []


# ---- NC-006 ---------------------------------------------------------------

def test_nc006_positive_templated_url() -> None:
    wf = _wf([_node("h", "http_request", config={"url": "https://api/{{ $json.x }}"})])
    assert any(f.policy_id == "NC-006" for f in nc006_dynamic_http(wf))


def test_nc006_negative_static_url() -> None:
    wf = _wf([_node("h", "http_request", config={"url": "https://api/static"})])
    assert nc006_dynamic_http(wf) == []


# ---- NC-007 ---------------------------------------------------------------

def test_nc007_positive_pii_no_logger() -> None:
    wf = _wf([_node("d", "db_query", data_classifications=["PII"])])
    assert any(f.policy_id == "NC-007" for f in nc007_pii_no_logging(wf))


def test_nc007_negative_with_logger_node() -> None:
    wf = _wf(
        [
            _node("d", "db_query", data_classifications=["PII"]),
            _node("logger", "data_transform", config={"audit": True}),
        ]
    )
    assert nc007_pii_no_logging(wf) == []


# ---- NC-008 ---------------------------------------------------------------

def test_nc008_positive_no_handler() -> None:
    wf = _wf([_node("c", "code_exec")])
    assert any(f.policy_id == "NC-008" for f in nc008_no_error_handling(wf))


def test_nc008_negative_with_handler() -> None:
    wf = _wf([_node("c", "code_exec"), _node("e", "error_handler")])
    assert nc008_no_error_handling(wf) == []


# ---- NC-009 ---------------------------------------------------------------

def test_nc009_positive_no_temp() -> None:
    wf = _wf([_node("l", "llm_call", config={"model": "gpt-4o"})])
    assert any(f.policy_id == "NC-009" for f in nc009_llm_no_temperature(wf))


def test_nc009_negative_with_temp() -> None:
    wf = _wf([_node("l", "llm_call", config={"temperature": 0})])
    assert nc009_llm_no_temperature(wf) == []


# ---- NC-010 ---------------------------------------------------------------

def test_nc010_positive_post_no_hitl() -> None:
    wf = _wf([_node("h", "http_request", config={"method": "POST", "url": "https://api/x"})])
    assert any(f.policy_id == "NC-010" for f in nc010_write_no_hitl(wf))


def test_nc010_negative_with_hitl_upstream() -> None:
    wf = _wf(
        [
            _node("hitl", "hitl"),
            _node("h", "http_request", config={"method": "POST", "url": "https://api/x"}),
        ],
        [NocodeEdge("hitl", "h")],
    )
    assert nc010_write_no_hitl(wf) == []


# ---- Registry sanity ------------------------------------------------------

def test_registry_metadata_covers_all_rules() -> None:
    assert set(RULE_METADATA.keys()) == {f"NC-{i:03d}" for i in range(1, 11)}


def test_evaluate_all_runs_clean_workflow_without_errors() -> None:
    wf = _wf(
        [
            _node("wh", "webhook", receives_user_input=True, config={"authentication": "headerAuth"}),
            _node("validate", "data_transform", config={"sanitize": True}),
            _node("llm", "llm_call", credentials=["oai"], config={"temperature": 0}),
            _node("err", "error_handler"),
        ],
        [NocodeEdge("wh", "validate"), NocodeEdge("validate", "llm")],
    )
    findings = evaluate_all(wf)
    assert all(f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} for f in findings)
