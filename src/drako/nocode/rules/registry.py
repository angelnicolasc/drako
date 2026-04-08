"""Rule registry for the nocode scanner.

Each NC-00X function takes a parsed (and reachability-tagged) workflow and
returns a list of `NocodeFinding`. The registry composes them so a caller
only ever has to call `evaluate_all(workflow)`.
"""

from __future__ import annotations

from typing import Callable, Iterable

from drako.nocode.graph import NocodeFinding, NocodeNode, NocodeWorkflow
from drako.nocode.reachability import TAINT_TAG, has_tainted_path, upstream_nodes


# ---------------------------------------------------------------------------
# Rule metadata — used by formatters and CHANGELOG/docs.
# ---------------------------------------------------------------------------

RULE_METADATA: dict[str, dict[str, str]] = {
    "NC-001": {"severity": "CRITICAL", "title": "User input reaches database without sanitization"},
    "NC-002": {"severity": "HIGH", "title": "User input reaches LLM without validation"},
    "NC-003": {"severity": "CRITICAL", "title": "Plaintext credentials in node config"},
    "NC-004": {"severity": "CRITICAL", "title": "User input reaches code execution without validation"},
    "NC-005": {"severity": "HIGH", "title": "Webhook with no authentication"},
    "NC-006": {"severity": "HIGH", "title": "HTTP request URL contains user input"},
    "NC-007": {"severity": "MEDIUM", "title": "PII data classification with no logging node"},
    "NC-008": {"severity": "MEDIUM", "title": "No error handling for sensitive node"},
    "NC-009": {"severity": "LOW", "title": "LLM call without temperature configured"},
    "NC-010": {"severity": "MEDIUM", "title": "Write operation with no human-in-the-loop"},
}

CATEGORY = "Nocode"

_SANITIZATION_HINTS = ("validate", "sanitize", "escape", "param", "clean", "guard")
_LOGGING_HINTS = ("log", "audit", "trail", "telemetry")
_WRITE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_WRITE_SQL_VERBS = ("insert", "update", "delete", "drop", "alter", "merge")


def _make(rule_id: str, message: str, *, node: NocodeNode | None = None,
          path: list[str] | None = None) -> NocodeFinding:
    meta = RULE_METADATA[rule_id]
    return NocodeFinding(
        policy_id=rule_id,
        category=CATEGORY,
        severity=meta["severity"],
        title=meta["title"],
        message=message,
        node_id=node.id if node else None,
        path=path or [],
    )


def _config_str(node: NocodeNode) -> str:
    """Best-effort flatten of a node config dict to a lowercased blob."""
    try:
        import json

        return json.dumps(node.config, default=str).lower()
    except Exception:
        return ""


def _has_sanitization_neighbour(workflow: NocodeWorkflow, target_id: str) -> bool:
    """True if any upstream data_transform node hints at validation."""
    for upstream_id in upstream_nodes(workflow, target_id):
        node = workflow.nodes.get(upstream_id)
        if node is None:
            continue
        if node.type != "data_transform":
            continue
        blob = _config_str(node)
        if any(hint in blob or hint in node.name.lower() for hint in _SANITIZATION_HINTS):
            return True
    return False


# ---------------------------------------------------------------------------
# NC-001 — User input → db_query without sanitization
# ---------------------------------------------------------------------------

def nc001_sql_injection(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes_of("db_query"):
        if not has_tainted_path(workflow, node.id):
            continue
        if _has_sanitization_neighbour(workflow, node.id):
            continue
        findings.append(
            _make(
                "NC-001",
                f"User input reaches database query '{node.name}' with no sanitisation node in between.",
                node=node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# NC-002 — User input → llm_call without validation
# ---------------------------------------------------------------------------

def nc002_llm_unvalidated(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes_of("llm_call"):
        if not has_tainted_path(workflow, node.id):
            continue
        if _has_sanitization_neighbour(workflow, node.id):
            continue
        findings.append(
            _make(
                "NC-002",
                f"User input flows into LLM call '{node.name}' with no validation step.",
                node=node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# NC-003 — Plaintext credentials in node config
# ---------------------------------------------------------------------------

_PLAINTEXT_CRED_KEYS = (
    "password", "api_key", "apikey", "secret", "token", "auth", "private_key",
)


def _looks_plaintext_secret(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if not value.strip():
        return False
    # n8n credential references look like "{{ $credentials.foo }}" or
    # "{{$credentials.foo.api_key}}" — anything templated is fine.
    if "{{" in value and "}}" in value:
        return False
    if value.startswith("$") or value.startswith("={{"):
        return False
    return len(value) >= 6


def _walk_config(value: object) -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k), v
            yield from _walk_config(v)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_config(item)


def nc003_plaintext_creds(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes.values():
        # If the node references the platform credential manager we treat
        # the node as safe regardless of config strings.
        if node.credentials:
            continue
        for key, value in _walk_config(node.config):
            if any(token in key.lower() for token in _PLAINTEXT_CRED_KEYS):
                if _looks_plaintext_secret(value):
                    findings.append(
                        _make(
                            "NC-003",
                            (
                                f"Node '{node.name}' has a credential field '{key}' "
                                "stored inline instead of via the platform credential manager."
                            ),
                            node=node,
                        )
                    )
                    break  # one finding per node is enough
    return findings


# ---------------------------------------------------------------------------
# NC-004 — code_exec reachable from user input without validation
# ---------------------------------------------------------------------------

def nc004_code_exec_no_validation(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes_of("code_exec"):
        if not has_tainted_path(workflow, node.id):
            continue
        if _has_sanitization_neighbour(workflow, node.id):
            continue
        findings.append(
            _make(
                "NC-004",
                f"Code-execution node '{node.name}' is reachable from user input without a validation step.",
                node=node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# NC-005 — webhook with no authentication
# ---------------------------------------------------------------------------

_AUTH_HINTS = ("auth", "headerauth", "basicauth", "jwt", "oauth", "token", "apikey")


def nc005_webhook_no_auth(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes_of("webhook"):
        blob = _config_str(node)
        explicit_none = blob == "" or '"authentication": "none"' in blob
        has_auth = any(token in blob for token in _AUTH_HINTS) and not explicit_none
        if has_auth:
            continue
        findings.append(
            _make(
                "NC-005",
                f"Webhook '{node.name}' has no authentication configured — the endpoint is publicly callable.",
                node=node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# NC-006 — http_request with templated user input in URL
# ---------------------------------------------------------------------------

def nc006_dynamic_http(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes_of("http_request"):
        url = ""
        if isinstance(node.config, dict):
            url = str(node.config.get("url") or node.config.get("URL") or "")
        if not url:
            continue
        if "{{" in url and "}}" in url:
            findings.append(
                _make(
                    "NC-006",
                    f"HTTP request '{node.name}' templates user input directly into the URL field.",
                    node=node,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# NC-007 — PII workflow without logging node
# ---------------------------------------------------------------------------

_PII_TAGS = {"pii", "pci", "phi", "financial"}


def nc007_pii_no_logging(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    has_sensitive = any(
        any(tag.lower() in _PII_TAGS for tag in n.data_classifications)
        for n in workflow.nodes.values()
    )
    if not has_sensitive:
        return []
    has_logging = any(
        n.type == "data_transform"
        and any(hint in n.name.lower() or hint in _config_str(n) for hint in _LOGGING_HINTS)
        for n in workflow.nodes.values()
    )
    if has_logging:
        return []
    return [
        _make(
            "NC-007",
            "Workflow processes sensitive data classifications (PII/PCI/PHI) but has no logging node.",
        )
    ]


# ---------------------------------------------------------------------------
# NC-008 — Sensitive node with no error handler in workflow
# ---------------------------------------------------------------------------

def nc008_no_error_handling(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    has_handler = any(n.type == "error_handler" for n in workflow.nodes.values())
    if has_handler:
        return []
    sensitive = [
        n for n in workflow.nodes.values() if n.type in ("code_exec", "db_query")
    ]
    if not sensitive:
        return []
    return [
        _make(
            "NC-008",
            "Workflow has code execution or database queries but no error-handler node — failures will silently break runs.",
        )
    ]


# ---------------------------------------------------------------------------
# NC-009 — llm_call without temperature configured
# ---------------------------------------------------------------------------

def nc009_llm_no_temperature(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    for node in workflow.nodes_of("llm_call"):
        config_blob = _config_str(node)
        if '"temperature"' not in config_blob and "temperature" not in node.config:
            findings.append(
                _make(
                    "NC-009",
                    f"LLM node '{node.name}' has no temperature set — outputs will not be reproducible.",
                    node=node,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# NC-010 — Write op with no HITL upstream
# ---------------------------------------------------------------------------

def _is_write(node: NocodeNode) -> bool:
    blob = _config_str(node)
    if node.type == "http_request":
        method = ""
        if isinstance(node.config, dict):
            method = str(node.config.get("method", "")).upper()
        if method in _WRITE_HTTP_METHODS:
            return True
    if node.type == "db_query":
        if any(verb in blob for verb in _WRITE_SQL_VERBS):
            return True
    return False


def nc010_write_no_hitl(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    findings: list[NocodeFinding] = []
    has_hitl_anywhere = any(n.type == "hitl" for n in workflow.nodes.values())
    for node in workflow.nodes.values():
        if not _is_write(node):
            continue
        if has_hitl_anywhere:
            # Stronger check: must be upstream of this node
            if any(
                workflow.nodes[uid].type == "hitl"
                for uid in upstream_nodes(workflow, node.id)
                if uid in workflow.nodes
            ):
                continue
        findings.append(
            _make(
                "NC-010",
                f"Write operation '{node.name}' has no human-in-the-loop checkpoint upstream.",
                node=node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_RULES: list[Callable[[NocodeWorkflow], list[NocodeFinding]]] = [
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
]


def evaluate_all(workflow: NocodeWorkflow) -> list[NocodeFinding]:
    """Run every rule and return the combined finding list."""
    findings: list[NocodeFinding] = []
    for rule in ALL_RULES:
        findings.extend(rule(workflow))
    return findings
