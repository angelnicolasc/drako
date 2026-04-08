"""Parser for n8n workflow JSON exports.

n8n exports have a top-level `nodes` array (each node carries a `type`
string in dot-namespace, plus `parameters` and `credentials` dicts) and a
`connections` object keyed by source node name. We map n8n's node-type
strings to drako's normalised vocabulary by prefix matching, since n8n
ships dozens of variants per category.
"""

from __future__ import annotations

import logging
from typing import Any

from drako.nocode.graph import NocodeEdge, NocodeNode, NocodeWorkflow
from drako.nocode.parsers.base import Parser, ParserError

log = logging.getLogger(__name__)


# Order matters: more specific prefixes first.
_TYPE_RULES: list[tuple[str, str, bool]] = [
    # (substring/prefix, normalised_type, receives_user_input)
    ("n8n-nodes-base.webhook", "webhook", True),
    ("@n8n/n8n-nodes-langchain.openAi", "llm_call", False),
    ("@n8n/n8n-nodes-langchain.anthropic", "llm_call", False),
    ("@n8n/n8n-nodes-langchain.agent", "llm_call", False),
    ("@n8n/n8n-nodes-langchain.llm", "llm_call", False),
    ("n8n-nodes-base.mySql", "db_query", False),
    ("n8n-nodes-base.postgres", "db_query", False),
    ("n8n-nodes-base.mongoDb", "db_query", False),
    ("n8n-nodes-base.code", "code_exec", False),
    ("n8n-nodes-base.function", "code_exec", False),
    ("n8n-nodes-base.executeCommand", "code_exec", False),
    ("n8n-nodes-base.httpRequest", "http_request", False),
    ("n8n-nodes-base.set", "data_transform", False),
    ("n8n-nodes-base.merge", "data_transform", False),
    ("n8n-nodes-base.itemLists", "data_transform", False),
    ("n8n-nodes-base.errorTrigger", "error_handler", False),
    ("n8n-nodes-base.if", "data_transform", False),
    ("n8n-nodes-base.switch", "data_transform", False),
]


def _classify(platform_type: str) -> tuple[str, bool]:
    for prefix, norm_type, taints in _TYPE_RULES:
        if platform_type == prefix or platform_type.startswith(prefix):
            return norm_type, taints
    log.debug("Unknown n8n node type %s — defaulting to data_transform", platform_type)
    return "data_transform", False


def _extract_credentials(node: dict[str, Any]) -> list[str]:
    creds = node.get("credentials") or {}
    if isinstance(creds, dict):
        return list(creds.keys())
    return []


class N8nParser(Parser):
    platform = "n8n"

    def parse(self, payload: dict[str, Any]) -> NocodeWorkflow:
        if not isinstance(payload, dict) or "nodes" not in payload:
            raise ParserError("n8n export missing top-level 'nodes' array")

        workflow = NocodeWorkflow(
            name=str(payload.get("name", "Unnamed n8n workflow")),
            platform="n8n",
            raw=payload,
        )

        # Build nodes (n8n keys connections by node *name*, not id, so we
        # use name as the canonical id throughout the normalised graph).
        for raw_node in payload.get("nodes", []):
            if not isinstance(raw_node, dict):
                continue
            name = str(raw_node.get("name") or raw_node.get("id") or "")
            platform_type = str(raw_node.get("type", ""))
            norm_type, taints = _classify(platform_type)
            params = raw_node.get("parameters") or {}
            workflow.nodes[name] = NocodeNode(
                id=name,
                name=name,
                type=norm_type,
                platform_type=platform_type,
                credentials=_extract_credentials(raw_node),
                receives_user_input=taints,
                config=params if isinstance(params, dict) else {},
                raw=raw_node,
            )

        # Build edges from the n8n connections object.
        connections = payload.get("connections") or {}
        if isinstance(connections, dict):
            for source_name, outputs in connections.items():
                if not isinstance(outputs, dict):
                    continue
                # outputs is shaped like {"main": [[{node, type, index}, ...]]}
                for _, output_list in outputs.items():
                    if not isinstance(output_list, list):
                        continue
                    for branch in output_list:
                        if not isinstance(branch, list):
                            continue
                        for target in branch:
                            if not isinstance(target, dict):
                                continue
                            target_name = str(target.get("node", ""))
                            if target_name and source_name in workflow.nodes:
                                workflow.edges.append(
                                    NocodeEdge(source=source_name, target=target_name)
                                )

        return workflow
