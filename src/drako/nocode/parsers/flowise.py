"""Parser for Flowise chatflow JSON exports.

Flowise exports a `nodes` array (each node is a React-Flow node with a
`data` dict containing `name`, `category`, `inputs`, `credential`) and an
`edges` array (each carrying `source` / `target` ids). We classify by
the `category` field which is consistent across versions; entry-point
nodes (chatInput / promptTemplate) are tagged as user-input sources.
"""

from __future__ import annotations

import logging
from typing import Any

from drako.nocode.graph import NocodeEdge, NocodeNode, NocodeWorkflow
from drako.nocode.parsers.base import Parser, ParserError

log = logging.getLogger(__name__)


_CATEGORY_MAP = {
    "chat models": "llm_call",
    "llms": "llm_call",
    "agents": "llm_call",
    "vector stores": "data_transform",
    "document loaders": "data_transform",
    "text splitters": "data_transform",
    "embeddings": "data_transform",
    "memory": "data_transform",
    "tools": "data_transform",
    "custom tool": "code_exec",
    "code interpreter": "code_exec",
    "tools/custom tool": "code_exec",
    "tools/code interpreter": "code_exec",
}

_USER_INPUT_NAMES = {"chatinput", "prompttemplate", "questiontextretriever"}


def _classify(name: str, category: str) -> tuple[str, bool]:
    name_l = name.lower()
    cat_l = category.lower()
    if name_l in _USER_INPUT_NAMES:
        return "webhook", True
    if cat_l in _CATEGORY_MAP:
        return _CATEGORY_MAP[cat_l], False
    # Fall back to substring sniffing for hierarchical categories like
    # "Tools/Custom Tool" / "Chat Models / OpenAI" that some exports use.
    for key, norm in _CATEGORY_MAP.items():
        if key in cat_l:
            return norm, False
    log.debug("Unknown Flowise node category %r — defaulting to data_transform", category)
    return "data_transform", False


def _extract_credentials(data: dict[str, Any]) -> list[str]:
    creds = data.get("credential") or data.get("credentials")
    if isinstance(creds, str):
        return [creds]
    if isinstance(creds, list):
        return [str(c) for c in creds]
    if isinstance(creds, dict):
        return list(creds.keys())
    return []


class FlowiseParser(Parser):
    platform = "flowise"

    def parse(self, payload: dict[str, Any]) -> NocodeWorkflow:
        if not isinstance(payload, dict) or "nodes" not in payload:
            raise ParserError("Flowise export missing top-level 'nodes' array")

        workflow = NocodeWorkflow(
            name=str(payload.get("name", "Unnamed Flowise chatflow")),
            platform="flowise",
            raw=payload,
        )

        for raw_node in payload.get("nodes", []):
            if not isinstance(raw_node, dict):
                continue
            node_id = str(raw_node.get("id", ""))
            data = raw_node.get("data") or {}
            if not isinstance(data, dict):
                data = {}
            name = str(data.get("name") or data.get("label") or node_id)
            category = str(data.get("category", ""))
            norm_type, taints = _classify(name, category)
            workflow.nodes[node_id] = NocodeNode(
                id=node_id,
                name=name,
                type=norm_type,
                platform_type=name,
                credentials=_extract_credentials(data),
                receives_user_input=taints,
                config=data.get("inputs") or {},
                raw=raw_node,
            )

        for raw_edge in payload.get("edges", []):
            if not isinstance(raw_edge, dict):
                continue
            source = str(raw_edge.get("source", ""))
            target = str(raw_edge.get("target", ""))
            if source in workflow.nodes and target in workflow.nodes:
                workflow.edges.append(NocodeEdge(source=source, target=target))

        return workflow
