"""Normalised graph data model for the nocode scanner.

We deliberately keep this independent of networkx-specific types in the
public API: workflows expose plain dicts of nodes plus a `networkx.DiGraph`
for callers that want to traverse it directly. The Finding type is a
thin extension of the existing scanner Finding so that downstream tools
can treat code findings and nocode findings uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from drako.cli.policies.base import Finding

if TYPE_CHECKING:
    import networkx as nx


# Canonical normalised node types. Both parsers map their platform types
# into one of these strings — every rule and the reachability analyser
# only ever look at this normalised vocabulary.
NODE_TYPES = (
    "webhook",
    "llm_call",
    "db_query",
    "code_exec",
    "http_request",
    "data_transform",
    "hitl",
    "auth",
    "error_handler",
)


@dataclass
class NocodeNode:
    """A single node in a normalised workflow graph."""

    id: str
    type: str  # one of NODE_TYPES
    platform_type: str  # original platform node type string
    name: str = ""
    credentials: list[str] = field(default_factory=list)
    receives_user_input: bool = False
    data_classifications: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class NocodeEdge:
    """Directed edge between two nodes."""

    source: str
    target: str
    carries: list[str] = field(default_factory=list)


@dataclass
class NocodeWorkflow:
    """A parsed, normalised workflow ready for rule evaluation."""

    name: str
    platform: str  # "n8n" | "flowise"
    nodes: dict[str, NocodeNode] = field(default_factory=dict)
    edges: list[NocodeEdge] = field(default_factory=list)
    graph: "nx.DiGraph | None" = None  # built lazily by build_graph()
    raw: dict[str, Any] = field(default_factory=dict)

    def nodes_of(self, node_type: str) -> list[NocodeNode]:
        return [n for n in self.nodes.values() if n.type == node_type]

    def edge(self, src: str, dst: str) -> NocodeEdge | None:
        for e in self.edges:
            if e.source == src and e.target == dst:
                return e
        return None


@dataclass
class NocodeFinding(Finding):
    """Scanner finding for a no-code workflow.

    Extends the standard `Finding` with workflow-specific context. Inherits
    every existing field (severity, message, …) so that the standard
    scoring helpers can score nocode findings without modification.
    """

    node_id: str | None = None
    path: list[str] = field(default_factory=list)


def build_graph(workflow: NocodeWorkflow) -> "nx.DiGraph":
    """Materialise a `networkx.DiGraph` from the workflow's nodes + edges.

    Stored back on the workflow as `workflow.graph` for callers that need
    repeated graph access. Idempotent: returns the existing graph if set.
    """
    import networkx as nx

    if workflow.graph is not None:
        return workflow.graph

    g: nx.DiGraph = nx.DiGraph()
    for node in workflow.nodes.values():
        g.add_node(node.id, node=node)
    for edge in workflow.edges:
        if edge.source in workflow.nodes and edge.target in workflow.nodes:
            g.add_edge(edge.source, edge.target, edge=edge)
    workflow.graph = g
    return g
