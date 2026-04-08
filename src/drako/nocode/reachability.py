"""Taint propagation for the nocode scanner.

Runs a BFS from every node with `receives_user_input=True` and marks all
edges along reachable directed paths with `"user_input"` in their
`carries` list. This MUST run before rule evaluation — NC-001 / NC-002
distinguish "user input reaches a dangerous node" from "dangerous node
exists in isolation", and that distinction lives entirely on the edges.
"""

from __future__ import annotations

from collections import deque

from drako.nocode.graph import NocodeWorkflow, build_graph


TAINT_TAG = "user_input"


def propagate_user_input(workflow: NocodeWorkflow) -> None:
    """Mark every edge downstream of a user-input source as tainted."""
    graph = build_graph(workflow)
    sources = [
        node.id
        for node in workflow.nodes.values()
        if node.receives_user_input
    ]
    if not sources:
        return

    visited: set[str] = set()
    queue: deque[str] = deque(sources)
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        for successor in graph.successors(current):
            edge = workflow.edge(current, successor)
            if edge is not None and TAINT_TAG not in edge.carries:
                edge.carries.append(TAINT_TAG)
            if successor not in visited:
                queue.append(successor)


def has_tainted_path(workflow: NocodeWorkflow, target_id: str) -> bool:
    """Return True if any incoming edge of the target carries user_input."""
    return any(
        TAINT_TAG in e.carries for e in workflow.edges if e.target == target_id
    )


def upstream_nodes(workflow: NocodeWorkflow, target_id: str) -> set[str]:
    """Return the set of nodes that can reach `target_id` (BFS reverse)."""
    graph = build_graph(workflow)
    if target_id not in graph:
        return set()
    seen: set[str] = set()
    queue: deque[str] = deque([target_id])
    while queue:
        current = queue.popleft()
        for predecessor in graph.predecessors(current):
            if predecessor not in seen:
                seen.add(predecessor)
                queue.append(predecessor)
    return seen
