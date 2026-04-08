"""BFS taint propagation tests."""

from drako.nocode.graph import NocodeEdge, NocodeNode, NocodeWorkflow
from drako.nocode.reachability import (
    TAINT_TAG,
    has_tainted_path,
    propagate_user_input,
    upstream_nodes,
)


def _wf() -> NocodeWorkflow:
    wf = NocodeWorkflow(name="t", platform="n8n")
    wf.nodes = {
        "wh": NocodeNode(id="wh", type="webhook", platform_type="webhook", receives_user_input=True),
        "transform": NocodeNode(id="transform", type="data_transform", platform_type="set"),
        "db": NocodeNode(id="db", type="db_query", platform_type="postgres"),
        "isolated": NocodeNode(id="isolated", type="db_query", platform_type="postgres"),
    }
    wf.edges = [
        NocodeEdge(source="wh", target="transform"),
        NocodeEdge(source="transform", target="db"),
    ]
    return wf


def test_propagation_marks_downstream_edges() -> None:
    wf = _wf()
    propagate_user_input(wf)
    assert TAINT_TAG in wf.edge("wh", "transform").carries
    assert TAINT_TAG in wf.edge("transform", "db").carries


def test_isolated_node_is_not_tainted() -> None:
    wf = _wf()
    propagate_user_input(wf)
    assert has_tainted_path(wf, "db") is True
    assert has_tainted_path(wf, "isolated") is False


def test_no_sources_is_a_noop() -> None:
    wf = _wf()
    wf.nodes["wh"].receives_user_input = False
    propagate_user_input(wf)
    assert all(TAINT_TAG not in e.carries for e in wf.edges)


def test_upstream_nodes_walks_reverse() -> None:
    wf = _wf()
    propagate_user_input(wf)
    up = upstream_nodes(wf, "db")
    assert "wh" in up
    assert "transform" in up
    assert "isolated" not in up
