"""JSON formatter for `drako nocode`."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import date

from drako.nocode.graph import NocodeFinding, NocodeWorkflow
from drako.nocode.scoring import score_workflow


def _finding_dict(f: NocodeFinding) -> dict:
    return {
        "policy_id": f.policy_id,
        "severity": f.severity,
        "title": f.title,
        "message": f.message,
        "node_id": f.node_id,
        "path": f.path,
    }


def format_json(workflow: NocodeWorkflow, findings: list[NocodeFinding]) -> str:
    score, grade = score_workflow(findings)
    payload = {
        "workflow": workflow.name,
        "platform": workflow.platform,
        "analyzed": date.today().isoformat(),
        "node_count": len(workflow.nodes),
        "score": score,
        "grade": grade,
        "findings": [_finding_dict(f) for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_bom_json(workflow: NocodeWorkflow) -> str:
    nodes = []
    for node in workflow.nodes.values():
        nd = asdict(node)
        nd.pop("raw", None)
        nodes.append(nd)
    edges = [
        {"source": e.source, "target": e.target, "carries": e.carries}
        for e in workflow.edges
    ]
    return json.dumps(
        {
            "workflow": workflow.name,
            "platform": workflow.platform,
            "nodes": nodes,
            "edges": edges,
        },
        indent=2,
    )
