"""Tests for the LangGraph compliance middleware."""

from __future__ import annotations

from typing import Any

import pytest
import httpx
import respx

from agentmesh.client import AgentMeshClient
from agentmesh.middleware.langgraph import AgentMeshCheckpointer, with_langgraph_compliance


class TestAgentMeshCheckpointer:
    @respx.mock
    def test_put_records_audit(self):
        endpoint = "https://api.agentmesh.test"
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        audit_route = respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_lg"})
        )

        client = AgentMeshClient(api_key="am_live_t_s", endpoint=endpoint)
        cp = AgentMeshCheckpointer(client=client)
        cp.put(
            config={"configurable": {"thread_id": "t1"}},
            checkpoint={"ts": "2026-01-01T00:00:00Z"},
            metadata={"source": "agent_node"},
        )

        assert audit_route.called

    @respx.mock
    def test_put_delegates_to_inner(self):
        endpoint = "https://api.agentmesh.test"
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_lg"})
        )

        inner = type("MockCheckpointer", (), {"put": lambda self, *a, **kw: {"saved": True}})()

        client = AgentMeshClient(api_key="am_live_t_s", endpoint=endpoint)
        cp = AgentMeshCheckpointer(client=client, inner=inner)
        result = cp.put(
            config={"configurable": {}},
            checkpoint={"ts": "now"},
            metadata={"source": "node_a"},
        )
        assert result == {"saved": True}

    @respx.mock
    def test_get_delegates_to_inner(self):
        endpoint = "https://api.agentmesh.test"
        inner = type("MockCheckpointer", (), {"get": lambda self, config: {"checkpoint": "data"}})()

        client = AgentMeshClient(api_key="am_live_t_s", endpoint=endpoint)
        cp = AgentMeshCheckpointer(client=client, inner=inner)
        result = cp.get(config={})
        assert result == {"checkpoint": "data"}

    def test_get_without_inner_returns_none(self):
        client = AgentMeshClient(api_key="am_live_t_s", endpoint="https://api.agentmesh.test")
        cp = AgentMeshCheckpointer(client=client, inner=None)
        assert cp.get({}) is None

    def test_list_without_inner_returns_empty(self):
        client = AgentMeshClient(api_key="am_live_t_s", endpoint="https://api.agentmesh.test")
        cp = AgentMeshCheckpointer(client=client, inner=None)
        assert cp.list() == []


class TestAgentMeshCheckpointerAsync:
    @respx.mock
    @pytest.mark.asyncio
    async def test_aput_records_audit(self):
        endpoint = "https://api.agentmesh.test"
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        audit_route = respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_async"})
        )

        client = AgentMeshClient(api_key="am_live_t_s", endpoint=endpoint)
        cp = AgentMeshCheckpointer(client=client)
        await cp.aput(
            config={},
            checkpoint={"ts": "now"},
            metadata={"source": "async_node"},
        )
        assert audit_route.called
        await client.close()


class TestLangGraphProxy:
    @respx.mock
    def test_invoke_injects_checkpointer(self, config_file):
        endpoint = "https://api.agentmesh.test"
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_p"})
        )

        # Fake compiled graph
        class FakeGraph:
            def invoke(self, input: Any, config: dict | None = None, **kw: Any) -> dict:
                return {"result": "done", "config": config}

        proxy = with_langgraph_compliance(FakeGraph(), config_path=config_file)
        result = proxy.invoke({"query": "test"})
        assert result["result"] == "done"
        # Checkpointer should be injected in the config
        assert "checkpointer" in result["config"].get("configurable", {})
