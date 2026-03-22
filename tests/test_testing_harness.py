"""Tests for drako.testing — HITL test harness."""

import os
import pytest

from drako.testing import test_mode, MockHITLResolver, is_test_mode, get_hitl_default


class TestTestMode:
    """test_mode() context manager."""

    def test_activates_env_var(self):
        """test_mode sets DRAKO_TEST_MODE inside the context."""
        assert os.environ.get("DRAKO_TEST_MODE") != "true"
        with test_mode():
            assert os.environ["DRAKO_TEST_MODE"] == "true"
        assert os.environ.get("DRAKO_TEST_MODE") != "true"

    def test_auto_approve_returns_allowed(self):
        """HITL auto-approve makes evaluate_policy return 'allowed'."""
        from drako.client import DrakoClient

        with test_mode(hitl="auto-approve"):
            client = DrakoClient.__new__(DrakoClient)
            result = client.evaluate_policy_sync(agent_id="a1", tool_name="search")
            assert result["decision"] == "allowed"

    def test_auto_deny_returns_rejected(self):
        """HITL auto-deny makes evaluate_policy return 'rejected'."""
        from drako.client import DrakoClient

        with test_mode(hitl="auto-deny"):
            client = DrakoClient.__new__(DrakoClient)
            result = client.evaluate_policy_sync(agent_id="a1", tool_name="search")
            assert result["decision"] == "rejected"

    def test_skip_returns_allowed(self):
        """HITL skip bypasses HITL entirely → allowed."""
        from drako.client import DrakoClient

        with test_mode(hitl="skip"):
            client = DrakoClient.__new__(DrakoClient)
            result = client.evaluate_policy_sync(agent_id="a1", tool_name="search")
            assert result["decision"] == "allowed"

    def test_restores_env_on_exit(self):
        """Environment variables are restored after context exits."""
        os.environ.pop("DRAKO_TEST_MODE", None)
        with test_mode():
            pass
        assert "DRAKO_TEST_MODE" not in os.environ

    def test_invalid_hitl_raises(self):
        """Invalid hitl string raises ValueError."""
        with pytest.raises(ValueError, match="hitl must be"):
            with test_mode(hitl="invalid"):
                pass

    def test_nested_contexts(self):
        """Nested test_mode contexts work correctly."""
        from drako.client import DrakoClient

        with test_mode(hitl="auto-approve"):
            client = DrakoClient.__new__(DrakoClient)
            r1 = client.evaluate_policy_sync(agent_id="a1", tool_name="t1")
            assert r1["decision"] == "allowed"

            with test_mode(hitl="auto-deny"):
                r2 = client.evaluate_policy_sync(agent_id="a1", tool_name="t1")
                assert r2["decision"] == "rejected"

            # Outer context restored
            r3 = client.evaluate_policy_sync(agent_id="a1", tool_name="t1")
            assert r3["decision"] == "allowed"


class TestMockHITLResolver:
    """MockHITLResolver per-tool rules."""

    def test_default_approve(self):
        resolver = MockHITLResolver(default_action="approve")
        result = resolver.resolve("any_tool", "agent1")
        assert result["decision"] == "allowed"

    def test_default_deny(self):
        resolver = MockHITLResolver(default_action="deny")
        result = resolver.resolve("any_tool", "agent1")
        assert result["decision"] == "rejected"

    def test_per_tool_rules(self):
        resolver = MockHITLResolver(
            default_action="approve",
            rules={"delete_records": "deny", "read_data": "approve"},
        )
        assert resolver.resolve("delete_records")["decision"] == "rejected"
        assert resolver.resolve("read_data")["decision"] == "allowed"
        assert resolver.resolve("other_tool")["decision"] == "allowed"

    def test_call_log(self):
        resolver = MockHITLResolver()
        resolver.resolve("tool_a", "agent1")
        resolver.resolve("tool_b", "agent2")
        assert len(resolver.call_log) == 2
        assert resolver.call_log[0]["tool_name"] == "tool_a"
        assert resolver.call_log[1]["agent_id"] == "agent2"

    def test_resolver_in_test_mode(self):
        """MockHITLResolver works inside test_mode context."""
        from drako.client import DrakoClient

        resolver = MockHITLResolver(
            default_action="approve",
            rules={"dangerous_tool": "deny"},
        )

        with test_mode(hitl=resolver):
            client = DrakoClient.__new__(DrakoClient)
            r1 = client.evaluate_policy_sync(agent_id="a1", tool_name="safe_tool")
            assert r1["decision"] == "allowed"

            r2 = client.evaluate_policy_sync(agent_id="a1", tool_name="dangerous_tool")
            assert r2["decision"] == "rejected"

    def test_invalid_default_action_raises(self):
        with pytest.raises(ValueError):
            MockHITLResolver(default_action="invalid")


class TestEnvHelpers:
    """is_test_mode() and get_hitl_default()."""

    def test_is_test_mode_true(self):
        os.environ["DRAKO_TEST_MODE"] = "true"
        assert is_test_mode() is True
        del os.environ["DRAKO_TEST_MODE"]

    def test_is_test_mode_false(self):
        os.environ.pop("DRAKO_TEST_MODE", None)
        assert is_test_mode() is False

    def test_get_hitl_default(self):
        os.environ["DRAKO_HITL_DEFAULT"] = "deny"
        assert get_hitl_default() == "deny"
        del os.environ["DRAKO_HITL_DEFAULT"]

    def test_get_hitl_default_missing(self):
        os.environ.pop("DRAKO_HITL_DEFAULT", None)
        assert get_hitl_default() == "approve"
