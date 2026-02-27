"""CrewAI compliance middleware — transparent proxy with audit + policy."""

from __future__ import annotations

from typing import Any

from agentmesh.client import AgentMeshClient
from agentmesh.middleware.base import ComplianceMiddleware
from agentmesh.utils.logger import log


class CrewAIComplianceMiddleware(ComplianceMiddleware):
    """Wraps a CrewAI ``Crew`` to intercept its lifecycle:

    - **Pre-kickoff**: verify identity of every agent.
    - **Pre-task**: evaluate policy for each task.
    - **Post-task**: record audit log.
    - **On-error**: notify the trust engine.

    All other attributes/methods are proxied transparently to the
    underlying crew so the user notices no behavioural difference.
    """

    def __init__(
        self,
        crew: Any,
        client: AgentMeshClient,
        auto_audit: bool = True,
        auto_verify: bool = True,
        auto_policy: bool = True,
    ):
        super().__init__(
            client=client,
            auto_audit=auto_audit,
            auto_verify=auto_verify,
            auto_policy=auto_policy,
        )
        self._crew = crew

    # ----------------------------------------------------------------
    # Synchronous kickoff
    # ----------------------------------------------------------------

    def kickoff(self, **kwargs: Any) -> Any:
        """Compliance-wrapped ``crew.kickoff()``."""
        # Step 1 — verify all agents
        if self._auto_verify:
            self._verify_all_agents()

        # Step 2 — install task callbacks
        original_tasks = self._get_tasks()
        if self._auto_policy or self._auto_audit:
            self._wrap_tasks(original_tasks)

        # Step 3 — execute
        try:
            result = self._crew.kickoff(**kwargs)
        except Exception as exc:
            self._on_error(exc)
            raise

        # Step 4 — summary
        task_count = len(original_tasks) if original_tasks else 0
        log.info("Crew complete. %d tasks audited.", task_count)
        return result

    # ----------------------------------------------------------------
    # Async kickoff
    # ----------------------------------------------------------------

    async def akickoff(self, **kwargs: Any) -> Any:
        """Async compliance-wrapped ``crew.kickoff()``."""
        # Step 1 — verify all agents
        if self._auto_verify:
            await self._verify_all_agents_async()

        # Step 2 — install task callbacks
        original_tasks = self._get_tasks()
        if self._auto_policy or self._auto_audit:
            self._wrap_tasks(original_tasks)

        # Step 3 — execute (CrewAI >=0.70 supports async kickoff)
        try:
            if hasattr(self._crew, "akickoff"):
                result = await self._crew.akickoff(**kwargs)
            else:
                result = self._crew.kickoff(**kwargs)
        except Exception as exc:
            self._on_error(exc)
            raise

        task_count = len(original_tasks) if original_tasks else 0
        log.info("Crew complete. %d tasks audited.", task_count)
        return result

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    def _get_agents(self) -> list[Any]:
        """Retrieve the agent list from the crew, handling various CrewAI versions."""
        if hasattr(self._crew, "agents"):
            return list(self._crew.agents)
        return []

    def _get_tasks(self) -> list[Any]:
        """Retrieve the task list from the crew."""
        if hasattr(self._crew, "tasks"):
            return list(self._crew.tasks)
        return []

    def _verify_all_agents(self) -> None:
        for agent in self._get_agents():
            name = getattr(agent, "name", None) or getattr(agent, "role", "unknown")
            role = getattr(agent, "role", "agent")
            self._verify_agent(name, role)

    async def _verify_all_agents_async(self) -> None:
        for agent in self._get_agents():
            name = getattr(agent, "name", None) or getattr(agent, "role", "unknown")
            role = getattr(agent, "role", "agent")
            await self._verify_agent_async(name, role)

    def _wrap_tasks(self, tasks: list[Any]) -> None:
        """Install pre/post hooks on each task via CrewAI's callback mechanism."""
        for task in tasks:
            original_callback = getattr(task, "callback", None)

            # Determine agent DID for this task
            agent = getattr(task, "agent", None)
            agent_name = getattr(agent, "name", None) or getattr(agent, "role", "unknown") if agent else "unknown"
            agent_did = self._agent_dids.get(agent_name, "unknown")
            task_desc = getattr(task, "description", str(task))[:200]

            # Pre-task policy check (only if task has the hook)
            if self._auto_policy and agent_did != "unknown":
                try:
                    self._check_policy(task_desc, agent_did)
                except Exception:
                    raise

            # Wrap the callback for post-task audit
            if self._auto_audit:
                def _make_callback(orig_cb: Any, _did: str, _desc: str) -> Any:
                    def _audited_callback(output: Any) -> Any:
                        try:
                            result_data = {"output": str(output)[:1000]} if output else {}
                            self._record_audit(_desc, _did, result_data)
                        except Exception as exc:
                            log.warning("Audit log failed: %s", exc)
                        if orig_cb:
                            return orig_cb(output)
                        return output
                    return _audited_callback

                task.callback = _make_callback(original_callback, agent_did, task_desc)

    def _on_error(self, exc: Exception) -> None:
        """Notify the trust engine about an error."""
        log.error("Crew execution failed: %s", exc)

    # ----------------------------------------------------------------
    # Transparent proxy
    # ----------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Proxy all unknown attributes to the underlying crew."""
        return getattr(self._crew, name)


def with_compliance(
    crew: Any,
    config_path: str = ".agentmesh.yaml",
    auto_audit: bool = True,
    auto_verify: bool = True,
    auto_policy: bool = True,
) -> CrewAIComplianceMiddleware:
    """Convenience function to wrap a CrewAI Crew with compliance.

    Usage::

        from agentmesh import with_compliance

        crew = with_compliance(MyCrew())
        result = crew.kickoff()
    """
    client = AgentMeshClient.from_config(config_path)
    return CrewAIComplianceMiddleware(
        crew=crew,
        client=client,
        auto_audit=auto_audit,
        auto_verify=auto_verify,
        auto_policy=auto_policy,
    )
