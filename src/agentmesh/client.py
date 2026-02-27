"""AgentMeshClient — async-first HTTP client for the AgentMesh API."""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx

from agentmesh import __version__
from agentmesh.config import AgentMeshConfig
from agentmesh.exceptions import (
    AgentMeshAPIError,
    AuthenticationError,
    PolicyViolationError,
    QuotaExceededError,
)
from agentmesh.utils.logger import log

_DEFAULT_ENDPOINT = "https://api.useagentmesh.com"
_TIMEOUT = 30.0
_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0  # seconds


class AgentMeshClient:
    """HTTP client that communicates with the AgentMesh backend.

    All async methods have ``_sync`` counterparts for non-async frameworks.
    """

    def __init__(
        self,
        api_key: str,
        endpoint: str = _DEFAULT_ENDPOINT,
        tenant_id: str | None = None,
    ):
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._tenant_id = tenant_id or self._extract_tenant_id(api_key)
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "X-Tenant-ID": self._tenant_id,
            "User-Agent": f"agentmesh-python/{__version__}",
            "Content-Type": "application/json",
        }
        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config_path: str = ".agentmesh.yaml") -> AgentMeshClient:
        """Instantiate from a .agentmesh.yaml file."""
        config = AgentMeshConfig.load(config_path)
        api_key = config.resolve_api_key()
        return cls(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id)

    @classmethod
    def from_env(cls) -> AgentMeshClient:
        """Instantiate from environment variables."""
        api_key = os.environ.get("AGENTMESH_API_KEY")
        if not api_key:
            raise AuthenticationError("AGENTMESH_API_KEY environment variable is not set")
        endpoint = os.environ.get("AGENTMESH_ENDPOINT", _DEFAULT_ENDPOINT)
        tenant_id = os.environ.get("AGENTMESH_TENANT_ID")
        return cls(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)

    # ------------------------------------------------------------------
    # Internal HTTP machinery
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tenant_id(api_key: str) -> str:
        """Best-effort extraction of tenant_id from the API key prefix."""
        # Keys look like am_live_<tenant>_<secret> or am_test_<tenant>_<secret>
        parts = api_key.split("_")
        if len(parts) >= 3:
            return parts[2]
        return "default"

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self._endpoint,
                headers=self._headers,
                timeout=_TIMEOUT,
            )
        return self._async_client

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self._endpoint,
                headers=self._headers,
                timeout=_TIMEOUT,
            )
        return self._sync_client

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Make an HTTP request with retry and error handling."""
        client = self._get_async_client()
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                response = await client.request(method, path, **kwargs)
                return self._handle_response(response)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    wait = _BACKOFF_BASE * (2 ** attempt)
                    log.warning("Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                                path, attempt + 1, _MAX_RETRIES, wait, exc)
                    await asyncio.sleep(wait)

        raise AgentMeshAPIError(
            status_code=0,
            detail=f"Request failed after {_MAX_RETRIES} retries: {last_exc}",
        )

    def _request_sync(self, method: str, path: str, **kwargs: Any) -> dict:
        """Synchronous version of _request with retry."""
        client = self._get_sync_client()
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                response = client.request(method, path, **kwargs)
                return self._handle_response(response)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    wait = _BACKOFF_BASE * (2 ** attempt)
                    log.warning("Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                                path, attempt + 1, _MAX_RETRIES, wait, exc)
                    time.sleep(wait)

        raise AgentMeshAPIError(
            status_code=0,
            detail=f"Request failed after {_MAX_RETRIES} retries: {last_exc}",
        )

    @staticmethod
    def _handle_response(response: httpx.Response) -> dict:
        """Parse response and raise typed errors."""
        request_id = response.headers.get("X-Request-ID")

        if response.status_code == 401:
            raise AuthenticationError(
                detail=response.text or "Authentication failed",
                request_id=request_id,
            )
        if response.status_code == 429:
            raise QuotaExceededError(
                detail=response.text or "Quota exceeded",
                request_id=request_id,
            )
        if response.status_code == 403:
            body = response.json() if response.text else {}
            raise PolicyViolationError(
                detail=body.get("detail", "Action blocked by policy"),
                policy_id=body.get("policy_id"),
                request_id=request_id,
            )
        if response.status_code >= 400:
            raise AgentMeshAPIError(
                status_code=response.status_code,
                detail=response.text or "Unknown error",
                request_id=request_id,
            )

        if not response.text:
            return {}
        return response.json()

    # ------------------------------------------------------------------
    # Async API methods
    # ------------------------------------------------------------------

    async def verify_agent_identity(
        self, agent_name: str, agent_role: str, metadata: dict | None = None
    ) -> dict:
        """Register/verify an agent and return its DID + trust score."""
        payload: dict[str, Any] = {"agent_name": agent_name, "agent_role": agent_role}
        if metadata:
            payload["metadata"] = metadata
        result = await self._request("POST", "/api/v1/agents/register", json=payload)
        log.info('Agent "%s" verified (DID: %s)', agent_name, result.get("did", "unknown"))
        return result

    async def evaluate_policy(
        self, action: str, agent_did: str, context: dict | None = None
    ) -> dict:
        """Evaluate whether an action is permitted by the tenant's policies."""
        payload: dict[str, Any] = {
            "agent_did": agent_did,
            "action_type": action,
        }
        if context:
            payload["context"] = context
        return await self._request("POST", "/api/v1/trust/evaluate", json=payload)

    async def audit_log(
        self,
        action: str,
        agent_did: str,
        result: dict | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create an audit hash chain entry."""
        payload: dict[str, Any] = {
            "agent_did": agent_did,
            "action_type": action,
            "action_description": action,
        }
        if result:
            payload["output_data"] = result
        if metadata:
            payload["metadata"] = metadata
        return await self._request("POST", "/api/v1/audit-logs", json=payload)

    async def verify_chain(self, last_n: int | None = None) -> dict:
        """Verify the integrity of the audit hash chain."""
        params: dict[str, Any] = {}
        if last_n is not None:
            params["last_n"] = last_n
        return await self._request("POST", "/api/v1/audit-logs/verify", json=params)

    async def check_quota(self) -> dict:
        """Check the tenant's current usage quota."""
        return await self._request("GET", f"/api/v1/billing/usage/{self._tenant_id}")

    async def validate_key(self) -> dict:
        """Validate the API key and return tenant info."""
        return await self._request("GET", "/api/v1/stats")

    # ------------------------------------------------------------------
    # Sync wrappers
    # ------------------------------------------------------------------

    def verify_agent_identity_sync(
        self, agent_name: str, agent_role: str, metadata: dict | None = None
    ) -> dict:
        """Sync wrapper for verify_agent_identity."""
        payload: dict[str, Any] = {"agent_name": agent_name, "agent_role": agent_role}
        if metadata:
            payload["metadata"] = metadata
        result = self._request_sync("POST", "/api/v1/agents/register", json=payload)
        log.info('Agent "%s" verified (DID: %s)', agent_name, result.get("did", "unknown"))
        return result

    def evaluate_policy_sync(
        self, action: str, agent_did: str, context: dict | None = None
    ) -> dict:
        """Sync wrapper for evaluate_policy."""
        payload: dict[str, Any] = {
            "agent_did": agent_did,
            "action_type": action,
        }
        if context:
            payload["context"] = context
        return self._request_sync("POST", "/api/v1/trust/evaluate", json=payload)

    def audit_log_sync(
        self,
        action: str,
        agent_did: str,
        result: dict | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Sync wrapper for audit_log."""
        payload: dict[str, Any] = {
            "agent_did": agent_did,
            "action_type": action,
            "action_description": action,
        }
        if result:
            payload["output_data"] = result
        if metadata:
            payload["metadata"] = metadata
        return self._request_sync("POST", "/api/v1/audit-logs", json=payload)

    def verify_chain_sync(self, last_n: int | None = None) -> dict:
        """Sync wrapper for verify_chain."""
        params: dict[str, Any] = {}
        if last_n is not None:
            params["last_n"] = last_n
        return self._request_sync("POST", "/api/v1/audit-logs/verify", json=params)

    def check_quota_sync(self) -> dict:
        """Sync wrapper for check_quota."""
        return self._request_sync("GET", f"/api/v1/billing/usage/{self._tenant_id}")

    def validate_key_sync(self) -> dict:
        """Sync wrapper for validate_key."""
        return self._request_sync("GET", "/api/v1/stats")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP clients."""
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()

    async def __aenter__(self) -> AgentMeshClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
