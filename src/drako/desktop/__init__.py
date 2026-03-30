"""Desktop AI agent discovery, scanning, and governance.

Discovers all AI agents, MCP servers, and skills installed on the
user's machine by reading known configuration paths. Evaluates
8 MCP security rules and optionally activates runtime protection.
"""

from __future__ import annotations

from drako.desktop.discovery import (
    DesktopAgent,
    DesktopBOM,
    MCPServerConfig,
    discover_agents,
)

__all__ = [
    "DesktopAgent",
    "DesktopBOM",
    "MCPServerConfig",
    "discover_agents",
]
