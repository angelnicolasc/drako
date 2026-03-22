# mypy: strict
"""MCP server configuration registry.

Defines the 20 most popular MCP servers and their metadata for
governance analysis. Each entry includes the npm package, GitHub
repo, and category for organized reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MCPServerConfig:
    """Configuration for a single MCP server to analyze."""

    name: str
    package_name: str
    repo_url: str
    category: str
    description: str
    manifest_path: str = "package.json"
    entry_point: str = "src/index.ts"
    extra_source_globs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GovernanceCharacteristic:
    """Result of evaluating one governance dimension."""

    name: str
    present: bool
    evidence: str
    weight: int
    score: int  # 0 or 100


# ---------------------------------------------------------------------------
# Registry: 20 popular MCP servers
# ---------------------------------------------------------------------------

MCP_SERVERS: list[MCPServerConfig] = [
    # ── Filesystem ──
    MCPServerConfig(
        name="filesystem",
        package_name="@modelcontextprotocol/server-filesystem",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Filesystem",
        description="Read/write local filesystem with configurable allowed directories",
        entry_point="src/filesystem/index.ts",
    ),
    MCPServerConfig(
        name="sqlite",
        package_name="@modelcontextprotocol/server-sqlite",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Database",
        description="SQLite database operations via MCP",
        entry_point="src/sqlite/index.ts",
    ),
    MCPServerConfig(
        name="postgres",
        package_name="@modelcontextprotocol/server-postgres",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Database",
        description="PostgreSQL database operations via MCP",
        entry_point="src/postgres/index.ts",
    ),

    # ── APIs ──
    MCPServerConfig(
        name="github",
        package_name="@modelcontextprotocol/server-github",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="API",
        description="GitHub API operations (repos, issues, PRs, files)",
        entry_point="src/github/index.ts",
    ),
    MCPServerConfig(
        name="slack",
        package_name="@modelcontextprotocol/server-slack",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="API",
        description="Slack workspace interaction via MCP",
        entry_point="src/slack/index.ts",
    ),
    MCPServerConfig(
        name="linear",
        package_name="mcp-linear",
        repo_url="https://github.com/jerhadf/linear-mcp-server",
        category="API",
        description="Linear issue tracker integration",
        entry_point="src/index.ts",
    ),
    MCPServerConfig(
        name="jira",
        package_name="mcp-jira",
        repo_url="https://github.com/sooperset/mcp-atlassian",
        category="API",
        description="Jira/Atlassian project management integration",
        entry_point="src/index.ts",
    ),

    # ── Cloud ──
    MCPServerConfig(
        name="aws-kb-retrieval",
        package_name="@modelcontextprotocol/server-aws-kb-retrieval",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Cloud",
        description="AWS Bedrock Knowledge Base retrieval",
        entry_point="src/aws-kb-retrieval/index.ts",
    ),
    MCPServerConfig(
        name="gcp",
        package_name="mcp-server-gcp",
        repo_url="https://github.com/nicholasgriffintn/mcp-server-gcp",
        category="Cloud",
        description="Google Cloud Platform operations via MCP",
        entry_point="src/index.ts",
    ),

    # ── Data ──
    MCPServerConfig(
        name="google-drive",
        package_name="@modelcontextprotocol/server-gdrive",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Data",
        description="Google Drive file access and search",
        entry_point="src/gdrive/index.ts",
    ),
    MCPServerConfig(
        name="notion",
        package_name="mcp-notion",
        repo_url="https://github.com/makenotion/notion-mcp-server",
        category="Data",
        description="Notion workspace and database access",
        entry_point="src/index.ts",
    ),
    MCPServerConfig(
        name="airtable",
        package_name="mcp-airtable",
        repo_url="https://github.com/felores/airtable-mcp",
        category="Data",
        description="Airtable base operations via MCP",
        entry_point="src/index.ts",
    ),

    # ── Dev ──
    MCPServerConfig(
        name="docker",
        package_name="mcp-docker",
        repo_url="https://github.com/ckreiling/mcp-server-docker",
        category="Dev",
        description="Docker container and image management",
        entry_point="src/index.ts",
    ),
    MCPServerConfig(
        name="kubernetes",
        package_name="mcp-kubernetes",
        repo_url="https://github.com/Flux159/mcp-server-kubernetes",
        category="Dev",
        description="Kubernetes cluster operations",
        entry_point="src/index.ts",
    ),
    MCPServerConfig(
        name="git",
        package_name="@modelcontextprotocol/server-git",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Dev",
        description="Git repository operations (log, diff, commit)",
        entry_point="src/git/index.ts",
    ),

    # ── AI / Search ──
    MCPServerConfig(
        name="brave-search",
        package_name="@modelcontextprotocol/server-brave-search",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="AI",
        description="Brave Search API for web and local search",
        entry_point="src/brave-search/index.ts",
    ),
    MCPServerConfig(
        name="puppeteer",
        package_name="@modelcontextprotocol/server-puppeteer",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="AI",
        description="Browser automation via Puppeteer",
        entry_point="src/puppeteer/index.ts",
    ),
    MCPServerConfig(
        name="fetch",
        package_name="@modelcontextprotocol/server-fetch",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="AI",
        description="HTTP fetch with content extraction",
        entry_point="src/fetch/index.ts",
    ),
    MCPServerConfig(
        name="memory",
        package_name="@modelcontextprotocol/server-memory",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="AI",
        description="Knowledge graph-based persistent memory",
        entry_point="src/memory/index.ts",
    ),
    MCPServerConfig(
        name="everything",
        package_name="@modelcontextprotocol/server-everything",
        repo_url="https://github.com/modelcontextprotocol/servers",
        category="Dev",
        description="Reference/test server exercising all MCP features",
        entry_point="src/everything/index.ts",
    ),
]


def get_servers_by_name(names: list[str]) -> list[MCPServerConfig]:
    """Filter servers by name. Returns all if names is empty."""
    if not names:
        return list(MCP_SERVERS)
    name_set = {n.lower() for n in names}
    return [s for s in MCP_SERVERS if s.name.lower() in name_set]
