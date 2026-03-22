# mypy: strict
"""Manifest and source fetcher with local caching.

Fetches MCP server manifests and source files from GitHub,
caches them locally with a 7-day TTL. Supports offline mode
that uses only cached data.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from mcp_configs import MCPServerConfig

_CACHE_DIR = Path(__file__).parent / "cache"
_TTL_SECONDS: int = 7 * 24 * 60 * 60  # 7 days

_GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


@dataclass(frozen=True)
class CachedContent:
    """Cached manifest + source content for a server."""

    manifest: str
    source: str
    cached_at: float


def _cache_path(server_name: str) -> Path:
    return _CACHE_DIR / f"{server_name}.json"


def _is_fresh(path: Path) -> bool:
    """Check if cache file exists and is within TTL."""
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        cached_at = float(data.get("cached_at", 0))
        return (time.time() - cached_at) < _TTL_SECONDS
    except (json.JSONDecodeError, OSError, ValueError):
        return False


def _load_cache(path: Path) -> CachedContent | None:
    """Load cached content from disk."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return CachedContent(
            manifest=data["manifest"],
            source=data["source"],
            cached_at=float(data["cached_at"]),
        )
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def _save_cache(server_name: str, content: CachedContent) -> None:
    """Persist content to cache."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(server_name)
    data = {
        "manifest": content.manifest,
        "source": content.source,
        "cached_at": content.cached_at,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _extract_owner_repo(repo_url: str) -> str:
    """Extract owner/repo from GitHub URL."""
    # https://github.com/owner/repo -> owner/repo
    parts = repo_url.rstrip("/").split("/")
    return "/".join(parts[-2:])


def _fetch_raw_file(
    client: httpx.Client,
    repo_url: str,
    file_path: str,
    branch: str = "main",
) -> str:
    """Fetch a raw file from GitHub. Returns empty string on failure."""
    owner_repo = _extract_owner_repo(repo_url)
    url = f"{_GITHUB_RAW_BASE}/{owner_repo}/{branch}/{file_path}"
    try:
        resp = client.get(url, timeout=15.0)
        if resp.status_code == 200:
            return resp.text
    except httpx.HTTPError:
        pass
    return ""


def fetch_server_content(
    config: MCPServerConfig,
    client: httpx.Client | None = None,
    offline: bool = False,
) -> CachedContent | None:
    """Fetch manifest + source for a server, using cache when available.

    Args:
        config: Server configuration.
        client: Optional httpx client (created if None and not offline).
        offline: If True, only use cached data.

    Returns:
        CachedContent if available, None if fetch failed and no cache.
    """
    path = _cache_path(config.name)

    # Try cache first
    if _is_fresh(path):
        return _load_cache(path)

    if offline:
        # Stale cache is better than nothing in offline mode
        return _load_cache(path)

    # Fetch from GitHub
    should_close = client is None
    if client is None:
        client = httpx.Client()

    try:
        manifest = _fetch_raw_file(client, config.repo_url, config.manifest_path)
        source = _fetch_raw_file(client, config.repo_url, config.entry_point)

        # Fetch extra source globs (simplified: treat as exact paths)
        for extra_path in config.extra_source_globs:
            extra = _fetch_raw_file(client, config.repo_url, extra_path)
            if extra:
                source += "\n" + extra

        if not manifest and not source:
            # Total fetch failure — return stale cache if any
            return _load_cache(path)

        content = CachedContent(
            manifest=manifest,
            source=source,
            cached_at=time.time(),
        )
        _save_cache(config.name, content)
        return content

    finally:
        if should_close:
            client.close()
