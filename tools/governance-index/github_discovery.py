# mypy: strict
"""GitHub repository discovery for AI agent projects.

Uses the GitHub Search API to find the top open-source AI agent
projects, deduplicates, and returns them sorted by stars.
Rate-limit aware with automatic back-off.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass

import httpx

_SEARCH_QUERIES: list[str] = [
    '"AI agent" language:Python stars:>100',
    '"LLM agent" language:Python stars:>100',
    "crewai language:Python stars:>50",
    "langgraph language:Python stars:>50",
    "autogen language:Python stars:>50",
    "pydantic-ai language:Python stars:>50",
    '"agent framework" language:Python stars:>100',
]

_GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"


@dataclass(frozen=True)
class RepoInfo:
    """Discovered repository metadata."""

    full_name: str
    clone_url: str
    stars: int
    language: str
    description: str
    topics: tuple[str, ...]


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _API_VERSION,
    }


def _sleep_for_rate_limit(response: httpx.Response) -> None:
    """Sleep if approaching rate limit."""
    remaining = int(response.headers.get("X-RateLimit-Remaining", "10"))
    if remaining <= 2:
        reset_at = int(response.headers.get("X-RateLimit-Reset", "0"))
        sleep_seconds = max(reset_at - int(time.time()), 1) + 1
        print(f"  Rate limit near ({remaining} remaining), sleeping {sleep_seconds}s...", file=sys.stderr)
        time.sleep(sleep_seconds)


def discover_repos(
    token: str,
    min_stars: int = 100,
    limit: int = 100,
) -> list[RepoInfo]:
    """Discover AI agent repositories from GitHub.

    Args:
        token: GitHub personal access token.
        min_stars: Minimum star count filter (applied post-fetch).
        limit: Maximum number of repos to return.

    Returns:
        List of RepoInfo sorted by stars descending, deduplicated.
    """
    seen: set[str] = set()
    repos: list[RepoInfo] = []
    client = httpx.Client(timeout=30.0)

    try:
        for query in _SEARCH_QUERIES:
            if len(repos) >= limit * 2:
                break  # We have enough candidates

            page = 1
            while page <= 3:  # Max 3 pages per query (90 results)
                url = f"{_GITHUB_API}/search/repositories"
                params = {
                    "q": query,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 30,
                    "page": page,
                }

                try:
                    resp = client.get(url, headers=_headers(token), params=params)
                except httpx.HTTPError as e:
                    print(f"  HTTP error for query '{query}': {e}", file=sys.stderr)
                    break

                if resp.status_code == 403 or resp.status_code == 429:
                    _sleep_for_rate_limit(resp)
                    continue  # Retry same page

                if resp.status_code != 200:
                    print(f"  Search API returned {resp.status_code} for '{query}'", file=sys.stderr)
                    break

                _sleep_for_rate_limit(resp)

                data = resp.json()
                items: list[dict[str, object]] = data.get("items", [])
                if not items:
                    break

                for item in items:
                    full_name = str(item.get("full_name", ""))
                    if full_name in seen:
                        continue
                    seen.add(full_name)

                    stars = int(item.get("stargazers_count", 0))  # type: ignore[arg-type]
                    if stars < min_stars:
                        continue

                    repos.append(RepoInfo(
                        full_name=full_name,
                        clone_url=str(item.get("clone_url", "")),
                        stars=stars,
                        language=str(item.get("language", "")),
                        description=str(item.get("description", ""))[:200],
                        topics=tuple(item.get("topics", [])),  # type: ignore[arg-type]
                    ))

                page += 1
                time.sleep(1)  # Respect search rate limit (10 req/min)

    finally:
        client.close()

    # Deduplicate and sort by stars
    repos.sort(key=lambda r: r.stars, reverse=True)
    return repos[:limit]
