#!/usr/bin/env python3
"""Framework Security Monitor — Detect security-relevant changes in AI frameworks.

Monitors GitHub repositories for commits and issues that match security keywords.
Generates JSON alerts for human review. No automated advisory creation.

Usage:
    python monitor.py                   # Full run
    python monitor.py --dry-run         # Print what would be fetched, don't write
    python monitor.py --framework crewai # Monitor a single framework
    python monitor.py --since 3         # Look back 3 days (default: 7)

Requires GITHUB_TOKEN environment variable for API access.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("framework-monitor")

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.yaml"
ALERTS_DIR = SCRIPT_DIR / "alerts"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A security-relevant finding from a framework repository."""
    framework: str
    type: str  # "commit" or "issue"
    url: str
    title: str
    keywords_matched: list[str]
    relevance_score: float
    detected_at: str
    potential_advisory: bool
    sha: str | None = None
    files_changed: list[str] = field(default_factory=list)
    author: str | None = None
    labels: list[str] = field(default_factory=list)


@dataclass
class MonitorConfig:
    """Parsed monitor configuration."""
    frameworks: dict[str, dict[str, Any]]
    keywords: dict[str, list[str]]
    lookback_days: int
    max_commits: int
    max_issues: int
    alerts_dir: str
    max_alerts: int
    relevance_threshold: float

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> MonitorConfig:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        schedule = raw.get("schedule", {})
        output = raw.get("output", {})

        return cls(
            frameworks=raw.get("frameworks", {}),
            keywords=raw.get("keywords", {}),
            lookback_days=schedule.get("lookback_days", 7),
            max_commits=schedule.get("max_commits_per_repo", 100),
            max_issues=schedule.get("max_issues_per_repo", 50),
            alerts_dir=output.get("alerts_dir", "alerts"),
            max_alerts=output.get("max_alerts_per_run", 50),
            relevance_threshold=output.get("relevance_threshold", 0.3),
        )


# ---------------------------------------------------------------------------
# GitHub API client
# ---------------------------------------------------------------------------

class GitHubClient:
    """Lightweight GitHub REST API client."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str | None = None):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.Client(
            base_url=self.BASE_URL,
            headers=headers,
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def get_commits(
        self,
        repo: str,
        since: datetime,
        per_page: int = 100,
    ) -> list[dict]:
        """Fetch commits from a repository since a given date."""
        commits: list[dict] = []
        page = 1

        while len(commits) < per_page:
            resp = self._client.get(
                f"/repos/{repo}/commits",
                params={
                    "since": since.isoformat(),
                    "per_page": min(100, per_page - len(commits)),
                    "page": page,
                },
            )
            if resp.status_code == 403:
                logger.warning("Rate limited on %s commits (page %d)", repo, page)
                break
            resp.raise_for_status()

            batch = resp.json()
            if not batch:
                break

            commits.extend(batch)
            page += 1

        return commits[:per_page]

    def get_commit_detail(self, repo: str, sha: str) -> dict:
        """Fetch commit details including changed files."""
        resp = self._client.get(f"/repos/{repo}/commits/{sha}")
        if resp.status_code == 403:
            logger.warning("Rate limited fetching commit %s/%s", repo, sha[:8])
            return {}
        resp.raise_for_status()
        return resp.json()

    def get_issues(
        self,
        repo: str,
        since: datetime,
        per_page: int = 50,
    ) -> list[dict]:
        """Fetch issues (not PRs) from a repository since a given date."""
        issues: list[dict] = []
        page = 1

        while len(issues) < per_page:
            resp = self._client.get(
                f"/repos/{repo}/issues",
                params={
                    "since": since.isoformat(),
                    "state": "all",
                    "per_page": min(100, per_page - len(issues)),
                    "page": page,
                },
            )
            if resp.status_code == 403:
                logger.warning("Rate limited on %s issues (page %d)", repo, page)
                break
            resp.raise_for_status()

            batch = resp.json()
            if not batch:
                break

            # Filter out pull requests (they have a pull_request key)
            real_issues = [i for i in batch if "pull_request" not in i]
            issues.extend(real_issues)
            page += 1

        return issues[:per_page]


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def _build_keyword_weights(keywords: dict[str, list[str]]) -> dict[str, float]:
    """Map each keyword to its severity weight."""
    weights = {}
    severity_map = {"critical": 1.0, "high": 0.7, "medium": 0.4}

    for severity, kw_list in keywords.items():
        w = severity_map.get(severity, 0.3)
        for kw in kw_list:
            weights[kw.lower()] = w

    return weights


def score_text(
    text: str,
    keyword_weights: dict[str, float],
    framework_weight: float = 1.0,
) -> tuple[float, list[str]]:
    """Score a text blob for security relevance.

    Returns (score, matched_keywords).
    """
    text_lower = text.lower()
    matched: list[str] = []
    raw_score = 0.0

    for keyword, weight in keyword_weights.items():
        if keyword in text_lower:
            matched.append(keyword)
            raw_score += weight

    # Normalize: cap at 1.0, apply framework weight
    normalized = min(raw_score / 3.0, 1.0) * framework_weight
    return round(normalized, 3), matched


def score_file_paths(
    files: list[str],
    monitored_paths: list[str],
) -> float:
    """Bonus score if changed files are in monitored paths."""
    if not files or not monitored_paths:
        return 0.0

    matches = 0
    for f in files:
        for mp in monitored_paths:
            if f.startswith(mp):
                matches += 1
                break

    ratio = matches / len(files) if files else 0
    return round(ratio * 0.3, 3)  # Max 0.3 bonus


# ---------------------------------------------------------------------------
# Monitor logic
# ---------------------------------------------------------------------------

def monitor_framework(
    gh: GitHubClient,
    name: str,
    fw_config: dict,
    config: MonitorConfig,
    since: datetime,
    dry_run: bool = False,
) -> list[Alert]:
    """Monitor a single framework repository."""
    repo = fw_config["repo"]
    paths = fw_config.get("paths", [])
    weight = fw_config.get("weight", 1.0)
    keyword_weights = _build_keyword_weights(config.keywords)

    alerts: list[Alert] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    logger.info("Monitoring %s (%s) since %s", name, repo, since.date())

    if dry_run:
        logger.info("  [dry-run] Would fetch commits and issues from %s", repo)
        return []

    # --- Commits ---
    try:
        commits = gh.get_commits(repo, since, per_page=config.max_commits)
        logger.info("  Found %d commits", len(commits))

        for commit in commits:
            message = commit.get("commit", {}).get("message", "")
            sha = commit.get("sha", "")
            url = commit.get("html_url", "")
            author = commit.get("commit", {}).get("author", {}).get("name", "unknown")

            # Score commit message
            text_score, matched = score_text(message, keyword_weights, weight)

            if not matched:
                continue

            # Get changed files for path scoring
            changed_files: list[str] = []
            try:
                detail = gh.get_commit_detail(repo, sha)
                changed_files = [f.get("filename", "") for f in detail.get("files", [])]
            except Exception:
                pass

            path_bonus = score_file_paths(changed_files, paths)
            total_score = min(text_score + path_bonus, 1.0)

            if total_score < config.relevance_threshold:
                continue

            # First line of commit message as title
            title = message.split("\n")[0][:200]

            alerts.append(Alert(
                framework=name,
                type="commit",
                url=url,
                title=title,
                keywords_matched=matched,
                relevance_score=total_score,
                detected_at=now_iso,
                potential_advisory=total_score >= 0.7,
                sha=sha[:12],
                files_changed=changed_files[:10],
                author=author,
            ))

    except httpx.HTTPStatusError as e:
        logger.error("  Failed to fetch commits from %s: %s", repo, e)
    except Exception as e:
        logger.error("  Unexpected error fetching commits from %s: %s", repo, e)

    # --- Issues ---
    try:
        issues = gh.get_issues(repo, since, per_page=config.max_issues)
        logger.info("  Found %d issues", len(issues))

        for issue in issues:
            title = issue.get("title", "")
            body = issue.get("body", "") or ""
            url = issue.get("html_url", "")
            labels = [l.get("name", "") for l in issue.get("labels", [])]

            combined_text = f"{title} {body} {' '.join(labels)}"
            text_score, matched = score_text(combined_text, keyword_weights, weight)

            if not matched:
                continue

            # Boost if labeled as security
            label_boost = 0.2 if any(
                "security" in l.lower() or "vulnerability" in l.lower()
                for l in labels
            ) else 0.0

            total_score = min(text_score + label_boost, 1.0)

            if total_score < config.relevance_threshold:
                continue

            alerts.append(Alert(
                framework=name,
                type="issue",
                url=url,
                title=title[:200],
                keywords_matched=matched,
                relevance_score=total_score,
                detected_at=now_iso,
                potential_advisory=total_score >= 0.7,
                labels=labels,
            ))

    except httpx.HTTPStatusError as e:
        logger.error("  Failed to fetch issues from %s: %s", repo, e)
    except Exception as e:
        logger.error("  Unexpected error fetching issues from %s: %s", repo, e)

    return alerts


def save_alerts(alerts: list[Alert], output_dir: Path) -> Path:
    """Save alerts to a timestamped JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"alerts_{timestamp}.json"
    filepath = output_dir / filename

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "high_relevance": sum(1 for a in alerts if a.potential_advisory),
        "alerts": [asdict(a) for a in alerts],
    }

    filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return filepath


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Monitor AI framework repos for security-relevant changes",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be monitored without making API calls",
    )
    parser.add_argument(
        "--framework",
        default=None,
        help="Monitor only this framework (e.g. crewai)",
    )
    parser.add_argument(
        "--since",
        type=int,
        default=None,
        help="Look back N days (overrides config)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=CONFIG_PATH,
        help="Path to config file",
    )
    args = parser.parse_args()

    # Load config
    config = MonitorConfig.load(args.config)
    lookback = args.since or config.lookback_days
    since = datetime.now(timezone.utc) - timedelta(days=lookback)

    # GitHub token
    token = os.environ.get("GITHUB_TOKEN")
    if not token and not args.dry_run:
        logger.warning(
            "GITHUB_TOKEN not set. API rate limits will be very low (60 req/hr). "
            "Set it for 5000 req/hr."
        )

    # Filter frameworks
    frameworks = config.frameworks
    if args.framework:
        if args.framework not in frameworks:
            logger.error("Unknown framework: %s. Available: %s", args.framework, list(frameworks.keys()))
            return 1
        frameworks = {args.framework: frameworks[args.framework]}

    logger.info(
        "Framework Security Monitor starting | %d frameworks | lookback: %d days",
        len(frameworks), lookback,
    )

    all_alerts: list[Alert] = []

    with GitHubClient(token=token) as gh:
        for name, fw_config in frameworks.items():
            alerts = monitor_framework(
                gh, name, fw_config, config, since,
                dry_run=args.dry_run,
            )
            all_alerts.extend(alerts)

    if args.dry_run:
        logger.info("Dry run complete. No alerts written.")
        return 0

    # Sort by relevance score descending
    all_alerts.sort(key=lambda a: a.relevance_score, reverse=True)

    # Cap alerts
    if len(all_alerts) > config.max_alerts:
        logger.info("Capping alerts from %d to %d", len(all_alerts), config.max_alerts)
        all_alerts = all_alerts[:config.max_alerts]

    # Save
    if all_alerts:
        output_dir = SCRIPT_DIR / config.alerts_dir
        filepath = save_alerts(all_alerts, output_dir)
        logger.info(
            "Saved %d alerts (%d high-relevance) to %s",
            len(all_alerts),
            sum(1 for a in all_alerts if a.potential_advisory),
            filepath,
        )
    else:
        logger.info("No security-relevant changes detected.")

    # Summary
    logger.info("--- Summary ---")
    for name in frameworks:
        fw_alerts = [a for a in all_alerts if a.framework == name]
        high = sum(1 for a in fw_alerts if a.potential_advisory)
        logger.info("  %s: %d alerts (%d high-relevance)", name, len(fw_alerts), high)

    return 0


if __name__ == "__main__":
    sys.exit(main())
