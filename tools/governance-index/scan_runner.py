# mypy: strict
"""Scan runner — clones repos and runs Drako governance scans.

Each repo is shallow-cloned, scanned with the Drako scanner, and
the result collected. Failures are logged and skipped gracefully.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from github_discovery import RepoInfo


@dataclass(frozen=True)
class RepoScanResult:
    """Scan result for one repository."""

    repo_name: str
    score: int
    grade: str
    framework: str
    findings_by_severity: dict[str, int]
    agents: int
    tools: int
    scan_duration_ms: int


def scan_repo(
    repo: RepoInfo,
    work_dir: Path,
    timeout: int = 60,
) -> RepoScanResult | None:
    """Clone and scan a single repository.

    Args:
        repo: Repository metadata from discovery.
        work_dir: Parent directory for clones.
        timeout: Maximum seconds for clone + scan combined.

    Returns:
        RepoScanResult on success, None on failure.
    """
    repo_dir = work_dir / repo.full_name.replace("/", "__")

    try:
        # Shallow clone
        if not repo_dir.exists():
            clone_start = time.monotonic()
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", repo.clone_url, str(repo_dir)],
                capture_output=True,
                timeout=30,
                text=True,
            )
            if result.returncode != 0:
                print(f"    Clone failed: {result.stderr[:200]}", file=sys.stderr)
                return None
            clone_elapsed = time.monotonic() - clone_start
            remaining_timeout = max(timeout - int(clone_elapsed), 10)
        else:
            remaining_timeout = timeout

        # Run Drako scan (import directly for speed)
        scan_start = time.monotonic()
        try:
            from drako.cli.scanner import run_scan
            scan_result = run_scan(str(repo_dir))
        except Exception as e:
            print(f"    Scan error: {e}", file=sys.stderr)
            return None

        scan_ms = int((time.monotonic() - scan_start) * 1000)

        # Check timeout
        if scan_ms > remaining_timeout * 1000:
            print(f"    Scan timeout ({scan_ms}ms > {remaining_timeout}s)", file=sys.stderr)

        # Extract framework name
        framework = "unknown"
        if scan_result.bom.frameworks:
            framework = scan_result.bom.frameworks[0].name

        # Count findings by severity
        severity_counts: dict[str, int] = {}
        for finding in scan_result.findings:
            sev = finding.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return RepoScanResult(
            repo_name=repo.full_name,
            score=scan_result.score,
            grade=scan_result.grade,
            framework=framework,
            findings_by_severity=severity_counts,
            agents=len(scan_result.bom.agents),
            tools=len(scan_result.bom.tools),
            scan_duration_ms=scan_ms,
        )

    except subprocess.TimeoutExpired:
        print(f"    Clone timeout for {repo.full_name}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"    Unexpected error: {e}", file=sys.stderr)
        return None


def cleanup_repo(repo: RepoInfo, work_dir: Path) -> None:
    """Remove cloned repository directory."""
    repo_dir = work_dir / repo.full_name.replace("/", "__")
    if repo_dir.exists():
        shutil.rmtree(repo_dir, ignore_errors=True)
