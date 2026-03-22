# mypy: strict
"""Checkpoint / resume system for long-running index builds.

Saves progress after each repo scan so the process can be
resumed without re-scanning completed repos. Uses atomic
writes to prevent data loss on interruption.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from scan_runner import RepoScanResult


@dataclass
class CheckpointData:
    """Serializable checkpoint state."""

    completed: dict[str, dict[str, object]]  # repo_name -> scan result dict
    pending: list[str]
    timestamp: float


def save_checkpoint(
    completed: dict[str, RepoScanResult],
    pending: list[str],
    output_dir: Path,
) -> Path:
    """Atomically save checkpoint to disk.

    Args:
        completed: Map of repo_name -> RepoScanResult for finished repos.
        pending: List of repo names still to scan.
        output_dir: Directory to write checkpoint.json.

    Returns:
        Path to the checkpoint file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = output_dir / "checkpoint.json"

    data = {
        "completed": {
            name: {
                "repo_name": r.repo_name,
                "score": r.score,
                "grade": r.grade,
                "framework": r.framework,
                "findings_by_severity": r.findings_by_severity,
                "agents": r.agents,
                "tools": r.tools,
                "scan_duration_ms": r.scan_duration_ms,
            }
            for name, r in completed.items()
        },
        "pending": pending,
        "timestamp": time.time(),
    }

    # Atomic write: write to temp file then rename
    fd, tmp_path = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        # On Windows, need to remove target first
        if checkpoint_path.exists():
            checkpoint_path.unlink()
        os.rename(tmp_path, str(checkpoint_path))
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return checkpoint_path


def load_checkpoint(output_dir: Path) -> tuple[dict[str, RepoScanResult], list[str]] | None:
    """Load checkpoint from disk.

    Returns:
        Tuple of (completed results dict, pending names list), or None if no checkpoint.
    """
    checkpoint_path = output_dir / "checkpoint.json"
    if not checkpoint_path.exists():
        return None

    try:
        data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    completed: dict[str, RepoScanResult] = {}
    for name, result_dict in data.get("completed", {}).items():
        completed[name] = RepoScanResult(
            repo_name=str(result_dict["repo_name"]),
            score=int(result_dict["score"]),
            grade=str(result_dict["grade"]),
            framework=str(result_dict["framework"]),
            findings_by_severity={
                str(k): int(v)
                for k, v in result_dict.get("findings_by_severity", {}).items()
            },
            agents=int(result_dict["agents"]),
            tools=int(result_dict["tools"]),
            scan_duration_ms=int(result_dict["scan_duration_ms"]),
        )

    pending: list[str] = [str(p) for p in data.get("pending", [])]
    return completed, pending
