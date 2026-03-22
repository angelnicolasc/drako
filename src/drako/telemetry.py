"""Opt-in anonymous telemetry for Drako.

Collects anonymous usage statistics to improve the product.
Never blocks, never crashes, never sends PII.

Telemetry is opt-in via:
  - Environment variable: DRAKO_TELEMETRY=1
  - Config: drako config set telemetry.enabled true
  - File: .drako/telemetry_consent containing "yes"

Disable with:
  - DRAKO_TELEMETRY=0
  - drako config set telemetry.enabled false
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import threading
import uuid
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CONSENT_FILE = ".drako/telemetry_consent"
_DEFAULT_ENDPOINT = "https://api.getdrako.com"
_NOTICE_FILE = ".drako/.telemetry_notice_shown"

_NOTICE_TEXT = (
    "Drako collects anonymous usage stats to improve the product.\n"
    "Disable with: drako config set telemetry.enabled false\n"
    "Details: https://getdrako.com/telemetry"
)


# ---------------------------------------------------------------------------
# Consent management
# ---------------------------------------------------------------------------

def is_telemetry_enabled() -> bool:
    """Check if telemetry is enabled.

    Priority: env var > consent file > default (False).
    """
    try:
        env = os.environ.get("DRAKO_TELEMETRY", "").strip().lower()
        if env in ("1", "true", "yes", "on"):
            return True
        if env in ("0", "false", "no", "off"):
            return False

        # Check consent file
        consent_path = Path.cwd() / _CONSENT_FILE
        if consent_path.is_file():
            content = consent_path.read_text(encoding="utf-8").strip().lower()
            return content in ("yes", "true", "1")

        return False
    except Exception:
        return False


def enable_telemetry(directory: str = ".") -> Path:
    """Enable telemetry by creating the consent file."""
    consent_path = Path(directory) / _CONSENT_FILE
    consent_path.parent.mkdir(parents=True, exist_ok=True)
    consent_path.write_text("yes\n", encoding="utf-8")
    return consent_path


def disable_telemetry(directory: str = ".") -> None:
    """Disable telemetry by removing or overwriting the consent file."""
    consent_path = Path(directory) / _CONSENT_FILE
    if consent_path.exists():
        consent_path.write_text("no\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Anonymous identity
# ---------------------------------------------------------------------------

def _machine_hash() -> str:
    """Generate a one-way hash of the machine identity.

    Cannot be reversed to identify the user. Consistent across runs
    on the same machine.
    """
    try:
        raw = f"{platform.node()}:{uuid.getnode()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    except Exception:
        return "unknown"


def _detect_ci() -> bool:
    """Detect if running in a CI environment."""
    ci_vars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
               "CIRCLECI", "TRAVIS", "BUILDKITE", "CODEBUILD_BUILD_ID"]
    return any(os.environ.get(v) for v in ci_vars)


# ---------------------------------------------------------------------------
# Event sending
# ---------------------------------------------------------------------------

def send_event(
    event_type: str,
    properties: dict[str, Any] | None = None,
    endpoint: str | None = None,
) -> None:
    """Send a telemetry event asynchronously.

    Fire-and-forget: runs in a daemon thread. Never blocks the caller.
    Never raises exceptions.
    """
    try:
        if not is_telemetry_enabled():
            return

        payload = {
            "event": event_type,
            "anonymous_id": _machine_hash(),
            "drako_version": _get_version(),
            "os": sys.platform,
            "python_version": platform.python_version(),
            "ci_detected": _detect_ci(),
            **(properties or {}),
        }

        ep = endpoint or os.environ.get("DRAKO_ENDPOINT", _DEFAULT_ENDPOINT)
        url = f"{ep}/api/v1/telemetry/events"

        thread = threading.Thread(
            target=_send_event_sync,
            args=(url, payload),
            daemon=True,
        )
        thread.start()
    except Exception:
        pass  # Never crash the caller


def _send_event_sync(url: str, payload: dict[str, Any]) -> None:
    """Synchronous event sender (runs in background thread)."""
    try:
        import httpx
        with httpx.Client(timeout=5.0) as client:
            client.post(url, json=payload)
    except Exception:
        pass  # Silently ignore all errors


def _get_version() -> str:
    """Get the current drako SDK version."""
    try:
        from importlib.metadata import version
        return version("drako")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# First-run notice
# ---------------------------------------------------------------------------

def maybe_show_telemetry_notice(directory: str = ".") -> None:
    """Show a one-time telemetry notice if telemetry is enabled."""
    try:
        if not is_telemetry_enabled():
            return

        notice_path = Path(directory) / _NOTICE_FILE
        if notice_path.exists():
            return

        import click
        click.echo(click.style("\n  [telemetry] ", fg="blue") + _NOTICE_TEXT, err=True)

        notice_path.parent.mkdir(parents=True, exist_ok=True)
        notice_path.write_text("shown\n", encoding="utf-8")
    except Exception:
        pass
