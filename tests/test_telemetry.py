"""Tests for SDK telemetry module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drako.telemetry import (
    is_telemetry_enabled,
    enable_telemetry,
    disable_telemetry,
    send_event,
    _machine_hash,
    _detect_ci,
    maybe_show_telemetry_notice,
)


# ---------------------------------------------------------------------------
# Consent management
# ---------------------------------------------------------------------------

class TestTelemetryConsent:
    def test_disabled_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DRAKO_TELEMETRY", raising=False)
        monkeypatch.chdir(tmp_path)
        assert is_telemetry_enabled() is False

    def test_enable_via_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DRAKO_TELEMETRY", "1")
        monkeypatch.chdir(tmp_path)
        assert is_telemetry_enabled() is True

    def test_disable_via_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DRAKO_TELEMETRY", "0")
        monkeypatch.chdir(tmp_path)
        assert is_telemetry_enabled() is False

    def test_env_var_overrides_consent_file(self, tmp_path, monkeypatch):
        # Consent file says yes, env says no
        monkeypatch.chdir(tmp_path)
        enable_telemetry(str(tmp_path))
        monkeypatch.setenv("DRAKO_TELEMETRY", "0")
        assert is_telemetry_enabled() is False

    def test_enable_creates_consent_file(self, tmp_path):
        path = enable_telemetry(str(tmp_path))
        assert path.exists()
        assert path.read_text(encoding="utf-8").strip() == "yes"

    def test_disable_overwrites_consent_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        enable_telemetry(str(tmp_path))
        disable_telemetry(str(tmp_path))
        consent_path = tmp_path / ".drako" / "telemetry_consent"
        assert consent_path.read_text(encoding="utf-8").strip() == "no"

    def test_consent_file_enables_telemetry(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DRAKO_TELEMETRY", raising=False)
        monkeypatch.chdir(tmp_path)
        enable_telemetry(str(tmp_path))
        assert is_telemetry_enabled() is True


# ---------------------------------------------------------------------------
# Machine hash
# ---------------------------------------------------------------------------

class TestMachineHash:
    def test_returns_hex_string(self):
        h = _machine_hash()
        assert isinstance(h, str)
        assert len(h) == 32

    def test_consistent_across_calls(self):
        h1 = _machine_hash()
        h2 = _machine_hash()
        assert h1 == h2


# ---------------------------------------------------------------------------
# CI detection
# ---------------------------------------------------------------------------

class TestCIDetection:
    def test_detects_github_actions(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        assert _detect_ci() is True

    def test_no_ci_by_default(self, monkeypatch):
        for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
                     "CIRCLECI", "TRAVIS", "BUILDKITE", "CODEBUILD_BUILD_ID"]:
            monkeypatch.delenv(var, raising=False)
        assert _detect_ci() is False


# ---------------------------------------------------------------------------
# send_event
# ---------------------------------------------------------------------------

class TestSendEvent:
    def test_noop_when_disabled(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DRAKO_TELEMETRY", raising=False)
        monkeypatch.chdir(tmp_path)
        # Should not raise
        send_event("scan_completed", {"score": 80})

    @patch("drako.telemetry._send_event_sync")
    def test_sends_event_when_enabled(self, mock_send, tmp_path, monkeypatch):
        monkeypatch.setenv("DRAKO_TELEMETRY", "1")
        monkeypatch.chdir(tmp_path)

        send_event("scan_completed", {"score": 80}, endpoint="http://localhost:8000")

        # Wait for daemon thread
        import time
        time.sleep(0.5)

        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        url = args[0]
        payload = args[1]
        assert url == "http://localhost:8000/api/v1/telemetry/events"
        assert payload["event"] == "scan_completed"
        assert payload["score"] == 80
        assert "anonymous_id" in payload
        assert "drako_version" in payload

    def test_never_raises_on_error(self, monkeypatch):
        monkeypatch.setenv("DRAKO_TELEMETRY", "1")

        # Even with a bad endpoint, should not raise
        send_event("scan_completed", {"score": 80}, endpoint="http://invalid-host-xxx:9999")


# ---------------------------------------------------------------------------
# First-run notice
# ---------------------------------------------------------------------------

class TestTelemetryNotice:
    def test_shows_notice_once(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DRAKO_TELEMETRY", "1")
        monkeypatch.chdir(tmp_path)

        maybe_show_telemetry_notice(str(tmp_path))
        notice_path = tmp_path / ".drako" / ".telemetry_notice_shown"
        assert notice_path.exists()

    def test_does_not_show_when_disabled(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DRAKO_TELEMETRY", raising=False)
        monkeypatch.chdir(tmp_path)

        maybe_show_telemetry_notice(str(tmp_path))
        notice_path = tmp_path / ".drako" / ".telemetry_notice_shown"
        assert not notice_path.exists()
