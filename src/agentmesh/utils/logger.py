"""Structured logging with [AgentMesh] prefix."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "agentmesh") -> logging.Logger:
    """Return a logger with the [AgentMesh] prefix format."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("[AgentMesh] %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = get_logger()
