"""Abstract parser interface for nocode workflow exports."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from drako.nocode.graph import NocodeWorkflow


class ParserError(ValueError):
    """Raised when a workflow payload cannot be parsed."""


class Parser(ABC):
    """Base class for nocode workflow parsers."""

    platform: str = ""

    @abstractmethod
    def parse(self, payload: dict[str, Any]) -> NocodeWorkflow:
        """Convert a raw platform export into a NocodeWorkflow."""
        ...
