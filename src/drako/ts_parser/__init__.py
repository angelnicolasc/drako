"""TypeScript/JavaScript AST parser using Tree-sitter.

Optional dependency — install with ``pip install drako[typescript]``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.ts_parser._compat import ts_available

if TYPE_CHECKING:
    from drako.ts_parser.parser import TSParser

__all__ = ["ts_available"]


def get_parser() -> TSParser:
    """Return a module-level singleton :class:`TSParser`.

    Raises :class:`ImportError` if tree-sitter packages are not installed.
    """
    from drako.ts_parser.parser import TSParser

    return TSParser.instance()
