"""Workflow parsers for the nocode scanner."""

from drako.nocode.parsers.base import Parser, ParserError
from drako.nocode.parsers.flowise import FlowiseParser
from drako.nocode.parsers.n8n import N8nParser

PARSERS: dict[str, type[Parser]] = {
    "n8n": N8nParser,
    "flowise": FlowiseParser,
}


def parse(platform: str, payload: dict) -> "object":  # noqa: ANN401
    """Parse a workflow payload using the parser registered for `platform`."""
    try:
        parser_cls = PARSERS[platform.lower()]
    except KeyError as exc:
        raise ParserError(f"Unknown nocode platform: {platform!r}") from exc
    return parser_cls().parse(payload)


__all__ = ["Parser", "ParserError", "PARSERS", "parse", "N8nParser", "FlowiseParser"]
