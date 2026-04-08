"""Simple mode — indie-developer-friendly scan output.

Filters scan findings to a curated whitelist of high-signal rules and renders
them as plain English with framework-aware fix suggestions. No SARIF, no
OWASP jargon, no AST talk — just "here's what's broken and how to fix it".
"""

from drako.simple.formatter import format_simple
from drako.simple.router import route_fix
from drako.simple.rules import SIMPLE_RULE_WHITELIST

__all__ = ["SIMPLE_RULE_WHITELIST", "format_simple", "route_fix"]
