"""Output formatters for `drako nocode`."""

from drako.nocode.formatters.json_fmt import format_json, format_bom_json
from drako.nocode.formatters.markdown_fmt import format_markdown
from drako.nocode.formatters.text_fmt import format_bom_text, format_text

FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "markdown": format_markdown,
}

BOM_FORMATTERS = {
    "text": format_bom_text,
    "json": format_bom_json,
    "markdown": format_bom_text,  # markdown bom is just labelled text
}

__all__ = [
    "FORMATTERS",
    "BOM_FORMATTERS",
    "format_text",
    "format_json",
    "format_markdown",
    "format_bom_text",
    "format_bom_json",
]
