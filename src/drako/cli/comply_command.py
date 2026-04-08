"""Thin shim that exposes the comply Click group for the main CLI.

The comply package itself is intentionally importable without the optional
[comply] extras installed: it lazy-imports python-docx / weasyprint /
jinja2 only when generators run, and prints a clear install hint on
ImportError. This keeps `drako --help` working on a bare install.
"""

from drako.comply.cli import comply

__all__ = ["comply"]
