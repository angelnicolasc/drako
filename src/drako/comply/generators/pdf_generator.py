"""PDF generator for EU AI Act articles via Jinja2 + WeasyPrint."""

from __future__ import annotations

import re
from pathlib import Path

from drako.comply import LEGAL_DISCLAIMER, ComplianceContext


def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "system"


def _import_jinja_weasy():
    try:
        import jinja2  # type: ignore
        import weasyprint  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "drako[comply] extras are required for PDF generation. "
            "Install with: pip install drako[comply]"
        ) from exc
    return jinja2, weasyprint


def render_html(article: int, ctx: ComplianceContext) -> str:
    """Render the article HTML through Jinja2 — exposed for tests."""
    from drako.comply.generators import ARTICLE_META

    jinja2, _ = _import_jinja_weasy()
    template_dir = Path(__file__).resolve().parent.parent / "templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(template_dir)),
        autoescape=jinja2.select_autoescape(["html", "xml", "j2"]),
    )
    template = env.get_template(ARTICLE_META[article]["template"])
    return template.render(
        title=ARTICLE_META[article]["title"],
        ctx=ctx,
        legal_disclaimer=LEGAL_DISCLAIMER,
    )


def generate_pdf(article: int, ctx: ComplianceContext, output_dir: Path) -> Path:
    """Generate `article_{N}_{system_name}.pdf` and return its path."""
    _, weasyprint = _import_jinja_weasy()
    output_dir.mkdir(parents=True, exist_ok=True)
    html = render_html(article, ctx)
    fname = f"article_{article}_{_safe_filename(ctx.system_name)}.pdf"
    out_path = output_dir / fname
    weasyprint.HTML(string=html).write_pdf(str(out_path))
    return out_path
