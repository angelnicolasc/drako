"""PDF generator smoke tests — skipped when [comply] extras are not installed."""

from pathlib import Path

import pytest

pytest.importorskip("jinja2")
pytest.importorskip("weasyprint")

from drako.comply.generators import ARTICLES, generate_pdf  # noqa: E402
from drako.comply.generators.pdf_generator import render_html  # noqa: E402

pytestmark = pytest.mark.comply


@pytest.mark.parametrize("article", ARTICLES)
def test_render_html_includes_disclaimer(article: int, sample_ctx) -> None:
    html = render_html(article, sample_ctx)
    assert "LEGAL DISCLAIMER" in html
    assert sample_ctx.system_name in html


@pytest.mark.parametrize("article", ARTICLES)
def test_pdf_generation_writes_file(article: int, tmp_path: Path, sample_ctx) -> None:
    out = generate_pdf(article, sample_ctx, tmp_path)
    assert out.exists()
    assert out.suffix == ".pdf"
    assert out.stat().st_size > 1000  # non-empty PDF
