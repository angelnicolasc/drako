"""DOCX generator tests — skipped when [comply] extras are not installed."""

from pathlib import Path

import pytest

docx = pytest.importorskip("docx")

from drako.comply.generators import ARTICLES, generate_docx  # noqa: E402

pytestmark = pytest.mark.comply


@pytest.mark.parametrize("article", ARTICLES)
def test_docx_generation_writes_file(article: int, tmp_path: Path, sample_ctx) -> None:
    out = generate_docx(article, sample_ctx, tmp_path)
    assert out.exists()
    assert out.suffix == ".docx"
    # Re-open and confirm content is non-trivial.
    document = docx.Document(str(out))
    text = "\n".join(p.text for p in document.paragraphs)
    assert sample_ctx.system_name in text
