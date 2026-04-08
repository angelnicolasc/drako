"""DOCX + PDF document generators for `drako comply generate`."""

from drako.comply.generators.docx_generator import generate_docx
from drako.comply.generators.pdf_generator import generate_pdf

ARTICLES = (9, 11, 12, 14)

ARTICLE_META: dict[int, dict[str, str]] = {
    9: {
        "title": "EU AI Act — Article 9: Risk Management System",
        "template": "article_9_risk_management.html.j2",
    },
    11: {
        "title": "EU AI Act — Article 11: Technical Documentation",
        "template": "article_11_technical_docs.html.j2",
    },
    12: {
        "title": "EU AI Act — Article 12: Record Keeping",
        "template": "article_12_record_keeping.html.j2",
    },
    14: {
        "title": "EU AI Act — Article 14: Human Oversight",
        "template": "article_14_human_oversight.html.j2",
    },
}

__all__ = ["ARTICLES", "ARTICLE_META", "generate_docx", "generate_pdf"]
