"""Status dashboard tests."""

from pathlib import Path

from drako.comply.status import collect, render


def test_no_artifacts_reports_not_generated(tmp_path: Path) -> None:
    rows = collect(tmp_path, "comply-output")
    assert all(r.state == "NOT GENERATED" for r in rows)
    text = render(rows)
    assert "Art. 9" in text and "NOT GENERATED" in text


def test_artifact_makes_status_up_to_date(tmp_path: Path) -> None:
    out = tmp_path / "comply-output"
    out.mkdir()
    (out / "article_9_test.docx").write_bytes(b"x")
    rows = collect(tmp_path, "comply-output")
    art9 = next(r for r in rows if r.article == 9)
    assert art9.state == "up-to-date"
