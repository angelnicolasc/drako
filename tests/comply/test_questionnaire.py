"""Questionnaire flow tests — driven non-interactively via a fake prompter."""

from drako.comply.questionnaire import QUESTIONS, question_keys, run


def test_30_questions_in_six_groups() -> None:
    assert len(QUESTIONS) == 30
    groups = {q.group for q in QUESTIONS}
    assert len(groups) == 6


def test_only_missing_fields_are_asked() -> None:
    asked: list[str] = []

    def fake_prompt(text: str, **kwargs: object):  # noqa: ANN001
        asked.append(text)
        return "answer"

    existing = {q.key: "x" for q in QUESTIONS if q.key != "system_name"}
    answers = run(existing, prompter=fake_prompt)
    assert answers["system_name"] == "answer"
    assert len(asked) == 1


def test_multi_question_returns_list() -> None:
    def fake_prompt(text: str, **kwargs: object):  # noqa: ANN001
        return "us, eu, apac"

    answers = run({}, only=["deployment_regions"], prompter=fake_prompt)
    assert answers["deployment_regions"] == ["us", "eu", "apac"]


def test_question_keys_are_unique() -> None:
    keys = question_keys()
    assert len(keys) == len(set(keys))
