from types import SimpleNamespace

import pytest

from git_shield.opf import (
    OpenAIPrivacyFilterDetector,
    OpfError,
    detect_chunks,
    parse_opf_json,
)


def test_parse_opf_json_with_summary_prefix():
    output = (
        "summary: output_mode=typed spans=1\n"
        '{"detected_spans":[{"label":"private_email","text":"a@b.com","start":0,"end":7}]}\n'
    )
    findings = parse_opf_json(output)
    assert len(findings) == 1
    assert findings[0].label == "private_email"
    assert findings[0].text == "a@b.com"


def test_parse_opf_json_handles_brace_in_summary_string():
    output = 'note: result {ok}\n{"detected_spans":[]}'
    assert parse_opf_json(output) == []


def test_parse_opf_json_handles_brace_inside_string_value():
    output = '{"detected_spans":[{"label":"secret","text":"val {x}"}]}'
    findings = parse_opf_json(output)
    assert findings[0].text == "val {x}"


def test_parse_opf_json_no_json_raises():
    with pytest.raises(ValueError):
        parse_opf_json("no json here")


def test_detector_empty_text_short_circuits():
    called = {"n": 0}

    def runner(*_a, **_kw):
        called["n"] += 1
        return SimpleNamespace(returncode=0, stdout='{"detected_spans":[]}', stderr="")

    det = OpenAIPrivacyFilterDetector(runner=runner)
    assert det.detect("   ") == []
    assert called["n"] == 0


def test_detector_raises_on_nonzero_exit():
    def runner(*_a, **_kw):
        return SimpleNamespace(returncode=2, stdout="", stderr="boom")

    det = OpenAIPrivacyFilterDetector(runner=runner)
    with pytest.raises(OpfError):
        det.detect("Mario Rossi")


def test_detector_parses_valid_output():
    calls = []

    def runner(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout='{"detected_spans":[{"label":"private_person","text":"Mario Rossi"}]}',
            stderr="",
        )

    det = OpenAIPrivacyFilterDetector(runner=runner)
    findings = det.detect("Mario Rossi")
    assert findings[0].label == "private_person"
    assert "input" not in calls[0][1]
    assert "-f" in calls[0][0][0]
    assert "Mario Rossi" not in calls[0][0][0]


def test_detect_chunks_aggregates():
    class FakeDetector:
        def __init__(self):
            self.calls = 0

        def detect(self, text):
            from git_shield.opf import PrivacyFinding
            self.calls += 1
            return [PrivacyFinding("private_email", f"x{self.calls}@gmail.com")]

    fake = FakeDetector()
    result = detect_chunks(fake, ["a", "b", "c"])
    assert fake.calls == 3
    assert len(result) == 3
