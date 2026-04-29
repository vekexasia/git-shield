from git_shield.allowlist import load_patterns
from git_shield.opf import PrivacyFinding
from git_shield.scanner import filter_findings


def test_filter_findings_adds_line_number_from_span():
    text = "first\ncontact real.person@gmail.com\nlast\n"
    start = text.index("real.person@gmail.com")
    findings = [PrivacyFinding("private_email", "real.person@gmail.com", start, start + 21)]
    result = filter_findings(findings, load_patterns(), source_text=text)
    assert result[0].line == 2


def test_filter_findings_adds_line_number_by_text_fallback():
    text = "first\nMario Rossi\nlast\n"
    findings = [PrivacyFinding("private_person", "Mario Rossi")]
    result = filter_findings(findings, load_patterns(), source_text=text)
    assert result[0].line == 2
