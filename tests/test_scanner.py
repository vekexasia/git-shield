from git_shield.allowlist import load_patterns
from git_shield.opf import PrivacyFinding
from git_shield.scanner import filter_findings, redact_email


def test_filter_blocks_real_email_and_allows_test_email():
    findings = [
        PrivacyFinding("private_email", "real.person@gmail.com"),
        PrivacyFinding("private_email", "user1@test.com"),
    ]
    results = filter_findings(findings, load_patterns())
    assert len(results) == 1
    assert results[0].label == "private_email"
    assert results[0].redacted.startswith("r***n")
    assert results[0].redacted.endswith("gmail.com")


def test_filter_deduplicates_same_text():
    findings = [
        PrivacyFinding("private_phone", "+393392506412"),
        PrivacyFinding("private_phone", "+393392506412"),
    ]
    results = filter_findings(findings, load_patterns())
    assert len(results) == 1
    assert results[0].redacted.endswith("6412]")


def test_filter_keeps_distinct_emails_with_same_redaction():
    """marco@gmail.com and mario@gmail.com both redact to m***o@gmail.com but
    they are distinct values; we want both surfaced."""
    findings = [
        PrivacyFinding("private_email", "marco@gmail.com"),
        PrivacyFinding("private_email", "mario@gmail.com"),
    ]
    results = filter_findings(findings, load_patterns())
    assert len(results) == 2


def test_filter_blocks_person():
    results = filter_findings([PrivacyFinding("private_person", "Mario Rossi")], load_patterns())
    assert results[0].label == "private_person"
    assert results[0].redacted == "[person:redacted]"


def test_filter_respects_label_subset():
    findings = [
        PrivacyFinding("private_email", "real.person@gmail.com"),
        PrivacyFinding("private_phone", "+393392506412"),
    ]
    results = filter_findings(findings, load_patterns(), labels_to_block={"private_email"})
    assert len(results) == 1
    assert results[0].label == "private_email"


def test_filter_empty_label_set_blocks_nothing():
    findings = [PrivacyFinding("private_email", "real.person@gmail.com")]
    assert filter_findings(findings, load_patterns(), labels_to_block=set()) == []


def test_redact_email_short_local():
    assert redact_email("a@b.com") == "a*@b.com"
    assert redact_email("ab@b.com") == "a*@b.com"


def test_redact_email_long_local():
    assert redact_email("hello@b.com") == "h***o@b.com"
