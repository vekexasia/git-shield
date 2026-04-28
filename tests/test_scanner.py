from privacy_prepush.allowlist import load_patterns
from privacy_prepush.opf import PrivacyFinding
from privacy_prepush.scanner import filter_findings


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


def test_filter_deduplicates_redacted_findings():
    findings = [
        PrivacyFinding("private_phone", "+393392506412"),
        PrivacyFinding("private_phone", "+393392506412"),
    ]
    results = filter_findings(findings, load_patterns())
    assert results == [results[0]]
    assert results[0].redacted.endswith("6412]")


def test_filter_blocks_person():
    results = filter_findings([PrivacyFinding("private_person", "Mario Rossi")], load_patterns())
    assert results[0].label == "private_person"
    assert results[0].redacted == "[person:redacted]"
