from git_shield.scanner import redact_generic


def test_email_redaction_does_not_include_raw_value():
    raw = "real.person@gmail.com"
    redacted = redact_generic(raw, "private_email")
    assert raw not in redacted
    assert redacted == "r***n@gmail.com"


def test_phone_redaction_does_not_include_raw_value():
    raw = "+393331112222"
    redacted = redact_generic(raw, "private_phone")
    assert raw not in redacted
    assert redacted == "[phone:***2222]"


def test_person_redaction_does_not_include_raw_value():
    raw = "Giuseppe Verdi"
    redacted = redact_generic(raw, "private_person")
    assert raw not in redacted
    assert redacted == "[person:redacted]"
