from git_shield.doctor import Check, checks_ok, collect_checks


def test_checks_ok_requires_only_required_checks():
    checks = [Check("required", True, "ok"), Check("optional", False, "missing", required=False)]
    assert checks_ok(checks) is True


def test_checks_ok_fails_missing_required():
    checks = [Check("required", False, "missing")]
    assert checks_ok(checks) is False


def test_collect_checks_reports_missing_bins(monkeypatch):
    monkeypatch.setattr("git_shield.doctor.shutil.which", lambda _name: None)
    monkeypatch.setattr("git_shield.doctor.has_cuda", lambda: False)
    checks = collect_checks("opf", "gitleaks")
    by_name = {check.name: check for check in checks}
    assert by_name["git"].ok is False
    assert by_name["gitleaks"].ok is False
    assert by_name["opf"].ok is False
    assert by_name["cuda"].required is False
