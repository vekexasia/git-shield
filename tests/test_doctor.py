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


def test_collect_checks_can_report_gitleaks_update(monkeypatch):
    monkeypatch.setattr("git_shield.doctor.shutil.which", lambda name: f"/bin/{name}")
    monkeypatch.setattr("git_shield.doctor.has_cuda", lambda: False)
    monkeypatch.setattr("git_shield.doctor.gitleaks_installed_version", lambda _bin: "8.24.3")
    monkeypatch.setattr("git_shield.doctor.latest_gitleaks_version", lambda: "8.30.1")

    checks = collect_checks("opf", "gitleaks", check_updates=True)
    by_name = {check.name: check for check in checks}

    assert by_name["gitleaks-update"].ok is False
    assert by_name["gitleaks-update"].required is False
    assert "latest 8.30.1" in by_name["gitleaks-update"].detail


def test_collect_checks_reports_current_gitleaks(monkeypatch):
    monkeypatch.setattr("git_shield.doctor.shutil.which", lambda name: f"/bin/{name}")
    monkeypatch.setattr("git_shield.doctor.has_cuda", lambda: False)
    monkeypatch.setattr("git_shield.doctor.gitleaks_installed_version", lambda _bin: "8.30.1")
    monkeypatch.setattr("git_shield.doctor.latest_gitleaks_version", lambda: "8.30.1")

    checks = collect_checks("opf", "gitleaks", check_updates=True)
    by_name = {check.name: check for check in checks}

    assert by_name["gitleaks-update"].ok is True
    assert "latest: 8.30.1" in by_name["gitleaks-update"].detail
