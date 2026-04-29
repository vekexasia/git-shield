from types import SimpleNamespace

import pytest

from git_shield.secrets import SecretScanError, scan_secrets_with_gitleaks


def test_scan_secrets_empty_short_circuits():
    called = {"n": 0}

    def runner(*args, **kwargs):
        called["n"] += 1

    result = scan_secrets_with_gitleaks("   ", runner=runner)
    assert result.found is False
    assert called["n"] == 0


def test_scan_secrets_passes_on_zero_exit(tmp_path):
    bin = tmp_path / "gitleaks"
    bin.write_text("x")

    def runner(*args, **kwargs):
        assert kwargs["input"] == "hello"
        assert "stdin" in args[0]
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = scan_secrets_with_gitleaks("hello", str(bin), runner=runner)
    assert result.found is False


def test_scan_secrets_reports_findings(tmp_path):
    bin = tmp_path / "gitleaks"
    bin.write_text("x")

    def runner(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="leaks found: 1")

    result = scan_secrets_with_gitleaks("SECRET", str(bin), runner=runner)
    assert result.found is True
    assert "leaks found" in result.output


def test_scan_secrets_raises_on_unexpected_exit(tmp_path):
    bin = tmp_path / "gitleaks"
    bin.write_text("x")

    def runner(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="boom")

    with pytest.raises(SecretScanError):
        scan_secrets_with_gitleaks("hello", str(bin), runner=runner)
