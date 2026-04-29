"""Tests for new features: exit codes, --json, --quiet/--verbose."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from textwrap import dedent

import pytest

from git_shield.cli import main
from git_shield.output import EXIT_CLEAN, EXIT_ERROR, EXIT_PII, EXIT_SECRETS


STUB = dedent(
    """\
    #!/usr/bin/env python3
    import json, sys
    if '-f' in sys.argv:
        text = open(sys.argv[sys.argv.index('-f') + 1]).read()
    else:
        text = sys.stdin.read()
    spans = []
    if "real.person@gmail.com" in text:
        spans.append({"label": "private_email", "text": "real.person@gmail.com"})
    if "SECRET_LEAK" in text:
        spans.append({"label": "secret", "text": "SECRET_LEAK"})
    print(json.dumps({"detected_spans": spans}))
    """
)


@pytest.fixture
def stub_env(tmp_path: Path, monkeypatch) -> Path:
    opf = tmp_path / "opf"
    opf.write_text(STUB)
    opf.chmod(opf.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    gitleaks = tmp_path / "gitleaks"
    gitleaks.write_text(
        "#!/usr/bin/env python3\nimport sys\n"
        "text=sys.stdin.read()\n"
        "if 'SECRET_LEAK' in text:\n"
        "    import json\n"
        "    report = [{'RuleID': 'test-secret', 'StartLine': 1, 'Match': 'REDACTED'}]\n"
        "    import tempfile, os\n"
        "    rp = sys.argv[sys.argv.index('--report-path') + 1]\n"
        "    open(rp, 'w').write(json.dumps(report))\n"
        "    sys.stderr.write('leaks found: 1\\n')\n"
        "    sys.exit(1)\n"
        "sys.exit(0)\n"
    )
    gitleaks.chmod(gitleaks.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr("git_shield.cuda.has_cuda", lambda: True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _run(argv, stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()


# --- Exit code tests ---

def test_exit_code_pii_finding(stub_env, tmp_path):
    code, _, _ = _run(
        ["scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="real.person@gmail.com",
    )
    assert code == EXIT_PII


def test_exit_code_clean(stub_env, tmp_path):
    code, _, _ = _run(
        ["scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="nothing sensitive here",
    )
    assert code == EXIT_CLEAN


def test_exit_code_opf_error(stub_env, tmp_path):
    code, _, _ = _run(
        ["scan", "--stdin", "--device", "cpu", "--max-total-bytes", "5", "--config", str(tmp_path / "missing.toml")],
        stdin="x" * 100,
    )
    assert code == EXIT_ERROR


# --- --json output tests ---

def test_scan_stdin_json_clean(stub_env, tmp_path):
    code, stdout, _ = _run(
        ["scan", "--stdin", "--device", "cpu", "--json", "--config", str(tmp_path / "missing.toml")],
        stdin="nothing sensitive",
    )
    assert code == EXIT_CLEAN
    payload = json.loads(stdout)
    assert payload["ok"] is True
    assert payload["pii_findings"] == []


def test_scan_stdin_json_pii_found(stub_env, tmp_path):
    code, stdout, _ = _run(
        ["scan", "--stdin", "--device", "cpu", "--json", "--config", str(tmp_path / "missing.toml")],
        stdin="real.person@gmail.com",
    )
    assert code == EXIT_PII
    payload = json.loads(stdout)
    assert payload["ok"] is False
    assert len(payload["pii_findings"]) > 0
    assert payload["pii_findings"][0]["label"] == "private_email"


def test_secrets_json_clean(stub_env, tmp_path):
    code, stdout, _ = _run(
        ["secrets", "--stdin", "--json"],
        stdin="no secrets here",
    )
    assert code == EXIT_CLEAN
    payload = json.loads(stdout)
    assert payload["ok"] is True


# --- --quiet / --verbose tests ---

def test_quiet_suppresses_output(stub_env, tmp_path):
    code, _, err = _run(
        ["-q", "scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="nothing sensitive",
    )
    assert code == EXIT_CLEAN
    # quiet mode should suppress the success message
    assert "No OPF PII findings" not in err


def test_verbose_flag_accepted(stub_env, tmp_path):
    code, _, _ = _run(
        ["-v", "scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="nothing sensitive",
    )
    assert code == EXIT_CLEAN


# --- --version test ---

def test_version_flag():
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO("")
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                main(["--version"])
            except SystemExit:
                pass
    finally:
        sys.stdin = old_stdin
    output = out.getvalue() + err.getvalue()
    assert "git-shield 0.1.0" in output
