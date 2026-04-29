"""End-to-end CLI tests with a stub `opf` executable.

The stub is a tiny Python script written into a temp dir and made executable.
It echoes a JSON payload that depends on whether the input contains the trigger
strings we expect — letting us exercise the full pipeline (CLI -> chunking ->
detector -> scanner -> exit code) without loading the 2.8GB model.
"""
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
    if "Mario Rossi" in text:
        spans.append({"label": "private_person", "text": "Mario Rossi"})
    if "+393392506412" in text:
        spans.append({"label": "private_phone", "text": "+393392506412"})
    if "ALLOWED_EMAIL" in text:
        spans.append({"label": "private_email", "text": "user1@test.com"})
    if "TRIGGER_BAD_EXIT" in text:
        sys.stderr.write("simulated failure\\n")
        sys.exit(2)
    print(json.dumps({"detected_spans": spans}))
    """
)


@pytest.fixture
def stub_opf(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "opf"
    path.write_text(STUB)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    gitleaks = tmp_path / "gitleaks"
    gitleaks.write_text("#!/usr/bin/env python3\nimport sys\ntext=sys.stdin.read()\n\nif 'SECRET_LEAK' in text:\n    sys.stderr.write('leaks found: 1\\n')\n    sys.exit(1)\nsys.exit(0)\n")
    gitleaks.chmod(gitleaks.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr("git_shield.cli.has_cuda", lambda: True)
    # Run from a clean cwd so the project's own `.pii-allowlist` doesn't bleed in.
    monkeypatch.chdir(tmp_path)
    # Empty $HOME too, so ~/.githooks/pii-allowlist.txt cannot interfere.
    monkeypatch.setenv("HOME", str(tmp_path))
    return path


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


def test_cli_stdin_blocks_on_real_email(stub_opf, tmp_path):
    code, _, err = _run(
        ["scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="contact real.person@gmail.com today",
    )
    assert code == 1
    assert "private_email" in err
    assert "real.person@gmail.com" not in err  # redacted


def test_cli_stdin_clean_passes(stub_opf, tmp_path):
    code, _, err = _run(
        ["scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="nothing private here",
    )
    assert code == 0
    assert "No OPF PII findings" in err


def test_cli_stdin_allowed_email_passes(stub_opf, tmp_path):
    code, _, err = _run(
        ["scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="ALLOWED_EMAIL marker",
    )
    assert code == 0
    assert "No OPF PII findings" in err


def test_cli_stdin_label_override(stub_opf, tmp_path):
    """With --labels=private_phone, an email leak should NOT block."""
    code, _, _ = _run(
        [
            "scan", "--stdin", "--device", "cpu", "--labels", "private_phone",
            "--config", str(tmp_path / "missing.toml"),
        ],
        stdin="real.person@gmail.com only",
    )
    assert code == 0


def test_cli_handles_opf_failure(stub_opf, tmp_path):
    code, _, err = _run(
        ["scan", "--stdin", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="TRIGGER_BAD_EXIT",
    )
    assert code == 1
    assert "OPF failed" in err


def test_cli_skip_if_no_opf(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setattr("git_shield.cli.has_cuda", lambda: True)
    code, _, err = _run(
        [
            "scan", "--stdin", "--device", "cpu", "--skip-if-no-opf", "--skip-if-no-gitleaks",
            "--config", str(tmp_path / "missing.toml"),
        ],
        stdin="real.person@gmail.com",
    )
    assert code == 0
    assert "skipping" in err


def test_cli_max_total_bytes_refuses(stub_opf, tmp_path):
    code, _, err = _run(
        [
            "scan", "--stdin", "--device", "cpu", "--max-total-bytes", "10",
            "--config", str(tmp_path / "missing.toml"),
        ],
        stdin="x" * 200,
    )
    assert code == 1
    assert "refuse to scan" in err


def test_cli_cuda_skip_policy_when_no_cuda(stub_opf, monkeypatch, tmp_path):
    monkeypatch.setattr("git_shield.cli.has_cuda", lambda: False)
    code, _, err = _run(
        [
            "scan", "--stdin", "--device", "cuda", "--cuda-policy", "skip",
            "--config", str(tmp_path / "missing.toml"),
        ],
        stdin="real.person@gmail.com",
    )
    assert code == 0
    assert "skipping" in err


def test_cli_install_subcommand(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    code, _, err = _run(["install", "--repo", str(repo), "--device", "cpu"])
    assert code == 0
    assert (repo / ".git" / "hooks" / "pre-push").exists()
    assert "Installed hooks" in err


def test_cli_install_refuses_overwrite(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    _run(["install", "--repo", str(repo)])
    code, _, err = _run(["install", "--repo", str(repo)])
    assert code == 1
    assert "exists" in err


def test_cli_status_reports_hooks(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    _run(["install", "--repo", str(repo)])
    code, _, err = _run(["status", "--repo", str(repo)])
    assert code == 0
    assert "pre-commit: installed" in err
    assert "pre-push: installed" in err


def test_cli_install_dry_run(tmp_path: Path):
    repo = tmp_path / "repo"
    code, _, err = _run(["install", "--repo", str(repo), "--dry-run"])
    assert code == 0
    assert "Would write" in err


def test_cli_prepush_subcommand_skips_delete(stub_opf, monkeypatch, tmp_path):
    """A delete-only push (local-sha all zeroes) means no diff to scan."""
    monkeypatch.setattr("git_shield.cli.diff_with_fallback", lambda *a, **kw: "")
    code, _, err = _run(
        ["prepush", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="refs/heads/x 0000000000000000000000000000000000000000 refs/heads/x abc\n",
    )
    assert code == 0
    assert "No added text to scan" in err


def test_cli_prepush_no_refs(stub_opf, tmp_path):
    code, _, err = _run(
        ["prepush", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="\n",
    )
    assert code == 0
    assert "No refs on stdin" in err


def test_cli_prepush_blocks_on_pii(stub_opf, monkeypatch, tmp_path):
    monkeypatch.setattr(
        "git_shield.cli.diff_with_fallback",
        lambda *a, **kw: "diff --git a/x b/x\n+++ b/x\n@@\n+real.person@gmail.com\n",
    )
    code, _, err = _run(
        ["prepush", "--device", "cpu", "--config", str(tmp_path / "missing.toml")],
        stdin="refs/heads/main aaa refs/heads/main bbb\n",
    )
    assert code == 1
    assert "private_email" in err


def test_cli_no_subcommand_returns_help(tmp_path):
    code, _, err = _run([])
    assert code == 2
    assert "usage" in err.lower()
