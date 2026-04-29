from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def run(cmd, cwd: Path, **kwargs):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, **kwargs)


def write_stub_bins(tmp_path: Path) -> Path:
    bins = tmp_path / "bin"
    bins.mkdir()
    gitleaks = bins / "gitleaks"
    gitleaks.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "report = sys.argv[sys.argv.index('--report-path') + 1]\n"
        "text = sys.stdin.read()\n"
        "if 'SECRET_LEAK' in text:\n"
        "    open(report, 'w').write(json.dumps([{'RuleID':'test-secret','StartLine':1,'Match':'SECRET_LEAK=REDACTED'}]))\n"
        "    sys.exit(1)\n"
        "open(report, 'w').write('[]')\n"
    )
    opf = bins / "opf"
    opf.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "text = open(sys.argv[sys.argv.index('-f') + 1]).read()\n"
        "spans = []\n"
        "if 'real.person@gmail.com' in text:\n"
        "    start = text.index('real.person@gmail.com')\n"
        "    spans.append({'label':'private_email','text':'real.person@gmail.com','start':start,'end':start+21})\n"
        "print(json.dumps({'detected_spans': spans}))\n"
    )
    for path in [gitleaks, opf]:
        path.chmod(0o755)
    return bins


def init_repo(tmp_path: Path, bins: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q"], repo, check=True)
    run(["git", "config", "user.email", "dev@example.com"], repo, check=True)
    run(["git", "config", "user.name", "Dev"], repo, check=True)
    run(["git", "config", "core.hooksPath", ".git/hooks"], repo, check=True)
    (repo / "README.md").write_text("init\n")
    run(["git", "add", "README.md"], repo, check=True)
    run(["git", "commit", "-qm", "init"], repo, check=True)
    hook = (
        "#!/usr/bin/env bash\n"
        f"PYTHONPATH={Path(__file__).resolve().parents[1] / 'src'} "
        f"{sys.executable} -m git_shield.cli secrets --staged --gitleaks-bin {bins / 'gitleaks'}\n"
    )
    (repo / ".git" / "hooks" / "pre-commit").write_text(hook)
    (repo / ".git" / "hooks" / "pre-commit").chmod(0o755)
    return repo


def test_git_commit_blocks_secret_and_redacts(tmp_path):
    bins = write_stub_bins(tmp_path)
    repo = init_repo(tmp_path, bins)
    (repo / "leak.txt").write_text("SECRET_LEAK=super-secret-value\n")
    run(["git", "add", "leak.txt"], repo, check=True)
    proc = run(["git", "commit", "-m", "leak"], repo)
    assert proc.returncode == 1
    assert "test-secret" in proc.stderr
    assert "SECRET_LEAK=REDACTED" in proc.stderr
    assert "super-secret-value" not in proc.stderr


def test_git_commit_allows_pii_without_secret(tmp_path):
    bins = write_stub_bins(tmp_path)
    repo = init_repo(tmp_path, bins)
    (repo / "customer.txt").write_text("real.person@gmail.com\n")
    run(["git", "add", "customer.txt"], repo, check=True)
    proc = run(["git", "commit", "-m", "pii"], repo)
    assert proc.returncode == 0
