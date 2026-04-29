from pathlib import Path

import pytest

from git_shield.install import (
    HOOK_TEMPLATE,
    PRE_COMMIT_HOOK_TEMPLATE,
    install_global_hook,
    install_hook,
    uninstall_hook,
)


def _fake_repo(root: Path) -> Path:
    (root / ".git" / "hooks").mkdir(parents=True)
    return root


def test_install_writes_hook(tmp_path: Path):
    repo = _fake_repo(tmp_path)
    path = install_hook(repo, device="cpu")
    assert path.exists()
    assert path.read_text() == HOOK_TEMPLATE.format(device="cpu")
    assert (repo / ".git" / "hooks" / "pre-commit").read_text() == PRE_COMMIT_HOOK_TEMPLATE
    mode = path.stat().st_mode & 0o777
    assert mode & 0o111  # executable


def test_install_refuses_overwrite(tmp_path: Path):
    repo = _fake_repo(tmp_path)
    install_hook(repo)
    with pytest.raises(FileExistsError):
        install_hook(repo)


def test_install_force_overwrites_and_backs_up(tmp_path: Path):
    repo = _fake_repo(tmp_path)
    install_hook(repo, device="cuda")
    (repo / ".git" / "hooks" / "pre-push").write_text("old hook")
    install_hook(repo, device="cpu", force=True)
    assert "--device \"cpu\"" in (repo / ".git" / "hooks" / "pre-push").read_text()
    backups = list((repo / ".git" / "hooks").glob("pre-push.bak.*"))
    assert backups
    assert backups[0].read_text() == "old hook"


def test_install_fails_outside_git_repo(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        install_hook(tmp_path)


def test_uninstall_removes_own_hooks(tmp_path: Path):
    repo = _fake_repo(tmp_path)
    install_hook(repo)
    changed = uninstall_hook(repo)
    assert repo / ".git" / "hooks" / "pre-commit" in changed
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()
    assert not (repo / ".git" / "hooks" / "pre-push").exists()


def test_uninstall_refuses_foreign_hook(tmp_path: Path):
    repo = _fake_repo(tmp_path)
    (repo / ".git" / "hooks" / "pre-commit").write_text("foreign")
    with pytest.raises(FileExistsError):
        uninstall_hook(repo)


def test_install_global_writes_hook_and_sets_config(tmp_path: Path):
    calls = []

    def runner(*args, **kwargs):
        calls.append((args, kwargs))
        return None

    path = install_global_hook(tmp_path, device="cpu", runner=runner)
    assert path == tmp_path / ".githooks" / "pre-push"
    assert path.read_text() == HOOK_TEMPLATE.format(device="cpu")
    assert (tmp_path / ".githooks" / "pre-commit").read_text() == PRE_COMMIT_HOOK_TEMPLATE
    assert calls[0][0][0] == [
        "git",
        "config",
        "--global",
        "core.hooksPath",
        str(tmp_path / ".githooks"),
    ]


def test_install_global_refuses_overwrite(tmp_path: Path):
    install_global_hook(tmp_path, runner=lambda *args, **kwargs: None)
    with pytest.raises(FileExistsError):
        install_global_hook(tmp_path, runner=lambda *args, **kwargs: None)
