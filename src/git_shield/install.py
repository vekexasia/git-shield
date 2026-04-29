from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable

PRE_PUSH_HOOK_TEMPLATE = """#!/usr/bin/env bash
# Installed by git-shield. Edit the wrapper below, not this header.
set -euo pipefail
exec git-shield prepush --device "{device}" "$@"
"""

PRE_COMMIT_HOOK_TEMPLATE = """#!/usr/bin/env bash
# Installed by git-shield. Edit the wrapper below, not this header.
set -euo pipefail
exec git-shield secrets --staged "$@"
"""

HOOK_TEMPLATE = PRE_PUSH_HOOK_TEMPLATE

Runner = Callable[..., object]


def hook_path(repo_root: Path) -> Path:
    return repo_root / ".git" / "hooks" / "pre-push"


def _is_ours(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text(errors="replace")
    return "Installed by git-shield" in text and "git-shield" in text


def _latest_backup(path: Path) -> Path | None:
    backups = sorted(path.parent.glob(f"{path.name}.bak.*"))
    return backups[-1] if backups else None


def _backup_existing(target: Path, content: str) -> Path | None:
    if not target.exists():
        return None
    current = target.read_text(errors="replace")
    if current == content:
        return None
    backup = target.with_name(f"{target.name}.bak.{int(time.time())}")
    target.replace(backup)
    return backup


def write_hook(target: Path, content: str, force: bool = False) -> Path:
    if target.exists() and not force:
        raise FileExistsError(f"{target} exists; pass force=True to overwrite")
    target.parent.mkdir(parents=True, exist_ok=True)
    if force:
        _backup_existing(target, content)
    target.write_text(content)
    target.chmod(0o755)
    return target


def install_hook(repo_root: Path, device: str = "cuda", force: bool = False) -> Path:
    target = hook_path(repo_root)
    if not target.parent.exists():
        raise FileNotFoundError(f"not a git repo (no {target.parent})")
    write_hook(target.parent / "pre-commit", PRE_COMMIT_HOOK_TEMPLATE, force)
    return write_hook(target, PRE_PUSH_HOOK_TEMPLATE.format(device=device), force)


def install_global_hook(
    home: Path | None = None,
    device: str = "cuda",
    force: bool = False,
    runner: Runner = subprocess.run,
) -> Path:
    root = (home or Path.home()) / ".githooks"
    write_hook(root / "pre-commit", PRE_COMMIT_HOOK_TEMPLATE, force)
    target = write_hook(root / "pre-push", PRE_PUSH_HOOK_TEMPLATE.format(device=device), force)
    runner(
        ["git", "config", "--global", "core.hooksPath", str(root)],
        text=True,
        capture_output=True,
        check=True,
    )
    return target


def uninstall_hook(repo_root: Path, restore: bool = True) -> list[Path]:
    target = hook_path(repo_root)
    if not target.parent.exists():
        raise FileNotFoundError(f"not a git repo (no {target.parent})")
    changed: list[Path] = []
    for path in [target.parent / "pre-commit", target.parent / "pre-push"]:
        changed.extend(_remove_hook(path, restore))
    return changed


def uninstall_global_hook(home: Path | None = None, restore: bool = True) -> list[Path]:
    root = (home or Path.home()) / ".githooks"
    changed: list[Path] = []
    for path in [root / "pre-commit", root / "pre-push"]:
        changed.extend(_remove_hook(path, restore))
    return changed


def _remove_hook(path: Path, restore: bool) -> list[Path]:
    if not path.exists():
        return []
    if not _is_ours(path):
        raise FileExistsError(f"{path} was not installed by git-shield; refusing to remove")
    path.unlink()
    changed = [path]
    backup = _latest_backup(path) if restore else None
    if backup is not None:
        backup.replace(path)
        path.chmod(0o755)
        changed.append(path)
    return changed
