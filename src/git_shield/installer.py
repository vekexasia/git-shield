"""Auto-install gitleaks and opf dependencies."""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from .output import error, info, success, warn

# gitleaks release URLs
GITLEAKS_VERSION = "8.24.3"
GITLEAKS_BASE = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"


def _platform_gitleaks_url() -> str | None:
    """Return the gitleaks download URL for the current platform, or None if unsupported."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        arch = "linux_x64" if machine in ("x86_64", "amd64") else "linux_arm64" if machine in ("aarch64", "arm64") else None
    elif system == "darwin":
        arch = "darwin_arm64" if machine == "arm64" else "darwin_x64"
    else:
        return None

    if arch is None:
        return None
    return f"{GITLEAKS_BASE}/gitleaks_{GITLEAKS_VERSION}_{arch}.tar.gz"


def install_gitleaks(target_dir: Path | None = None) -> Path | None:
    """Download and install gitleaks binary.

    Returns the path to the installed binary, or None on failure.
    """
    url = _platform_gitleaks_url()
    if url is None:
        error("Cannot determine gitleaks download URL for this platform.")
        error("Install manually: https://github.com/gitleaks/gitleaks#installing")
        return None

    target_dir = target_dir or Path.home() / ".local" / "bin"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "gitleaks"

    info(f"Downloading gitleaks {GITLEAKS_VERSION} from {url}")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = Path(tmpdir) / "gitleaks.tar.gz"
            urllib.request.urlretrieve(url, archive)
            # Extract
            subprocess.run(
                ["tar", "xzf", str(archive), "-C", str(tmpdir)],
                check=True, capture_output=True,
            )
            extracted = Path(tmpdir) / "gitleaks"
            if not extracted.exists():
                error("gitleaks binary not found in archive.")
                return None
            shutil.move(str(extracted), str(target))
            target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as exc:
        error(f"Failed to install gitleaks: {exc}")
        return None

    success(f"Installed gitleaks to {target}")
    # Check if target_dir is on PATH
    if not _dir_on_path(target_dir):
        warn(f"{target_dir} is not on PATH. Add it: export PATH=\"{target_dir}:$PATH\"")
    return target


def install_opf(source_dir: Path | None = None) -> bool:
    """Install OpenAI Privacy Filter from the official GitHub repo.

    Official upstream install is local editable install from
    https://github.com/openai/privacy-filter, not a verified PyPI package.
    Returns True on success.
    """
    git = shutil.which("git")
    uv = shutil.which("uv")
    pip = shutil.which("pip") or shutil.which("pip3")

    if git is None:
        error("git not found. Cannot clone https://github.com/openai/privacy-filter.")
        return False

    source_dir = source_dir or Path.home() / ".cache" / "git-shield" / "privacy-filter"
    source_dir.parent.mkdir(parents=True, exist_ok=True)

    try:
        if source_dir.exists():
            info(f"Updating OpenAI Privacy Filter in {source_dir}")
            subprocess.run(
                [git, "-C", str(source_dir), "pull", "--ff-only"],
                check=True, capture_output=True, text=True,
            )
        else:
            info(f"Cloning OpenAI Privacy Filter to {source_dir}")
            subprocess.run(
                [git, "clone", "https://github.com/openai/privacy-filter", str(source_dir)],
                check=True, capture_output=True, text=True,
            )
    except subprocess.CalledProcessError as exc:
        error(f"Failed to clone/update OpenAI Privacy Filter: {exc.stderr.strip()[:500]}")
        return False

    if uv:
        info("Installing OpenAI Privacy Filter via uv tool install -e ...")
        try:
            subprocess.run(
                [uv, "tool", "install", "-e", str(source_dir)],
                check=True, capture_output=True, text=True,
            )
            success("Installed opf via uv tool install -e.")
            return True
        except subprocess.CalledProcessError as exc:
            warn(f"uv install failed, trying pip: {exc.stderr.strip()[:300]}")

    if pip:
        info("Installing OpenAI Privacy Filter via pip install -e ...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", str(source_dir)],
                check=True, capture_output=True, text=True,
            )
            success("Installed opf via pip install -e.")
            return True
        except subprocess.CalledProcessError as exc:
            error(f"pip install failed: {exc.stderr.strip()[:500]}")
            return False

    error("Neither uv nor pip found. Install uv: https://docs.astral.sh/uv/")
    return False


def _dir_on_path(directory: Path) -> bool:
    """Check if a directory is on PATH."""
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    resolved = str(directory.resolve())
    return any(Path(d).resolve() == Path(resolved) for d in path_dirs)
