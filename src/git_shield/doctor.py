from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .cuda import has_cuda


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True


def _version_tuple(version: str) -> tuple[int, ...]:
    match = re.search(r"(\d+(?:\.\d+)+)", version)
    if match is None:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def gitleaks_installed_version(gitleaks_bin: str = "gitleaks") -> str | None:
    resolved = shutil.which(gitleaks_bin)
    if resolved is None:
        return None
    try:
        proc = subprocess.run(
            [resolved, "version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = f"{proc.stdout}\n{proc.stderr}"
    match = re.search(r"\bv?(\d+(?:\.\d+)+)\b", output)
    return match.group(1) if match else None


def latest_gitleaks_version(timeout: int = 5) -> str | None:
    url = "https://" + "api.github.com" + "/repos/gitleaks/gitleaks/releases/latest"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "git-shield"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, TimeoutError, json.JSONDecodeError):
        return None
    tag = payload.get("tag_name")
    if not isinstance(tag, str):
        return None
    return tag.removeprefix("v")


def collect_checks(opf_bin: str = "opf", gitleaks_bin: str = "gitleaks", check_updates: bool = False) -> list[Check]:
    checks: list[Check] = []

    git = shutil.which("git")
    checks.append(Check("git", git is not None, git or "not found on PATH"))

    gitleaks = shutil.which(gitleaks_bin)
    checks.append(Check("gitleaks", gitleaks is not None, gitleaks or f"not found on PATH: {gitleaks_bin}"))
    if check_updates and gitleaks is not None:
        installed = gitleaks_installed_version(gitleaks_bin)
        latest = latest_gitleaks_version()
        if latest is None:
            checks.append(Check("gitleaks-update", True, "latest version check unavailable", required=False))
        elif installed is None:
            checks.append(
                Check(
                    "gitleaks-update",
                    False,
                    f"installed version unknown, latest {latest}",
                    required=False,
                )
            )
        elif _version_tuple(installed) and _version_tuple(latest) > _version_tuple(installed):
            checks.append(
                Check(
                    "gitleaks-update",
                    False,
                    f"update available: installed {installed}, latest {latest}",
                    required=False,
                )
            )
        else:
            checks.append(Check("gitleaks-update", True, f"current: {installed}, latest: {latest}", required=False))

    opf = shutil.which(opf_bin)
    checks.append(Check("opf", opf is not None, opf or f"not found on PATH: {opf_bin}"))

    checkpoint = Path.home() / ".opf" / "privacy_filter"
    checks.append(
        Check(
            "opf-checkpoint",
            checkpoint.exists(),
            str(checkpoint) if checkpoint.exists() else f"not found: {checkpoint}",
            required=False,
        )
    )

    cuda = has_cuda()
    checks.append(Check("cuda", cuda, "available" if cuda else "not available", required=False))

    try:
        import importlib
        gliner = importlib.import_module("gliner")
        checks.append(Check("gliner", True, "installed", required=False))
    except ImportError:
        checks.append(Check("gliner", False, "not installed (optional, install with: pip install gliner)", required=False))

    return checks


def checks_ok(checks: list[Check]) -> bool:
    return all(check.ok for check in checks if check.required)


def fix_hint(check: Check) -> str | None:
    if check.ok:
        return None
    if check.name == "gitleaks":
        return "Install gitleaks and ensure it is on PATH: https://github.com/gitleaks/gitleaks#installing"
    if check.name == "gitleaks-update":
        return "Update with: git-shield doctor --install --check-updates, or install the latest gitleaks release manually."
    if check.name == "opf":
        return "Install OpenAI Privacy Filter: git clone https://github.com/openai/privacy-filter && uv tool install -e ./privacy-filter"
    if check.name == "git":
        return "Install Git and ensure git is on PATH."
    if check.name == "opf-checkpoint":
        return "Run an OPF smoke test to download the model: opf --device cuda 'Mario Rossi email mario.rossi@gmail.com'"
    if check.name == "cuda":
        return "CUDA not found. Use --device cpu, or set cuda_policy='skip'/'cpu-small'."
    return None
