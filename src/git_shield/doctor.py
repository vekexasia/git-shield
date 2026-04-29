from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .cuda import has_cuda


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True


def collect_checks(opf_bin: str = "opf", gitleaks_bin: str = "gitleaks") -> list[Check]:
    checks: list[Check] = []

    git = shutil.which("git")
    checks.append(Check("git", git is not None, git or "not found on PATH"))

    gitleaks = shutil.which(gitleaks_bin)
    checks.append(Check("gitleaks", gitleaks is not None, gitleaks or f"not found on PATH: {gitleaks_bin}"))

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
    return checks


def checks_ok(checks: list[Check]) -> bool:
    return all(check.ok for check in checks if check.required)


def fix_hint(check: Check) -> str | None:
    if check.ok:
        return None
    if check.name == "gitleaks":
        return "Install gitleaks and ensure it is on PATH: https://github.com/gitleaks/gitleaks#installing"
    if check.name == "opf":
        return "Install OpenAI Privacy Filter: git clone https://github.com/openai/privacy-filter && uv tool install -e ./privacy-filter"
    if check.name == "git":
        return "Install Git and ensure git is on PATH."
    if check.name == "opf-checkpoint":
        return "Run an OPF smoke test to download the model: opf --device cuda 'Mario Rossi email mario.rossi@gmail.com'"
    if check.name == "cuda":
        return "CUDA not found. Use --device cpu, or set cuda_policy='skip'/'cpu-small'."
    return None
