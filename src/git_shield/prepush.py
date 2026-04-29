from __future__ import annotations

import subprocess
from dataclasses import dataclass

ZERO = "0" * 40
ZERO_SHA256 = "0" * 64


@dataclass(frozen=True)
class PushRef:
    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str

    @property
    def is_delete(self) -> bool:
        return _is_zero(self.local_sha)

    @property
    def is_new_branch(self) -> bool:
        return _is_zero(self.remote_sha) and not self.is_delete


def _is_zero(sha: str) -> bool:
    return sha in (ZERO, ZERO_SHA256) or set(sha) == {"0"}


def parse_prepush_stdin(text: str) -> list[PushRef]:
    """Parse the four-token-per-line format Git pipes to pre-push hooks."""
    refs: list[PushRef] = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) != 4:
            continue
        refs.append(PushRef(*parts))
    return refs


def resolve_base(
    ref: PushRef,
    fallback: str = "origin/main",
    runner=subprocess.run,
) -> str | None:
    """Pick a sensible base SHA/ref to diff `ref.local_sha` against.

    - delete: nothing to scan, return None
    - update of an existing remote ref: use remote_sha
    - new branch: try merge-base with `fallback`; fall back to `fallback`
    """
    if ref.is_delete:
        return None
    if not ref.is_new_branch:
        return ref.remote_sha
    proc = runner(
        ["git", "merge-base", fallback, ref.local_sha],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return fallback
