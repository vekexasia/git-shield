from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class AddedLine:
    path: str
    text: str


def parse_added_lines(diff_text: str) -> list[AddedLine]:
    """Extract added lines from a unified git diff.

    Only lines starting with a single '+' are returned. Diff metadata lines such
    as '+++' are ignored.
    """
    current_path = "<unknown>"
    lines: list[AddedLine] = []

    for raw in diff_text.splitlines():
        if raw.startswith("+++ b/"):
            current_path = raw[6:]
            continue
        if raw.startswith("+++ "):
            current_path = raw[4:]
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lines.append(AddedLine(current_path, raw[1:]))

    return lines


def added_text(diff_text: str) -> str:
    """Return staged/pushed added text with lightweight file markers."""
    chunks: list[str] = []
    for line in parse_added_lines(diff_text):
        chunks.append(f"FILE: {line.path}\n{line.text}")
    return "\n".join(chunks)


def git_diff(base: str, head: str = "HEAD", cwd: str | None = None) -> str:
    """Return git diff for a ref range."""
    return subprocess.check_output(
        ["git", "diff", "--unified=0", "--no-color", "--text", "--no-ext-diff", f"{base}..{head}"],
        text=True,
        errors="replace",
        cwd=cwd,
    )
