# Privacy Pre-Push

A local Git safety net for vibe coding: blocks API keys, secrets, and contextual PII before code leaves your machine.

Use it when AI-generated edits, quick experiments, copied logs, or test fixtures might accidentally include private data.

The tool now combines:

- `gitleaks` for API keys/secrets
- OpenAI Privacy Filter for contextual PII in push diffs
- optional fast regex/HF/GLiNER evaluation utilities for comparison

## Current status

Alpha. Model/backend evaluation notes are in [`MODEL_EVAL.md`](MODEL_EVAL.md).

Subcommands (`scan` / `prepush` / `secrets` / `doctor` / `init` / `install` / `uninstall`) are wired,
config + chunking + CUDA policy + binary/lockfile skip are in place, and the
test suite covers the full pipeline with stubbed `opf`/`gitleaks`.

Why pre-push instead of pre-commit?

- OpenAI Privacy Filter is much heavier than regex/gitleaks.
- Local benchmark on this machine:
  - CPU: 19KB diff took ~2m22s, ~4.6GB RAM — too slow.
  - CUDA: 19KB diff took ~2.2s, ~1.8GB host RAM — viable.
- Therefore this should run as a heavier `pre-push` guard, ideally using CUDA.

## Architecture

```text
Git pre-commit hook
  -> git-shield secrets --staged          # staged additions only
      -> gitleaks stdin --redact               # blocks API keys/secrets

Git pre-push hook
  -> git-shield prepush                   # parses <local-ref> <local-sha> <remote-ref> <remote-sha>
      -> resolve base per ref                  # remote_sha | merge-base(origin/main, local) | fallback
      -> git diff --unified=0 base..local      # tolerates missing refs (returns "")
      -> drop ignored paths (*.lock, *.png, Binary files differ, ...)
      -> extract added lines, prepend FILE: markers
      -> gitleaks stdin --redact               # blocks API keys/secrets in push diff
      -> CUDA policy gate                      # fail | skip | cpu-small
      -> chunk by byte size (UTF-8 aware)
      -> OpenAI Privacy Filter CLI (`opf`) per chunk
      -> dedupe by raw text, allowlist public/test values
      -> block push on private_email/private_phone/private_person/secret/...
```

## Quick start

Install the tool globally:

```bash
git clone https://github.com/vekexasia/openai-git-shield
cd openai-git-shield
uv tool install -e .
```

Install dependencies used by the hooks:

```bash
# gitleaks must be on PATH for API-key/secret scanning.
command -v gitleaks

# OpenAI Privacy Filter is a separate dependency; model download is ~2.8GB on first run.
git clone https://github.com/openai/privacy-filter ../privacy-filter
uv tool install -e ../privacy-filter
opf --device cuda 'Mario Rossi email mario.rossi@gmail.com'             # smoke test
```

Check dependencies and install hooks:

```bash
git-shield doctor
git-shield init

# Preview changes:
git-shield install --global --device cuda --dry-run

# Global hooks for all repos:
git-shield install --global --device cuda --force

# Or local hooks for only the current repo:
git-shield install --device cuda --force
```

Or, if you use the [`pre-commit`](https://pre-commit.com) framework, add to
`.pre-commit-config.yaml` instead:

```yaml
repos:
  - repo: https://github.com/vekexasia/openai-git-shield
    rev: v0.1.0
    hooks:
      - id: git-shield-secrets
        stages: [pre-commit]
      - id: git-shield
        stages: [pre-push]
```

## Setup for development

```bash
git clone https://github.com/vekexasia/openai-git-shield
cd openai-git-shield
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

The OPF model downloads to `~/.opf/privacy_filter` on first use (~2.8GB).

## CLI

Seven subcommands:

- `git-shield scan` — diff a ref range or stdin, scan secrets + PII
- `git-shield prepush` — read Git's pre-push stdin (`<local-ref> <local-sha> <remote-ref> <remote-sha>` per line) and scan each updated ref
- `git-shield secrets` — scan staged additions or stdin with gitleaks only
- `git-shield doctor` — verify required external dependencies and print fixes
- `git-shield init` — write starter `git-shield.toml` and `.pii-allowlist`
- `git-shield install` — write hooks locally or globally
- `git-shield uninstall` — remove hooks installed by this tool and restore backups when available

Examples:

```bash
echo 'Mario Rossi mario.rossi@gmail.com' | git-shield scan --stdin --device cuda
git-shield scan --base origin/main --head HEAD --device cuda
git-shield scan --base origin/main --head HEAD --skip-if-no-opf
git-shield doctor
git-shield init
git-shield install --global --device cuda --dry-run
git-shield install --global --device cuda --force
git-shield install --device cuda --force
git-shield uninstall --global
```

Common flags: `--config git-shield.toml`, `--max-bytes`, `--max-total-bytes`,
`--labels private_email,private_phone`, `--cuda-policy {fail,skip,cpu-small}`,
`--gitleaks-bin`, `--skip-secrets`, `--skip-if-no-gitleaks`.

## Allowlist

Allow public/test values with regexes in either:

- `~/.githooks/pii-allowlist.txt`
- `.pii-allowlist` in the repository

Keep allowlist entries narrow and explicit.

## Hook installation

```bash
git-shield install --global --device cuda --force
```

Global install writes:

```text
~/.githooks/pre-commit -> git-shield secrets --staged
~/.githooks/pre-push   -> git-shield prepush --device cuda
```

and sets:

```bash
git config --global core.hooksPath ~/.githooks
```

Local install writes `.git/hooks/pre-commit` and `.git/hooks/pre-push` for the
current repo only. It refuses to overwrite without `--force`. When `--force`
overwrites an existing different hook, the old hook is backed up as
`pre-commit.bak.<timestamp>` or `pre-push.bak.<timestamp>`.

Use `--dry-run` to preview hook paths. Use `git-shield uninstall` or
`git-shield uninstall --global` to remove only hooks installed by this tool;
it refuses to remove foreign hooks and restores the latest backup when available.

The pre-push hook parses Git's pre-push stdin protocol and resolves a sensible
base for new branches via `git merge-base`.

Hook findings include file paths and line numbers when scanning Git diffs:

```text
[git-shield]   leak.txt: line 1: generic-api-key: OPENAI_API_KEY=REDACTED
[git-shield]   customer.txt: line 1: private_email: g***i@gmail.com
```

## Replicability

This repo is designed to drop into any environment without local patching:

- No machine-specific paths in source, README, or tests.
- All defaults live in [`src/git_shield/config.py`](src/git_shield/config.py); per-repo overrides go in `git-shield.toml` (see `examples/`).
- Two adoption paths, pick whichever your team already uses:
  - **Raw Git hook** — `git-shield install` writes hooks directly.
  - **`pre-commit` framework** — declare it in `.pre-commit-config.yaml` (uses `.pre-commit-hooks.yaml` shipped here).
- OPF and gitleaks are external dependencies and are installed separately so this repo stays small/cloneable.
- Tests run fully offline against stubbed `opf`/`gitleaks` and never touch the host's `~/.githooks` or repo `.pii-allowlist` (see `tests/test_cli.py` fixture).

Drop-in artefacts:

- [`examples/git-shield.toml`](examples/git-shield.toml) — fully-commented config schema.
- [`examples/.pii-allowlist`](examples/.pii-allowlist) — minimal public/test allowlist starter.
- [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml) — pre-commit framework hook definition.

## Config file (`git-shield.toml`)

```toml
[git_shield]
device = "cuda"
cuda_policy = "cpu-small"        # fail | skip | cpu-small
cpu_small_threshold = 16384
max_bytes_per_chunk = 65536
max_total_bytes = 2097152
labels = ["private_email", "private_phone", "private_person", "secret"]
ignore_globs = ["*.lock", "*.png", "vendor/*"]
allowlist_paths = [".pii-allowlist"]
```

## Operational notes

- Raw PII and secrets should not be printed. Secrets are redacted by gitleaks;
  PII is redacted by this tool before logging.
- OPF chunks are scanned through temporary files because OPF treats stdin as
  line-delimited inputs. Temp files are created with Python's private tempfile
  defaults and removed when the scan completes.
- Bypass hooks only when necessary:
  - `git commit --no-verify`
  - `git push --no-verify`
- Add narrow public/test allowlist regexes instead of broad suppressions.
