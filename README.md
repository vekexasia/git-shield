# Git Shield

A local Git safety net for vibe coding. Git Shield blocks API keys, secrets, and contextual PII before code leaves your machine.

It is meant for projects where AI-generated edits, copied logs, quick experiments, support snippets, or test fixtures can accidentally introduce sensitive data.

## What it does

- **Pre-commit:** scans staged additions with `gitleaks` and blocks API keys/secrets.
- **Pre-push:** scans outgoing Git diffs with `gitleaks` and OpenAI Privacy Filter, then blocks contextual PII.
- **Redacted output:** reports file paths, line numbers, and finding types without printing raw secrets or raw PII.
- **Local-first:** scanning runs on your machine. No source code is sent to a hosted service by Git Shield.
- **Global or per-repo:** install once for every repo, or only in a specific repo.

Example output:

```text
[git-shield] gitleaks detected possible secrets in leak.txt. Operation blocked.
[git-shield]   leak.txt: line 1: generic-api-key: OPENAI_API_KEY=REDACTED

[git-shield] OpenAI Privacy Filter detected possible PII/secrets. Operation blocked.
[git-shield]   customer.txt: line 12: private_email: [email:redacted]
[git-shield]   customer.txt: line 12: private_person: [person:redacted]
```

## Quick install

Requirements:

- Python 3.11+
- Git
- [`uv`](https://docs.astral.sh/uv/)
- `gitleaks` on `PATH`
- `opf` from [openai/privacy-filter](https://github.com/openai/privacy-filter) on `PATH`
- CUDA recommended for PII scanning

Install Git Shield:

```bash
git clone https://github.com/vekexasia/git-shield
cd git-shield
uv tool install -e .
```

Install OpenAI Privacy Filter:

```bash
git clone https://github.com/openai/privacy-filter ../privacy-filter
uv tool install -e ../privacy-filter
opf --device cuda 'Mario Rossi email mario.rossi@gmail.com'
```

Check the setup:

```bash
git-shield doctor
git-shield doctor --smoke
```

Or run the guided path:

```bash
git-shield bootstrap --smoke --dry-run
git-shield bootstrap --smoke --force
```

Install global hooks for all repos:

```bash
git-shield install --global --device cuda --dry-run
git-shield install --global --device cuda --force
```

Or install hooks only in the current repo:

```bash
git-shield install --device cuda --force
```

## Copy-paste prompt for your coding agent

If you want an LLM coding agent to install this for you, paste this:

```text
Install Git Shield from https://github.com/vekexasia/git-shield.
Use uv. Install the git-shield CLI with `uv tool install -e .` from the clone.
Ensure `gitleaks` is available on PATH.
Install OpenAI Privacy Filter from https://github.com/openai/privacy-filter with `uv tool install -e ../privacy-filter`.
Run `opf --device cuda 'Mario Rossi email mario.rossi@gmail.com'` to download/smoke-test the model.
Run `git-shield doctor`.
If doctor passes, run `git-shield install --global --device cuda --dry-run`, then `git-shield install --global --device cuda --force`.
Do not print any real secrets or PII in the chat.
```

## How it works

```text
Git pre-commit hook
  -> git-shield secrets --staged
      -> gitleaks stdin --redact
      -> blocks API keys/secrets in staged additions

Git pre-push hook
  -> git-shield prepush
      -> resolves pushed refs and base commits
      -> extracts added lines from outgoing diffs
      -> skips ignored/binary/lock files
      -> runs gitleaks first
      -> runs OpenAI Privacy Filter on added text
      -> blocks private_email/private_phone/private_person/secret/etc.
```

Why PII runs at pre-push instead of pre-commit:

- OPF is much heavier than regex/gitleaks.
- Local benchmark on this machine: CPU was too slow, CUDA was viable.
- Pre-push catches leaks before they leave your machine without slowing every commit.

## CLI

```bash
git-shield doctor                         # check dependencies
git-shield doctor --smoke                 # run synthetic secret + PII smoke tests
git-shield doctor --json                  # machine-readable dependency status
git-shield status --global                # show installed hooks and dependencies
git-shield status --global --json         # machine-readable hook status
git-shield bootstrap --smoke --force      # doctor + init + global install
git-shield init                           # write starter config and allowlist
git-shield secrets --staged               # scan staged additions for secrets
git-shield scan --base origin/main        # scan a diff range
git-shield audit --all-files              # scan repo files, not just a diff
git-shield scan --stdin --device cuda     # scan stdin
git-shield install --global --force       # install global hooks
git-shield uninstall --global             # remove global hooks installed by Git Shield
```

Subcommands:

- `scan` - scan a ref range or stdin for secrets + PII.
- `prepush` - Git pre-push hook entrypoint.
- `secrets` - scan staged additions or stdin with gitleaks only.
- `doctor` - verify external dependencies and print fix hints; `--smoke` runs synthetic detection tests.
- `status` - show hooks, dependencies, config, and allowlists.
- `bootstrap` - run doctor, optionally initialize config, and install global hooks.
- `audit` - scan repository files, not just Git diffs.
- `init` - write starter `git-shield.toml` and `.pii-allowlist`.
- `install` - write hooks locally or globally.
- `uninstall` - remove hooks installed by Git Shield and restore backups when available.

## Hook installation details

Global install:

```bash
git-shield install --global --device cuda --force
```

Writes:

```text
~/.githooks/pre-commit -> git-shield secrets --staged
~/.githooks/pre-push   -> git-shield prepush --device cuda
```

and sets:

```bash
git config --global core.hooksPath ~/.githooks
```

Local install:

```bash
git-shield install --device cuda --force
```

Writes:

```text
.git/hooks/pre-commit
.git/hooks/pre-push
```

Safety behavior:

- Without `--force`, existing hooks are never overwritten.
- With `--force`, different existing hooks are backed up as `pre-commit.bak.<timestamp>` or `pre-push.bak.<timestamp>`.
- `git-shield uninstall` refuses to remove hooks it did not install.
- `git-shield uninstall` restores the latest backup when available.

## Configuration

Create starter files:

```bash
git-shield init
```

Example `git-shield.toml`:

```toml
[git_shield]
device = "cuda"
cuda_policy = "cpu-small" # fail | skip | cpu-small
cpu_small_threshold = 16384
opf_bin = "opf"
gitleaks_bin = "gitleaks"
timeout_seconds = 180
max_bytes_per_chunk = 65536
max_total_bytes = 2097152
labels = ["private_email", "private_phone", "private_person", "secret"]
ignore_globs = ["*.lock", "*.png", "vendor/*", "tests/fixtures/*"]
allowlist_paths = [".pii-allowlist"]
```

Allow public/test values with narrow regexes in:

- `~/.githooks/pii-allowlist.txt`
- `.pii-allowlist`
- extra paths configured in `git-shield.toml`

Example `.pii-allowlist`:

```text
(?i)^support@example\.com$
(?i)^user\d+@test\.com$
(?i)^git@github\.com$
```

## pre-commit framework usage

Raw Git hooks are the recommended install path because OPF and gitleaks are external dependencies.

If you still want to use the pre-commit framework:

```yaml
repos:
  - repo: https://github.com/vekexasia/git-shield
    rev: v0.1.0
    hooks:
      - id: git-shield-secrets
        stages: [pre-commit]
      - id: git-shield
        stages: [pre-push]
```

Make sure `gitleaks` and `opf` are available on `PATH` before using these hooks.

## What it catches

Secrets via gitleaks:

- API keys
- tokens
- credentials
- private keys
- many common provider-specific secret formats

PII via OpenAI Privacy Filter:

- `private_email`
- `private_phone`
- `private_person`
- `private_address`
- `private_url`
- `private_date`
- `account_number`
- `secret`

## What it does not guarantee

Git Shield is a guardrail, not a compliance product.

- It can miss sensitive data.
- It can false-positive on fixtures or public contact information.
- It only scans what Git exposes in staged additions or outgoing diffs.
- New branch base resolution depends on available local refs.
- You can bypass hooks with Git's `--no-verify`.

## Bypass and recovery

Bypass only when you know the finding is safe:

```bash
git commit --no-verify
git push --no-verify
```

Prefer allowlisting narrow public/test values instead of broad skips.

Remove hooks installed by Git Shield:

```bash
git-shield uninstall --global
git-shield uninstall
```

## Development

```bash
git clone https://github.com/vekexasia/git-shield
cd git-shield
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
uv build
```

Model/backend evaluation notes are in [`MODEL_EVAL.md`](MODEL_EVAL.md).

## Security notes

- Hook output is printed to stderr and is visible in normal Git command output.
- Secrets are redacted by gitleaks before display.
- PII is redacted by Git Shield before display.
- OPF chunks are scanned through temporary files because OPF treats stdin as line-delimited inputs. Temp files use Python's private tempfile defaults and are removed when scanning completes.
- Do not put real secrets or real PII in issues, tests, fixtures, or chat logs.

If you find a path that prints raw sensitive values, report it as a security bug. See [`SECURITY.md`](SECURITY.md).
