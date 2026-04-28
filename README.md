# OpenAI Privacy Pre-Push

Experimental Git `pre-push` guard powered by [OpenAI Privacy Filter](https://github.com/openai/privacy-filter).

Goal: catch contextual PII leaks before code leaves the machine. This is meant to complement, not replace:

- `gitleaks` for API keys/secrets
- fast regex PII checks in `pre-commit`

## Current status

Prototype scaffold only. Core logic is testable, but this is **not installed globally yet**.

Why pre-push instead of pre-commit?

- OpenAI Privacy Filter is much heavier than regex/gitleaks.
- Local benchmark on this machine:
  - CPU: 19KB diff took ~2m22s, ~4.6GB RAM — too slow.
  - CUDA: 19KB diff took ~2.2s, ~1.8GB host RAM — viable.
- Therefore this should run as a heavier `pre-push` guard, ideally using CUDA.

## Architecture

```text
Git pre-push hook
  -> privacy-prepush --base <remote/ref> --head HEAD
      -> git diff --unified=0 base..head
      -> extract added lines only
      -> OpenAI Privacy Filter CLI (`opf`)
      -> allowlist public/test values
      -> block push on private_person/private_email/private_phone/etc.
```

## Setup for development

```bash
cd /home/vekex/git/personale/openai-privacy-prepush
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

OpenAI Privacy Filter itself is currently installed separately:

```bash
git clone https://github.com/openai/privacy-filter /tmp/privacy-filter
cd /tmp/privacy-filter
pip install -e .
opf --device cuda 'Mario Rossi email mario.rossi@gmail.com'
```

The model downloads to `~/.opf/privacy_filter` on first use (~2.8GB).

## CLI examples

Scan arbitrary stdin:

```bash
echo 'Mario Rossi email mario.rossi@gmail.com' | privacy-prepush --stdin --device cuda
```

Scan current repo diff:

```bash
privacy-prepush --base origin/main --head HEAD --device cuda
```

Skip if OPF is not installed:

```bash
privacy-prepush --base origin/main --head HEAD --skip-if-no-opf
```

## Allowlist

Allow public/test values with regexes in either:

- `~/.githooks/pii-allowlist.txt`
- `.pii-allowlist` in the repository

Keep allowlist entries narrow and explicit.

## Hook installation idea

Eventually:

```bash
cat > .git/hooks/pre-push <<'SH'
#!/usr/bin/env bash
set -euo pipefail
privacy-prepush --base origin/main --head HEAD --device cuda
SH
chmod +x .git/hooks/pre-push
```

For global use we may integrate this into `pre-commit` framework as a `pre-push` stage.

## TODO

- [ ] Decide packaging strategy: standalone project vs global tool via `uv tool install -e .`.
- [ ] Decide hook runner: raw Git hook vs `pre-commit` framework `stages: [pre-push]`.
- [ ] Parse real pre-push stdin refs instead of assuming `origin/main..HEAD`.
- [ ] Add CUDA availability check and policy:
  - fail closed if no CUDA?
  - skip with warning?
  - fallback to CPU only for tiny diffs?
- [ ] Chunk or limit very large diffs.
- [ ] Add timing output and max runtime guard.
- [ ] Add integration tests with a fake `opf` executable.
- [ ] Add evaluation fixture with real-ish code diffs and expected findings.
- [ ] Add config file support (`privacy-prepush.toml`).
- [ ] Tune labels to block/allow by repo.
- [ ] Confirm no raw PII is printed in logs.
- [ ] Add docs for installing in `risto-menu`.
