# Changelog

## 0.1.0 - Unreleased

- Rename project from `openai-privacy-prepush` / `privacy-prepush` to `git-shield`.
- Add pre-commit secret scanning via gitleaks.
- Add pre-push contextual PII scanning via OpenAI Privacy Filter.
- Add global and local hook installer with backup/restore.
- Add `uninstall` command.
- Add `doctor` command with fix hints and `--smoke` synthetic detection tests.
- Add `status` command for hooks, dependencies, config, and allowlists.
- Add JSON output for `doctor` and `status`.
- Add `bootstrap` command for guided setup.
- Add `audit` command for repository file scans.
- Add `init` command for starter config files.
- Add `--dry-run` to install.
- Add allowlist support for public/test PII values.
- Add per-file and line-number reporting for Git diff scans.
- Add model evaluation notes and local eval harness.
- Add integration tests with real temp Git repos.
- Add no-raw-output safety tests.
- Add CI workflow, LICENSE, SECURITY.md, CONTRIBUTING.md.
- Add `--version` flag.
- Add `--quiet` / `--verbose` flags.
- Add `--json` output for `scan`, `prepush`, `secrets`, and `audit` commands.
- Add distinct exit codes: 0=clean, 1=error, 2=secrets, 3=PII, 4=both.
- Add colored output and progress spinner.
- Add `python -m git_shield` support.
- Refactor CLI into command modules for maintainability.
- Default `cuda_policy` to `cpu-small` so PII scanning works without CUDA.
- Add mypy configuration.
- Add Python 3.13 classifier.
- Add `--backend gliner` option for lighter CPU-friendly PII detection via GLiNER.
- Add `doctor --install` and `bootstrap --install-deps` for auto-installing gitleaks and opf.
- Add scan result caching by content hash (`--no-cache` to bypass).
- Add parallel secret scanning via ThreadPoolExecutor.
- Add automated release workflow (GitHub Actions).
- Note WSL support; native Windows not supported.
