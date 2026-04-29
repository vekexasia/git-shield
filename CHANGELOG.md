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
