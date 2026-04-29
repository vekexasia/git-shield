# Contributing

## Development

```bash
git clone https://github.com/vekexasia/git-shield
cd git-shield
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## Project structure

```
src/git_shield/
  cli.py              # thin dispatcher (parser + main)
  commands/           # one module per subcommand
    _scan_common.py   # shared scanning orchestration
    scan.py, prepush.py, secrets.py, doctor.py, ...
  output.py           # colors, progress, exit codes, JSON
  config.py           # Config dataclass + TOML loader
  scanner.py          # PII finding filtering + redaction
  opf.py              # OpenAI Privacy Filter adapter
  secrets.py          # gitleaks adapter
  diff.py             # git diff parsing
  ...
```

## Rules

- Do not add real secrets or real PII to tests, fixtures, issues, or docs.
- Use synthetic values only.
- Keep hook output redacted.
- Add regression tests for any bug that could leak raw sensitive data.

## Release checks

```bash
pytest
uv build
git-shield doctor
```
