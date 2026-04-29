# Contributing

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
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
