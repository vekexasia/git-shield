# Security Policy

Report security issues privately by opening a GitHub security advisory or contacting the maintainer directly.

Do not include raw secrets or raw PII in public issues. Use redacted examples.

## Scope

This tool is a local guardrail. It reduces accidental leakage in Git commits and pushes, but it is not a compliance product or a guarantee that all sensitive data will be detected.

## Logging

Hook output is intended to be redacted:

- gitleaks redacts detected secrets.
- git-shield redacts PII before printing findings.

If you find a path that prints raw sensitive values, treat it as a security bug.
