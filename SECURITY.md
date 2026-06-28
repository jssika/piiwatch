# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing **jessicamudusu@gmail.com**. Include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You will receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Scope

Security reports are most valuable for:

- **False negatives that expose real PII** — patterns or validations that allow genuinely sensitive data to pass through undetected
- **Information leakage** — cases where PIIWatch itself inadvertently logs, caches, or transmits raw PII values it should be redacting
- **Dependency vulnerabilities** — issues in `click`, `anthropic`, or `openai` packages that affect PIIWatch users

Out of scope: findings that require physical access to a machine or social engineering.

## Note on AI providers

When `--ai-provider` is used, PIIWatch sends a redacted context window to a third-party API (Anthropic or OpenAI). Raw matched values are only sent if `--ai-send-raw` is explicitly passed. Users are responsible for reviewing those providers' data handling policies before enabling AI-assisted review on sensitive inputs.
