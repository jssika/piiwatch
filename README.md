# PIIWatch — Open-Source PII Detection and Secret Scanner for Python

**Scan log files, config files, CSVs, and text streams for exposed Personally Identifiable Information (PII) and leaked secrets. Detects SSNs, credit card numbers, API keys, emails, and phone numbers using a hybrid of rule-based validation and AI-assisted contextual classification.**

PIIWatch is an open-source Python tool that helps security engineers, data engineers, and compliance teams find and triage sensitive data leakage in enterprise systems. It works on log files, environment configs, application output, and any text stream — from the CLI or as an embeddable Python library.

## What PIIWatch detects

| PII / Secret Type | Detection method |
|---|---|
| Social Security Numbers (SSN) | Regex + SSA invalid-range exclusion |
| Credit card numbers | Regex + Luhn checksum + brand prefix (Visa, Mastercard, Amex, Discover, JCB) |
| Email addresses | RFC-5322-style pattern with low-signal domain filtering |
| US phone numbers | Formatted variants: `(312) 555-0148`, `312-555-0148`, `+1 312 555 0148` |
| API keys and secrets | Known-provider prefixes: AWS, GitHub, Stripe, Slack, Google, JWTs; entropy-based generic detection |
| Authentication tokens | JWTs, bearer tokens, generic high-entropy secret assignments |

Every finding is assigned a **confidence score** (how certain the match is) and a **risk score** (0–100) with a severity level (`info` → `critical`), so teams can triage by actual impact rather than sifting through raw regex hits.

## Who is it for?

- **Security engineers** auditing log pipelines for accidental PII exposure
- **Data engineers** validating that ETL outputs and data exports don't leak sensitive fields
- **Compliance teams** building evidence for GDPR, HIPAA, or PCI DSS audits
- **DevSecOps** adding a PII gate to CI/CD pipelines (`--fail-on critical`)
- **Developers** verifying that test fixtures or debug logs don't contain real user data

## Quick start

```bash
pip install -e .

# Scan a single log file
piiwatch scan app.log

# Scan a directory recursively (common log/text extensions by default)
piiwatch scan ./logs --recursive

# Scan stdin — works with pipes
cat app.log | piiwatch scan -

# Machine-readable JSON output for scripting or CI
piiwatch scan app.log --json

# Fail with exit code 1 if any critical finding is present — useful in CI gates
piiwatch scan ./logs --recursive --fail-on critical

# Show surrounding context for each finding
piiwatch scan app.log --verbose

# Only surface high-confidence findings
piiwatch scan app.log --min-confidence 0.8

# AI-assisted review of ambiguous findings (requires pip install piiwatch[ai] and ANTHROPIC_API_KEY)
piiwatch scan app.log --ai-provider anthropic

# Same using OpenAI (requires pip install piiwatch[ai-openai] and OPENAI_API_KEY)
piiwatch scan app.log --ai-provider openai
```

Example output:

```
PIIWatch scan summary
  6 finding(s)  |  overall risk score: 92.1
  by severity: CRITICAL=2, HIGH=1, MEDIUM=1, LOW=2

SEVERITY  TYPE            VALUE                                       RISK  LOCATION
---------------------------------------------------------------------------------------
CRITICAL  credit_card     ***************1111                         92.1  app.log
CRITICAL  ssn             *******6789                                 85.5  app.log
HIGH      api_key         ****************MPLE                        72.8  app.log
MEDIUM    generic_secret  **************************************N3b"  41.2  app.log
LOW       email           *****************.com                       28.5  app.log
LOW       phone           *********0148                               27.0  app.log
```

Matched values are redacted in all output by default. Color output respects the [`NO_COLOR`](https://no-color.org) convention and auto-disables when stdout isn't a terminal.

## Python API

Use PIIWatch as a library to integrate PII detection directly into data pipelines, ingestion jobs, or audit tooling:

```python
from piiwatch import PIIWatchEngine

engine = PIIWatchEngine()
result = engine.scan("""
User payment: card 4111 1111 1111 1111, SSN 123-45-6789
AWS key leaked: AKIAIOSFODNN7EXAMPLE
""")

print(result["summary"])
for finding in result["findings"]:
    print(finding["pii_type"], finding["severity"], finding["value"])
```

Values are redacted by default in output (e.g. `***************1111`). Raw values are available via `Finding.raw_value` for callers that explicitly need them (e.g. a secrets-rotation workflow).

## AI-assisted classification

Pure regex-based PII scanners are noisy: a 16-digit number might be a credit card, an order ID, or a tracking number. PIIWatch assigns middling confidence to genuinely ambiguous matches rather than guessing, and can optionally send *only those ambiguous findings* to an LLM for contextual review — never the whole document, never high-confidence matches.

```bash
piiwatch scan app.log --ai-provider anthropic             # use Claude
piiwatch scan app.log --ai-provider openai                # use OpenAI
piiwatch scan app.log --ai-provider anthropic --ai-all    # review every finding, not just ambiguous ones
piiwatch scan app.log --ai-provider anthropic --ai-send-raw  # send unredacted values for higher accuracy
```

**Privacy default:** matched values are redacted before being sent to the provider — the model sees `***-**-6789` plus surrounding context, not the real number. Pass `--ai-send-raw` only if you've made an informed decision about the provider's data handling (e.g. a zero-data-retention agreement, or a self-hosted model).

**Reliability guarantee:** any AI failure (missing key, network error, rate limit, malformed output) falls back silently to the original rule-based finding. A broken or absent AI provider never crashes or blocks a scan.

```python
from piiwatch import PIIWatchEngine
from piiwatch.ai import AIClassifier, build_provider

provider = build_provider("anthropic")  # reads ANTHROPIC_API_KEY from env
classifier = AIClassifier(provider=provider)
engine = PIIWatchEngine(classifier=classifier)

result = engine.scan("tracking id 3125550148 attached to this order")
# AI likely rejects this as a false positive given the "tracking id" context,
# whereas the same digits next to "customer callback number:" would be confirmed.
```

## How it works

PIIWatch narrows detection down in layers to reduce false positives:

1. **Pattern matching** — candidate values are found via regex.
2. **Structural / checksum validation** — Luhn validation for credit cards, SSA invalid-range exclusion for SSNs, known key-prefix matching for API keys (AWS, GitHub, Stripe, Slack, Google, JWTs).
3. **Confidence scoring** — every finding carries a score in [0.0, 1.0] reflecting certainty, not just a binary match.
4. **Risk scoring** — PII type + confidence + validation outcome maps to a severity (`info` → `critical`) and a 0–100 risk score for triage.
5. **AI-assisted classification** *(optional)* — an LLM reviews ambiguous matches to confirm, reject, or reclassify findings.

## Test data

The `test_data/` directory contains realistic sample files covering every PII type the scanner detects. All values are fictitious.

| File | What it tests |
|---|---|
| `app.log` | SSNs, emails, and phone numbers embedded in application log lines |
| `config.env` | AWS access/secret keys, GitHub token, Stripe, Slack, Google API keys, JWT, generic secrets |
| `users.csv` | Structured CSV with emails, phone numbers, and SSNs across multiple rows |
| `payments.log` | Luhn-valid credit card numbers (Visa, Mastercard, Amex, Discover) in payment log lines |
| `clean.txt` | No real PII — use as a negative test to confirm zero high-confidence findings |

```bash
# Scan a single test file
piiwatch scan test_data/app.log

# Scan all test files at once
piiwatch scan test_data/ --recursive

# Only surface high-confidence findings
piiwatch scan test_data/users.csv --min-confidence 0.8

# Machine-readable output
piiwatch scan test_data/payments.log --json

# Show surrounding context for each finding
piiwatch scan test_data/config.env --verbose

# Negative test — should return zero high-confidence findings
piiwatch scan test_data/clean.txt
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

If `pytest` isn't available, `python run_tests.py` is a dependency-free fallback that runs the same test functions, including a `FakeProvider`/`MalformedProvider` test double for the AI layer so the test suite never makes real network calls.

## Project layout

```
piiwatch/
├── detectors/        # One module per PII type; each implements detect(text) -> list[Finding]
│   ├── base.py        # Finding dataclass, PIIType/Severity enums, Detector protocol
│   ├── ssn.py
│   ├── credit_card.py # includes Luhn validation
│   ├── email.py
│   ├── phone.py
│   ├── api_key.py     # known provider formats + entropy-based generic secret detection
│   └── registry.py    # DEFAULT_DETECTORS list
├── scoring.py         # Severity + risk score assignment, independent of detection logic
├── engine.py          # PIIWatchEngine: orchestrates detectors, dedupes, scores, optional AI review
├── file_discovery.py  # Recursive file discovery for directory scans
├── cli.py             # `piiwatch scan` command (click-based)
├── ai/
│   ├── provider.py            # LLMProvider protocol, LLMRequest/LLMError
│   ├── anthropic_provider.py  # Anthropic SDK adapter
│   ├── openai_provider.py     # OpenAI SDK adapter
│   ├── factory.py             # build_provider(name) construction helper
│   └── classifier.py          # AIClassifier: reviews ambiguous findings, redacts by default
└── reporting/
    └── terminal.py     # Dependency-free ANSI formatting for CLI output
    # JSON/CSV/HTML report generation (planned)
```

## Roadmap

- [x] Core detectors: SSN, credit card (Luhn), email, phone, API keys/secrets
- [x] Risk scoring and severity assessment
- [x] Detection engine with overlap deduplication
- [x] CLI for scanning files, directories, and stdin (with CI-friendly `--fail-on`)
- [x] AI-assisted contextual classification (Anthropic/OpenAI) for ambiguous matches, with type correction, redaction-by-default, and graceful fallback on any failure
- [ ] JSON / CSV / HTML reporting
- [ ] Structured (JSON) log ingestion
- [ ] OpenSearch integration for enterprise-scale analysis
- [ ] Cloud-native deployment for AWS environments
- [ ] Compliance-oriented reporting for audit teams (GDPR, HIPAA, PCI DSS)

## License

Apache-2.0
