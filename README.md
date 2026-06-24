# PIIWatch

**An open-source AI-powered platform for detecting and preventing sensitive data leakage in enterprise systems.**

PIIWatch identifies, classifies, and scores exposure risk for Personally Identifiable Information (PII) and secrets in logs and other text data — Social Security Numbers, credit card numbers, emails, phone numbers, API keys, and authentication tokens — using a hybrid of rule-based validation and (soon) AI-driven contextual classification.

## Status

Early development. The deterministic detection engine (regex + structural/checksum validation + risk scoring) is implemented and tested. AI-assisted contextual classification, the CLI, file/stream ingestion, and reporting formats (JSON/CSV/HTML) are next.

## Why a hybrid approach?

Pure regex-based PII scanners are noisy: a 16-digit number might be a credit card, an order ID, or a tracking number. PIIWatch narrows that down in layers:

1. **Pattern matching** — candidate values are found via regex.
2. **Structural/checksum validation** — e.g. Luhn validation for credit cards, SSA-invalid-range exclusion for SSNs, known key-prefix matching for API keys (AWS, GitHub, Stripe, Slack, Google, JWTs).
3. **Confidence scoring** — every finding carries a confidence score reflecting how certain the match is, not just a binary yes/no.
4. **Risk scoring** — a separate layer turns PII type + confidence + validation outcome into a severity (`info` → `critical`) and a 0–100 risk score, so findings can be triaged by actual impact.
5. *(planned)* **AI-assisted classification** — an LLM reviews ambiguous, low-confidence, or context-dependent matches to reduce false positives/negatives further.

## Quick start

### CLI

```bash
pip install -e .

# Scan a single file
piiwatch scan app.log

# Scan a directory recursively (common log/text extensions by default)
piiwatch scan ./logs --recursive

# Scan everything piped in
cat app.log | piiwatch scan -

# Machine-readable output for scripting/CI
piiwatch scan app.log --json

# Fail the command (exit code 1) if any critical-severity finding is present -- handy in CI
piiwatch scan ./logs --recursive --fail-on critical

# Show surrounding context for each finding
piiwatch scan app.log --verbose
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

Color output respects the [`NO_COLOR`](https://no-color.org) convention and auto-disables when stdout isn't a terminal (e.g. when piping to a file).

### Python API

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

Values are redacted by default in output (e.g. `***************1111`); raw values are available via `Finding.raw_value` for callers that explicitly need them (e.g. a secrets-rotation workflow), but never appear in reports unless explicitly requested.

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
├── engine.py          # PIIWatchEngine: orchestrates detectors, dedupes, scores
├── file_discovery.py  # Recursive file discovery for directory scans
├── cli.py             # `piiwatch scan` command (click-based)
├── ai/                # AI-assisted contextual classification (planned)
└── reporting/
    └── terminal.py     # Dependency-free ANSI formatting for CLI output
    # JSON/CSV/HTML report generation (planned)
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

(If `pytest` isn't available in your environment, `python run_tests.py` is a dependency-free fallback that runs the same test functions.)

## Roadmap

- [x] Core detectors: SSN, credit card (Luhn), email, phone, API keys/secrets
- [x] Risk scoring and severity assessment
- [x] Detection engine with overlap deduplication
- [x] CLI for scanning files, directories, and stdin (with CI-friendly `--fail-on`)
- [ ] AI-assisted contextual classification (LLM-based) for ambiguous matches
- [ ] JSON / CSV / HTML reporting
- [ ] Structured (JSON) log ingestion
- [ ] OpenSearch integration for enterprise-scale analysis
- [ ] Cloud-native deployment for AWS environments
- [ ] Compliance-oriented reporting for audit teams

## License

Apache-2.0
