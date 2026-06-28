# Contributing to PIIWatch

Thank you for your interest in contributing! PIIWatch is an open-source PII and secrets detection tool — contributions of all kinds are welcome.

## Ways to contribute

- **New detectors** — add support for a new PII type (passport numbers, IBANs, NINs, etc.)
- **False positive fixes** — improve regex patterns or validation logic to reduce noise
- **New AI providers** — add an adapter for a new LLM provider
- **Report formats** — add a new output format
- **Bug reports** — open an issue describing the input that triggered unexpected behavior
- **Documentation** — improve examples, clarify behavior, fix typos

## Getting started

```bash
git clone https://github.com/jssika/piiwatch.git
cd piiwatch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,ai]"
pytest
```

## Adding a new detector

1. Create `piiwatch/detectors/<type>.py` implementing the `Detector` protocol:
   ```python
   class MyDetector:
       name = "my_detector"
       def detect(self, text: str) -> list[Finding]: ...
   ```
2. Add your new `PIIType` value to `piiwatch/detectors/base.py` if needed.
3. Register it in `piiwatch/detectors/registry.py` — that's the only other file you need to touch.
4. Add a severity mapping in `piiwatch/scoring.py`.
5. Add tests in `tests/test_<type>.py`.

## Running tests

```bash
pytest                    # full suite
pytest tests/test_ssn.py  # single file
```

The test suite never makes real network calls — AI provider tests use `FakeProvider` and `MalformedProvider` stubs in `tests/fakes.py`.

## Code style

- Python 3.10+, no runtime dependencies beyond `click`
- Type annotations on all public functions
- No comments explaining *what* code does — only *why* when the reason is non-obvious

## Submitting a pull request

1. Fork the repo and create a branch: `git checkout -b my-feature`
2. Make your changes and add tests
3. Run `pytest` and confirm everything passes
4. Open a pull request with a clear description of what changed and why

## Reporting issues

Open a GitHub issue. For false positives or false negatives, include:
- The input text (redact any real PII — use realistic-looking fake values)
- The finding PIIWatch produced (or didn't produce)
- The expected behavior
