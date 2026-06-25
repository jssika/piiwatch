"""AI-assisted contextual classification for ambiguous findings.

The rule-based detectors are deliberately conservative about confidence:
anything genuinely ambiguous (an unformatted 10-digit number, a
borderline-entropy string assigned to "generic_secret", an SSN-shaped
number with no other context) gets a middling confidence score rather
than a hard yes/no. This module sends those specific findings -- not the
whole document, not every finding -- to an LLM along with their
surrounding context, and asks it to confirm, reject, or retype them.

Design principles:
  - Only ambiguous findings are sent to the model, by default. Sending
    every finding regardless of confidence is supported but is the
    expensive, slow path; the default keeps cost and latency bounded.
  - The model only ever sees a small context window around each finding,
    not full documents -- this limits what sensitive data leaves the
    local process when an external API provider is used.
  - Any failure (no provider configured, API error, malformed response)
    must fall back to the original rule-based finding unchanged. The AI
    layer can only ever refine results, never break the scan.
  - The model is asked to return strict JSON, parsed defensively.
"""

from __future__ import annotations

import json
import re

from piiwatch.ai.provider import LLMError, LLMProvider, LLMRequest
from piiwatch.detectors.base import Finding, PIIType

SYSTEM_PROMPT = """You are a precise data security classifier. You review a single \
candidate finding from an automated PII/secrets detector and decide whether it is a \
genuine sensitive-data exposure, given the surrounding text for context.

The text you receive marks the exact matched span with >>> <<< markers, e.g. \
"call >>>***-1234<<< now". Judge ONLY the marked span. Other text in the context \
window -- including other numbers, identifiers, or PII-looking values outside the \
markers -- is background context only and must not be evaluated or reported on. \
The marked value may be partially redacted with asterisks (e.g. "***-**-6789") -- \
this is intentional; judge primarily from the surrounding context in that case, \
since you won't be able to see the full value.

Respond with ONLY a JSON object, no other text, in this exact shape:
{"verdict": "confirmed" | "rejected", "confidence": <float 0.0-1.0>, \
"corrected_type": <one of "ssn", "credit_card", "email", "phone", "api_key", \
"auth_token", "generic_secret", "none" -- "none" if you believe this is not \
sensitive data at all, or the same type as given if you agree with it, or a \
different one of the listed types if you believe it was mislabeled>, \
"reasoning": "<one short sentence>"}

Guidelines:
- "confirmed" means you believe the MARKED value is genuinely sensitive data that \
would be a real exposure if found in production logs.
- "rejected" means you believe the MARKED value is a false positive: test/placeholder \
data, a coincidental number pattern, an unrelated identifier, or similar.
- Consider the surrounding context carefully: phrases like "test", "example", \
"placeholder", "dummy", or obviously fake values (e.g. 555-0100 numbers, \
sequential digits) suggest rejection. Realistic-looking values in a context \
implying real user/customer/production data suggest confirmation.
- Keep reasoning to one short, concrete sentence."""

_DEFAULT_AMBIGUITY_BAND = (0.3, 0.8)

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)

_VALID_VERDICTS = {"confirmed", "rejected"}
_TYPE_MAP = {t.value: t for t in PIIType}


class AIClassifier:
    """Reviews ambiguous findings using a configured LLM provider.

    Usage:
        classifier = AIClassifier(provider=AnthropicProvider())
        reviewed = classifier.review(findings, full_text)

    Privacy note on send_raw_values:
        By default (send_raw_values=False), the matched value itself is
        redacted before being sent to the provider -- the LLM sees
        something like ">>>***-**-6789<<<" plus surrounding text, not
        the real number. This is the safer default for any external API
        provider, since it limits what sensitive data leaves the local
        process.

        The trade-off: redaction also limits what the model can judge.
        A redacted SSN gives the model only surrounding context to work
        with (often enough -- "test SSN ... for QA" vs. a real customer
        record -- but not always). The raw value additionally lets it
        notice things like sequential or repeated digits that look
        obviously fake. Set send_raw_values=True only if you've made an
        informed decision about the provider's data handling (e.g.
        zero-data-retention agreement, self-hosted model).
    """

    def __init__(
        self,
        provider: LLMProvider,
        *,
        ambiguity_band: tuple[float, float] = _DEFAULT_AMBIGUITY_BAND,
        context_chars: int = 80,
        send_raw_values: bool = False,
    ):
        self.provider = provider
        self.ambiguity_band = ambiguity_band
        self.context_chars = context_chars
        self.send_raw_values = send_raw_values

    def is_ambiguous(self, finding: Finding) -> bool:
        lo, hi = self.ambiguity_band
        return lo <= finding.confidence <= hi

    def review(self, findings: list[Finding], text: str, *, force_all: bool = False) -> list[Finding]:
        """Review findings, returning a new list where ambiguous findings
        have been replaced with AI-reviewed versions (confidence adjusted,
        ai_* fields populated). Non-ambiguous findings pass through
        unchanged unless force_all=True.
        """
        results = []
        for finding in findings:
            if force_all or self.is_ambiguous(finding):
                results.append(self._review_one(finding, text))
            else:
                results.append(finding)
        return results

    def _review_one(self, finding: Finding, text: str) -> Finding:
        context = self._extract_context(finding, text)
        value_note = finding.redacted_value if not self.send_raw_values else finding.raw_value
        user_prompt = (
            f"Detected type: {finding.pii_type.value}\n"
            f"Rule-based confidence: {finding.confidence:.2f}\n"
            f"Validation status: {finding.validated}\n"
            f"Matched value: {value_note}\n"
            f"Surrounding context, with the matched span marked by >>> <<<\n"
            f"  (judge only the marked span -- other text is context only):\n{context}"
        )

        try:
            raw_response = self.provider.complete(
                LLMRequest(system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt)
            )
            parsed = self._parse_response(raw_response)
        except (LLMError, ValueError):
            # Any failure -- network, auth, malformed JSON, unexpected
            # shape -- falls back to the original finding untouched.
            # The AI layer must degrade gracefully, never break a scan.
            return finding

        return self._apply_verdict(finding, parsed)

    def _extract_context(self, finding: Finding, text: str) -> str:
        """Extract a window of text around the finding, with the matched
        span bracketed by `>>> <<<` markers.

        The window can legitimately include nearby unrelated findings
        (e.g. two phone-shaped matches a few words apart) -- that's
        useful context, not noise. What matters is that the model can
        unambiguously tell which specific span it's being asked to judge,
        rather than conflating it with something else in the window.

        By default the matched span itself is redacted (see
        send_raw_values on the class) -- only surrounding context is
        sent verbatim.
        """
        start = max(0, finding.start - self.context_chars)
        end = min(len(text), finding.end + self.context_chars)
        before = text[start:finding.start]
        matched = text[finding.start:finding.end] if self.send_raw_values else finding.redacted_value
        after = text[finding.end:end]
        return f"{before}>>>{matched}<<<{after}"

    def _parse_response(self, raw_response: str) -> dict:
        match = _JSON_BLOCK_RE.search(raw_response)
        if not match:
            raise ValueError(f"no JSON object found in AI response: {raw_response!r}")

        try:
            parsed = json.loads(match.group())
        except json.JSONDecodeError as exc:
            raise ValueError(f"AI response was not valid JSON: {exc}") from exc

        verdict = parsed.get("verdict")
        if verdict not in _VALID_VERDICTS:
            raise ValueError(f"AI response had invalid verdict: {verdict!r}")

        confidence = parsed.get("confidence")
        if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
            raise ValueError(f"AI response had invalid confidence: {confidence!r}")

        corrected_type_str = parsed.get("corrected_type")
        if corrected_type_str not in (*_TYPE_MAP.keys(), "none"):
            raise ValueError(f"AI response had invalid corrected_type: {corrected_type_str!r}")

        return {
            "verdict": verdict,
            "confidence": float(confidence),
            "corrected_type": corrected_type_str,
            "reasoning": str(parsed.get("reasoning", "")).strip(),
        }

    def _apply_verdict(self, finding: Finding, parsed: dict) -> Finding:
        corrected_type_str = parsed["corrected_type"]
        retyped = corrected_type_str != "none" and corrected_type_str != finding.pii_type.value

        if parsed["verdict"] == "rejected" or corrected_type_str == "none":
            ai_verdict = "rejected"
            new_pii_type = finding.pii_type
            corrected_type = None
            # Rejection drives confidence down sharply but doesn't erase
            # the finding -- a human reviewing the report can still see
            # it was flagged and why the AI dismissed it.
            new_confidence = min(finding.confidence, 1.0 - parsed["confidence"]) * 0.5
        elif retyped:
            ai_verdict = "retyped"
            new_pii_type = _TYPE_MAP[corrected_type_str]
            corrected_type = new_pii_type
            new_confidence = parsed["confidence"]
        else:
            ai_verdict = "confirmed"
            new_pii_type = finding.pii_type
            corrected_type = None
            new_confidence = parsed["confidence"]

        return Finding(
            pii_type=new_pii_type,
            raw_value=finding.raw_value,
            start=finding.start,
            end=finding.end,
            confidence=round(new_confidence, 3),
            validated=finding.validated,
            source=finding.source,
            context=finding.context,
            metadata=finding.metadata,
            ai_reviewed=True,
            ai_verdict=ai_verdict,
            ai_reasoning=parsed["reasoning"] or None,
            corrected_type=corrected_type,
        )
