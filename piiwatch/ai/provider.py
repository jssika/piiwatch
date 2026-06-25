"""Provider-agnostic interface for LLM-backed classification calls.

Concrete adapters (Anthropic, OpenAI) implement `LLMProvider`. The
classifier module only depends on this interface, never on a specific
SDK -- that keeps provider swapping a one-line config change and makes
the classifier trivially testable with a fake provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class LLMError(Exception):
    """Raised by provider adapters on any failure: auth, network,
    rate limit, malformed response, etc. The classifier catches this
    broadly and falls back to the original rule-based finding -- the AI
    layer must never crash or block a scan.
    """


@dataclass
class LLMRequest:
    """A single classification request sent to the provider.

    system_prompt and user_prompt are pre-built by the classifier; the
    provider adapter's only job is "send these strings to the model,
    return its text response."
    """

    system_prompt: str
    user_prompt: str
    max_tokens: int = 300
    # Low temperature: this is a classification task, not creative
    # writing, and we want consistent, repeatable verdicts.
    temperature: float = 0.0


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal interface a provider adapter must implement.

    name: short identifier used in logs/error messages, e.g. "anthropic".
    """

    name: str

    def complete(self, request: LLMRequest) -> str:
        """Send the request, return the model's raw text response.

        Must raise LLMError (not a provider-specific exception) on any
        failure, so the classifier's error handling stays provider-agnostic.
        """
        ...
