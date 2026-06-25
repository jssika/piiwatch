"""Fake LLMProvider for tests -- no network, no real API calls.

Lets tests script exact responses (or simulate failures) so classifier
logic can be tested deterministically.
"""

from __future__ import annotations

import json

from piiwatch.ai.provider import LLMError, LLMRequest


class FakeProvider:
    """A scriptable fake provider.

    Pass either:
      - `responses`: a list of dicts (auto-serialized to the expected
        JSON shape), consumed in order, one per `complete()` call.
      - `raise_error`: if set, every call raises LLMError with this message.
    """

    name = "fake"

    def __init__(self, responses: list[dict] | None = None, raise_error: str | None = None):
        self._responses = list(responses or [])
        self._raise_error = raise_error
        self.calls: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> str:
        self.calls.append(request)
        if self._raise_error:
            raise LLMError(self._raise_error)
        if not self._responses:
            raise LLMError("FakeProvider: no scripted responses left")
        return json.dumps(self._responses.pop(0))


class MalformedProvider:
    """Always returns garbage, to test the classifier's parsing fallback."""

    name = "malformed"

    def complete(self, request: LLMRequest) -> str:
        return "this is not json at all"
