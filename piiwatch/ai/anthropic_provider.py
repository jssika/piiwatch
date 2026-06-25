"""Anthropic provider adapter.

Requires the `anthropic` package (install via `pip install piiwatch[ai]`)
and an API key, either passed explicitly or read from the ANTHROPIC_API_KEY
environment variable (the SDK's default behavior).

The import of the `anthropic` SDK is deferred to __init__ rather than
done at module level, so that importing piiwatch.ai doesn't hard-require
the dependency for users who aren't using the AI layer at all.
"""

from __future__ import annotations

from piiwatch.ai.provider import LLMError, LLMRequest

DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        try:
            import anthropic
        except ImportError as exc:
            raise LLMError(
                "the 'anthropic' package is required for the Anthropic provider. "
                "Install with: pip install piiwatch[ai]"
            ) from exc

        try:
            self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        except Exception as exc:  # SDK raises its own error types on bad/missing key
            raise LLMError(f"failed to initialize Anthropic client: {exc}") from exc

        self._model = model

    def complete(self, request: LLMRequest) -> str:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system=request.system_prompt,
                messages=[{"role": "user", "content": request.user_prompt}],
            )
        except Exception as exc:
            # Catch broadly: SDK exposes many exception types (auth,
            # rate limit, connection, overloaded, etc.) and the caller
            # only needs to know "the AI call failed", not which subtype.
            raise LLMError(f"Anthropic API call failed: {exc}") from exc

        text_parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        if not text_parts:
            raise LLMError("Anthropic response contained no text content")
        return "".join(text_parts)
