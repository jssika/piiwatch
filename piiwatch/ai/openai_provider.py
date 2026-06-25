"""OpenAI provider adapter.

Requires the `openai` package and an API key (explicit or via the
OPENAI_API_KEY environment variable, the SDK's default).
"""

from __future__ import annotations

from piiwatch.ai.provider import LLMError, LLMRequest

DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        try:
            import openai
        except ImportError as exc:
            raise LLMError(
                "the 'openai' package is required for the OpenAI provider. "
                "Install with: pip install piiwatch[ai-openai]"
            ) from exc

        try:
            self._client = openai.OpenAI(api_key=api_key) if api_key else openai.OpenAI()
        except Exception as exc:
            raise LLMError(f"failed to initialize OpenAI client: {exc}") from exc

        self._model = model

    def complete(self, request: LLMRequest) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                messages=[
                    {"role": "system", "content": request.system_prompt},
                    {"role": "user", "content": request.user_prompt},
                ],
            )
        except Exception as exc:
            raise LLMError(f"OpenAI API call failed: {exc}") from exc

        try:
            content = response.choices[0].message.content
        except (IndexError, AttributeError) as exc:
            raise LLMError("OpenAI response contained no usable content") from exc

        if not content:
            raise LLMError("OpenAI response contained no text content")
        return content
